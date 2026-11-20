# Folder Vault: architecture and threat model

Prototype version 0.3.

> **In plain words.** This document is for the IT team's technical staff. It explains
> how Folder Vault is built and which attacks it is designed to stop. In short:
> each protected folder becomes an encrypted file that only a small background
> service can open, and that service only opens it for someone who gives the
> right password. The service never touches people's own folders, so it
> cannot be tricked into damaging them. Section 4 lists the attacks and the
> defences; section 7 says how much of the computer's memory and processor it
> is meant to use. Non-technical readers want [FOR-MANAGERS.md](FOR-MANAGERS.md).

## 1. What it does

Folder Vault lets a standard (non-admin) Windows user turn an ordinary folder into a
password-protected vault, unlock it when needed, and lock it again. The vault
password is separate from the Windows login, so knowing someone's Windows
password is not enough to read their protected folders.

Each protected folder is stored as a **BitLocker-encrypted VHDX virtual disk**
(XTS-AES-256) in a SYSTEM-only folder. The original folder is replaced by a
**link (NTFS junction)** pointing at the vault's mount point, so users keep
working in the same place. When the vault is unlocked, the decrypted volume is
mounted there and the folder shows the files; when it is locked, the virtual
disk is detached and the folder appears empty.

No third-party software, no compiled binaries: PowerShell 5.1 (built into
Windows 10/11) plus Windows' own BitLocker, VHDX and Storage components.

## 2. Requirements

| Requirement | Why |
|---|---|
| Windows 10/11 **Pro, Enterprise or Education** | BitLocker on data volumes is not available on Home |
| BitLocker full-disk encryption on C: (strongly recommended) | Prevents recovery of pre-migration plaintext from the disk |
| Users run as **standard users** | A local admin can bypass any local control |
| A separate IT-held admin account per PC | For install, recovery and audits |

## 3. Components

```
 User session (standard user)                    SYSTEM
 ┌─────────────────────────────────┐           ┌──────────────────────────────────┐
 │ FolderVault.Tray.ps1  (all day)     │           │ FolderVault.Broker.ps1 (sched. task, │
 │  - shield icon, menu            │           │   below-normal priority)         │
 │  - Windows Forms only, no WPF   │  named    │  - authenticates caller (SID)    │
 │ FolderVault.UI.ps1  (on demand)     │  pipe     │  - authorises path & vault scope │
 │  - windows, Explorer menu,      │◄─────────►│  - password policy, rate limits  │
 │    Ctrl+Alt+L; exits when done  │ \\.\pipe\ │  - auto-lock watchdog (sleeps    │
 │ FolderVault.UserOps.psm1            │ FolderVault   │    while all vaults are locked)  │
 │  - copy, verify, safe delete    │ Broker    │  - event log (no secrets)        │
 │  - friendly lock (closes        │           │ FolderVault.Engine.psm1              │
 │    Explorer windows first)      │           │  - VHDX create/attach/detach     │
 │ FolderVault.Client.psm1             │           │  - BitLocker via WMI             │
 │  - verifies pipe owner = SYSTEM │           │  - unlock shortcut in Mounts\{id}│
 └─────────────────────────────────┘           │  - recovery key escrow (CMS)     │
                                               └──────────────────────────────────┘
                                                        │
                       C:\ProgramData\FolderVault  (SYSTEM + Administrators only)
                         Vaults\{id}.vhdx   encrypted containers
                         Escrow\{id}.cms    recovery keys, encrypted to the IT team's cert
                         Mounts\{id}        mount points (volume root ACL = owner,
                                            or Users for shared vaults). While
                                            locked: holds only the read-only
                                            "double-click here to unlock" shortcut
                         vaults.json        vault registry
                         config.json        policy

 C:\Users\alice\Documents\Payroll  ──junction──►  C:\ProgramData\FolderVault\Mounts\{id}
 (created by Alice's own session)
```

Set-up files (`install\`): `FolderVault.Setup.psm1` (elevation, plain-English
output, readiness checks), `Install-FolderVault.ps1`, `Uninstall-FolderVault.ps1`,
`Test-FolderVaultReadiness.ps1`, launched by `Install.cmd`, `Uninstall.cmd` and
`Check-ThisPC.cmd`.

### The key security decision: SYSTEM never touches user folders
A privileged service that copies, deletes or mounts things at paths chosen by a
user is a classic privilege-escalation target: the user swaps a folder for a
junction to `C:\Windows\...` or another user's profile at the right moment, and
the service does the damage with SYSTEM rights. Folder Vault removes that whole
class of attack by splitting the work:

| Done by the SYSTEM broker (own folder only) | Done in the user's session (user's own rights) |
|---|---|
| Create, attach, detach, delete the VHDX | Check the folder (no links inside, not reached through a link) |
| BitLocker protectors, unlock, lock | Copy files into the unlocked vault and SHA-256 verify every file |
| Mount at `Mounts\{id}`, set the vault root ACL | Rename the original aside, create the junction, check it |
| Escrow the recovery key | Delete the original only after all checks pass |
| Policy, rate limiting, auto-lock, logging | Copy files back out when protection is removed |

The folder path a user gives the broker is stored as a label and checked
against policy, but the broker never opens it.

### Which folders may be protected (scopes)
The broker decides, from the caller's SID (never from the request), which of
three scopes a folder falls in. The window runs the same rules first so it can
explain a refusal before anything happens.

| Scope | Where | Who can unlock | Since |
|---|---|---|---|
| `Profile` | Inside the caller's own profile, including OneDrive and other sync folders | Owner only | 0.1 |
| `Local` | Anywhere else on a **fixed** local drive (for example `D:\Accounts`), if `AllowFoldersOutsideProfile` is on | Owner only | 0.3.0 |
| `Shared` | Inside a shared area set by IT | Anyone signed in on that PC who knows the password | 0.1 |

Always refused: system folders on any drive (Windows, Program Files,
ProgramData, `$...` folders, System Volume Information, Recovery, Windows.old
and similar) and any AppData; Folder Vault's own folders; a whole known folder
(Documents, Desktop, a OneDrive root, `OneDrive\Documents`...), a whole
profile or shared area; anything under another profile from the machine's
ProfileList, under `C:\Users\Public` or `C:\Users` itself; drives that are not
`DriveType Fixed` (USB sticks, card readers, DVDs, network drives). Code:
`Get-FVPathScope` (pure rules) and `Resolve-FVPathScope` (adds this PC's
profiles and drives from `Get-FVMachineLayout`).

Widening the scope gives a person no new power. They do every file operation
with their own rights, so they can only protect a folder they could already
rename and delete; the broker still never touches the folder.

### OneDrive and other cloud sync folders
With Files On-Demand, every file and folder under OneDrive is a cloud
**placeholder**: a reparse point with tag `IO_REPARSE_TAG_CLOUD` (0x9000001A,
variants in bits 12 to 15). Windows shows these to most programs as reparse
points ("exposed placeholders"). Up to 0.2.5, Folder Vault treated every reparse
point as a link and refused the folder. From 0.3.0 it reads the tag
(`FindFirstFileW`, `dwReserved0`, through a small helper compiled once with
.NET Framework's C# compiler) and treats cloud tags as ordinary data. Any
other tag, or an unreadable one, is still a link and still refused.

* Files whose data is only online (`FILE_ATTRIBUTE_OFFLINE`, `RECALL_ON_OPEN`
  or `RECALL_ON_DATA_ACCESS`) are refused with instructions, so protection
  never depends on a download finishing.
* Folders with placeholders are copied with .NET rather than robocopy:
  robocopy's `/XJ` is not documented to tell placeholders from junctions.
* OneDrive does not sync junctions (Microsoft: "OneDrive doesn't support
  syncing by using symbolic links or junction points"). So once protected,
  the folder is deleted from OneDrive online and other devices, and the old
  copies stay in the OneDrive recycle bin for 30 days (93 for work or school).
  The window warns the person and asks first.

### Why a SYSTEM broker?
Attaching a VHDX and calling BitLocker's WMI provider require administrator
rights. Standard users must not get those rights, so a small broker running as
SYSTEM does the privileged work and exposes **only** a narrow, validated set of
operations over a local named pipe. The broker is the security boundary and is
written to treat every request as hostile.

### Recovery key escrow
Every vault gets a BitLocker recovery password. It is never shown to the user.
It is encrypted (CMS / PKCS#7, RSA-3072) to an **escrow certificate** whose
private key the IT team keeps offline. Only the IT team can recover a vault
whose password was forgotten. If no escrow certificate is installed, vault
creation is refused (fail closed).

## 4. Trust boundaries and threat model

### Assets
1. Contents of protected folders.
2. Vault passwords (in transit from UI to broker, in memory).
3. Recovery keys.
4. Integrity of the broker (it runs as SYSTEM).

### Adversaries
| ID | Adversary | Capability assumed |
|---|---|---|
| A1 | Staff member who knows an office user's Windows password | Interactive logon as that user (standard user) |
| A2 | Staff member with their own standard account on the PC | Interactive logon, can run scripts as themselves |
| A3 | Thief / someone who removes the disk or boots from USB | Offline access to the disk |
| A4 | Network attacker on the LAN | SMB/RPC access to the PC |
| A5 | Local administrator | Out of scope: an admin owns the machine |

### Threats and controls

| # | Threat | Control |
|---|---|---|
| T1 | A1 opens the folder while locked | Folder is empty; data only exists inside the encrypted VHDX |
| T2 | A1/A2 copies the VHDX for offline cracking | `Vaults\` is readable only by SYSTEM and Administrators |
| T3 | Online password guessing through the UI or a script talking to the pipe | Broker-side exponential back-off and lockout, persisted across restarts; failures logged |
| T4 | Offline brute force (A3, or after theft) | BitLocker key stretching; 12+ character minimum enforced in the broker; full-disk BitLocker on C: |
| T5 | Vault left unlocked when the user walks away | UI locks on screen lock; broker watchdog locks if the unlocking user's session is locked, disconnected or logged off, and after a maximum unlock time |
| T6 | A2 abuses the SYSTEM broker as a confused deputy (e.g. "protect" C:\Windows, or another user's folder) | The broker never reads, writes or mounts at user paths (see above). Paths are still canonicalised and policy-checked server-side; the user-side code refuses folders containing or reached through links, and its deletion never follows links |
| T7 | A2 creates the pipe first (pipe squatting) to steal passwords | Client refuses to talk to a pipe whose owner is not SYSTEM/Administrators; broker starts at boot; Interactive users get no CreateNewInstance right |
| T8 | A4 connects to the pipe over the network | Pipe ACL denies the NETWORK SID; only INTERACTIVE logons may connect |
| T9 | Malformed / oversized / slow requests crash or stall the broker | 64 KB frame cap, strict schema validation, read timeouts, single-request-per-connection |
| T10 | Passwords leak into logs | Logging allowlist: op, vault ID, result code only; unit test asserts passwords never reach the log |
| T11 | Data loss during protect/unprotect | Copy → hash-verify → only then delete originals; rollback on any failure; registry entry written before work starts so a crash is recoverable |
| T12 | Plaintext remnants (shadow copies, search index, thumbnails, Recent items) | Full-disk BitLocker; indexing disabled on vault contents; Recent-item cleanup on lock; shadow copy and thumbnail hardening documented and tested (see test plan) |
| T13 | Tampering with Folder Vault's own scripts | Installed under Program Files (admin-writable only); optional Authenticode signing with `-ExecutionPolicy AllSigned` |
| T14 | Unprotect / change password by someone passing an unlocked PC | Both operations require the vault password, verified by a fresh BitLocker unlock |
| T15 | Forgotten password | Admin reset requires the IT team's offline escrow key **and** a local admin; recovery key is rotated after use |
| T16 | A2 protects a folder other people use (for example `D:\Accounts`), so only they hold the password | Needs rename and delete rights the person already has (they could already move the files away). The window warns that a `Local` folder becomes personal; event 1000 records scope `Local`; IT can switch `AllowFoldersOutsideProfile` off, or make the area shared |
| T17 | A2 protects someone else's folder, or one on a removable or network drive | Refused by the broker from the machine's ProfileList and drive types (`PathOtherUser`, `PathNotLocalDisk`) |
| T18 | Data loss or leakage through OneDrive | Online-only files refused; copy verified by SHA-256 before anything is deleted; person warned that the folder leaves OneDrive and that OneDrive keeps old copies in its recycle bin |

### Accepted residual risks (documented for the client)
* **Shared Windows passwords still matter.** Someone who knows a user's Windows
  password can plant a program that runs when that user signs in (a keylogger,
  or a fake "Folder Vault" password window) and capture the vault password the next
  time the real user types it. Folder Vault cannot prevent this from inside the
  same account. Mitigations: give each person their own account and change the
  shared passwords; application control (App Control for Business / Smart App
  Control); `Get-FolderVaultHealth.ps1` lists sign-in programs and flags overrides
  of Folder Vault's menu items.
* A local administrator, or malware running as admin, can read an unlocked vault
  or capture passwords. Mitigation is keeping users as standard users.
* While a vault is unlocked, anyone using that same Windows session can read it.
* Passwords exist briefly as .NET strings in the UI and broker processes; .NET
  cannot guarantee they are wiped from memory.
* Applications may keep their own copies (e.g. Office AutoRecover, browser
  downloads, email attachments saved elsewhere).
* Restore points (shadow copies) made before a folder was protected still hold
  its old plaintext; the health check warns while any exist.
* A folder protected from OneDrive leaves its old copies in the OneDrive
  recycle bin (30 days, 93 for work or school) and in OneDrive's version
  history until those expire. Empty the OneDrive recycle bin to remove them
  sooner.
* A folder protected on a drive other than C: leaves deleted copies on that
  drive unless it too has BitLocker. Check-ThisPC.cmd lists such drives.
* A shared vault, once unlocked, can be read by any signed-in user of that PC
  until it locks. Auto-lock on screen lock / user switch keeps this window to
  seconds.
* If the broker stops, auto-lock pauses until the task restarts it (within
  1-5 minutes); it locks everything on start.

## 5. Pipe protocol

Frame: 4-byte little-endian length, then UTF-8 JSON, max 65,536 bytes.
One request and one response per connection.

```json
{ "v": 1, "op": "Unlock", "id": "<vault guid>", "password": "..." }
{ "ok": false, "code": "BadPassword", "message": "...", "data": {} }
```

Operations: `Ping`, `GetPolicy`, `List`, `Create`, `FinalizeCreate`,
`Unlock`, `Lock`, `LockAll`, `ChangePassword`, `Remove`, `AdminList`,
`AdminReset`. Unknown fields, wrong types or wrong case are rejected.

## 6. Vault lifecycle

**Protect:** *(user)* check folder → *(broker)* create VHDX → verify it is
the right, empty virtual disk → GPT/NTFS → BitLocker protectors (passphrase +
recovery) → escrow recovery key → encrypt (XTS-AES-256) → mount at
`Mounts\{id}` → *(user)* copy with robocopy → SHA-256 verify every file →
rename original aside → create junction → check it → *(broker)* lock →
*(user)* re-check original unchanged → delete original.

**Unlock:** attach VHDX → BitLocker unlock with passphrase → remove the
unlock shortcut (a volume mounts only on an empty folder) → mount at
`Mounts\{id}` (the user's junction now shows the files).

**Lock:** BitLocker lock (purges key from memory) → remove mount point →
detach VHDX → put the unlock shortcut back in `Mounts\{id}`.

The unlock shortcut is created by SYSTEM inside its own folder. Its target is
fixed (the installed `FolderVault.UI.ps1 -Action Unlock -Id <guid>`) and users get
read access only, so it cannot be repointed. If it cannot be created, locking
still succeeds; the folder then simply looks empty.

**Friendly lock (user side):** normal lock → if files are in use, close File
Explorer windows showing the folder and retry → only then ask the person
whether to force it. Nothing is ever forced without a yes, except auto-lock,
which follows `ForceDismountOnAutoLock`.

**Remove protection:** *(user)* unlock → copy out to a new folder → verify →
*(broker)* lock → *(user)* swap the junction for the restored folder →
*(broker)* re-verify the password → delete VHDX and escrow file. The vault is
deleted last, so no failure can lose data.

## 7. Resource use

Folder Vault runs all day on every PC, so it is designed to cost almost nothing
while folders are locked, which is most of the time.

| Process | When it runs | What it does while idle | Target, and measured where known |
|---|---|---|---|
| Background service (`FolderVault.Broker.ps1`, SYSTEM) | Always, one per PC | Waits on the pipe. While every vault is locked: no session queries, wakes once a minute. While one is unlocked: one quick process query every 5 s | under 120 MB memory, under 0.2 % CPU. **Measured:** 96 to 99 MB, 0.00 % CPU over a 10-second sample, all folders locked (health check on the first test PC, Windows 11 Enterprise, 13 Nov 2026) |
| Tray icon (`FolderVault.Tray.ps1`) | One per signed-in user (optional: `-NoTrayIcon`) | One process-name lookup every 10 s; asks the service for the folder list only when the menu opens or the screen has just locked | under 90 MB memory, under 0.2 % CPU |
| Windows (`FolderVault.UI.ps1`) | Only while a window is open | Loads WPF on demand; exits when the window closes | n/a |

Most of the memory is the Windows PowerShell runtime itself. A small compiled
C# service typically needs 10 to 20 MB instead. Windows ships a C# compiler with .NET
Framework, so that could be built on the PC at install time if the measured
figures turn out too high. The service's measured figure is within target, so
there is no case for that yet. The tray icon is still to be measured (W80).

What changed in 0.2 to get here: the tray no longer loads WPF, and no longer
asks the service for the folder list every 3 s while the screen is locked. The
session query moved from one WMI method call per Explorer process to a single
`Get-Process -IncludeUserName`. The service now sleeps for up to a minute when
there is nothing to watch, and the scheduled task runs at priority 7 (below
normal).
