# Folder Vault: purple team exercise plan

> **In plain words.** Before Folder Vault goes onto the client's computers, two
> groups of the IT team's security staff test it together on spare test computers. One
> group tries to get into protected folders the way a nosy colleague, a thief
> or a hacker would. The other watches whether Folder Vault stops them and whether
> the attempt shows up in the logs. Nothing here is run on the client's own
> computers or with their data. This document is the checklist for those two
> days.

Version 0.3.

## 1. Purpose

Prove, with the red team attacking and the blue team watching side by side,
that Folder Vault (a) keeps protected folders unreadable to someone who knows the
user's Windows password, (b) cannot be turned against the PC it runs on, (c)
never loses data, and (d) leaves evidence the blue team can act on. Every test
records **prevented?** and **detected?** separately.

## 2. Rules of engagement

* Run on **test VMs only** (Windows 11 Pro and Windows 10 Pro, snapshots taken
  before every destructive test). No client data; use the sample tree from the
  integration suite.
* Duration: 2 days. Day 1 automated suite + P-01 to P-09. Day 2 P-10 to P-20 and
  write-up.
* Stop and revert the snapshot if a test damages the VM. Any finding rated High
  or Critical stops the pilot until it is fixed and re-tested.

## 3. Lab set-up

| Account | Type | Role in the exercise |
|---|---|---|
| `alice` | Standard user | Office user who owns protected folders |
| `bob` | Standard user | Non-office staff member. **Knows alice's Windows password** (the client's real problem) |
| `itadmin` | Local administrator | IT. Holds the TEST escrow PFX on a separate machine |

* C: BitLocker on (one extra run with it off, for P-12).
* Folder Vault installed with a TEST escrow certificate; shared root `C:\Shared`.
* Blue tooling: Event Viewer / `Get-WinEvent` (provider `FolderVault`),
  `C:\ProgramData\FolderVault\Logs\broker.log`, `admin\Get-FolderVaultHealth.ps1`,
  Microsoft Defender, Sysinternals Process Monitor and Autoruns.

### Blue team signals

| Event ID | Meaning | Expected reaction |
|---|---|---|
| 1001 / 1002 / 1003 | Unlocked / locked by user / auto-locked (reason=ScreenLocked, SignedOut, Timeout) | Baseline |
| 1010 | Wrong vault password | Count per vault per day |
| 1011 | Vault locked out after repeated wrong passwords | **Alert**: someone is guessing |
| 1012 | Attempt refused while throttled/locked out | Supports 1011 |
| 1040 | Protect request refused by policy (e.g. path outside own profile) | **Investigate**: possible abuse attempt |
| 1050 / 1051 | Admin operation refused / admin password reset done | 1050 investigate; 1051 must match a ticket |
| 1060 / 1061 / 1062 | Pipe caller rejected / malformed frame / invalid request | **Investigate**: someone is probing the broker |
| 1900 to 1930 | Internal and pipe errors; 1930 = service failed to start | Fix / report to the IT team |

## 4. Automated baseline (run first)

`tests\windows\Invoke-FolderVaultIntegrationTests.ps1 -TestPfxPath <test pfx> -IncludeScreenLockTest`
on each VM. All W-tests must pass before manual testing starts. Test W80
records the memory and processor use; copy its figures into the report. Attach
`C:\FolderVaultTest\results.json` to the report.

## 5. Manual test cases

| ID | ATT&CK | Red team action | Expected prevention | Expected detection | Auto |
|---|---|---|---|---|---|
| P-01 | T1078 Valid Accounts | As bob, sign in as alice. Open alice's protected folder; search the disk (`dir /s`, Explorer search) for her file names and contents. | Folder empty; no file names or content found anywhere bob can read | 1001 absent (no unlock) | W11, W23 |
| P-02 | T1110.001 Password Guessing | Script 200 unlock attempts against alice's vault through the pipe (own client, not the UI). | Back-off after 3, lockout at 10, ~4 tries/hour afterwards | 1010 ×N, 1011, 1012 | W25 |
| P-03 | T1110.002 Password Cracking | As bob, copy `Vaults\*.vhdx`. Then, as itadmin, extract the BitLocker hash from the VHDX and run a GPU cracker against a 12-character and a 5-word passphrase for 8 hours. | Copy denied to bob. Record crack rate; neither passphrase cracked |; | W03 |
| P-04 | T1005 Data from Local System | After protecting a folder, image the VM disk and look for the original files: deleted-file carving (Autopsy), `vssadmin list shadows` / Previous Versions, Windows Search index, `thumbcache_*.db`, Recent items, Office AutoRecover, `pagefile.sys`, `hiberfil.sys`. Repeat with C: BitLocker off. | With C: BitLocker on and no older restore points: nothing readable offline. Online, list every place a copy survives | Health check warns on restore points | W12 |
| P-05 | T1068 Exploitation for Privilege Escalation | Make Folder Vault's SYSTEM broker touch something outside its folder: crafted `Create` paths over the raw pipe; replace the folder with a junction to `C:\Windows\System32` or bob's profile at every step of a protection (script the race with oplocks/`Rename` loops); mount-point and symlink tricks in `Documents`. Capture the broker with Process Monitor. | **Procmon shows zero file-system writes by the broker outside `C:\ProgramData\FolderVault`**, and zero reads of user profiles | 1040, 1062 | W30, W32 |
| P-06 | T1499 / fuzzing | Fuzz the pipe: random lengths, 64 KB+ bodies, invalid UTF-8, deep JSON, 1,000 rapid connections, connections that never send. | Broker stays up; auto-lock still fires within 15 s during the flood | 1061, 1062 | W31 |
| P-07 | T1557 / named-pipe impersonation | Stop the broker (as admin), create a fake `FolderVaultBroker` pipe as bob, then unlock as alice through the real UI and through the client module. | UI shows "could not confirm it is talking to the genuine background service"; fake pipe receives nothing | UI message | W33 |
| P-08 | T1021.002 SMB/Named pipes | From a second VM, connect to `\\<vm>\pipe\FolderVaultBroker` with alice's and itadmin's credentials. | Access denied (NETWORK SID denied) |; | W02 |
| P-09 | T1543 / T1574 Persistence & hijack | As bob/alice: write to `C:\Program Files\FolderVault`, edit the scheduled task, add `HKLM\...\Directory\shell` verbs, plant a `.psm1` in a user module path the broker might load. | All denied; broker loads modules by absolute path only | Health check: integrity PASS | W03 |
| P-10 | T1056.001 / T1056.002 Input capture | As bob, signed in as alice: add a Startup-folder script that logs keystrokes, and an `HKCU\Software\Classes\Directory\shell\FolderVault.Unlock` override that shows a fake password box. Then alice signs in and unlocks normally. | **Not prevented (accepted risk R-01).** Record whether Defender / App Control blocks it | Health check: FAIL on the override, WARN on the Startup item |; |
| P-11 | Physical / unattended | Alice unlocks and walks away: (a) Win+L, (b) switch user to bob, (c) idle 10 min, (d) close the lid / sleep. | Vault locks within ~5 s of (a)(b) and at the inactivity lock in (c). For (d) it locks when the lock screen appears on wake (needs "require sign-in on wake"); record the result | 1003 with reason | W42, W43 |
| P-12 | T1200 / offline | Boot the VM from a Linux ISO; mount the disk; try to read the vault and the deleted originals. Repeat with C: BitLocker off. | BitLocker on: nothing. Off: VHDX still encrypted; record whether originals are recoverable (expected yes → why the installer requires C: BitLocker) |; |; |
| P-13 | Memory | Hibernate while a vault is unlocked; resume; inspect `hiberfil.sys` from a USB boot with C: BitLocker off. | Record whether the vault key is present (expected only if C: is unencrypted) |; |; |
| P-14 | Recovery abuse | As alice (non-elevated): `AdminList`, `AdminReset` with made-up keys. As itadmin without the PFX: try to reset. | Refused; recovery needs elevation **and** the escrow key | 1050 | W52 |
| P-15 | Denial of service | As bob, lock out a shared vault with wrong guesses. | Lockout happens (accepted R-02). Admin reset procedure restores access within the SLA | 1011 |; |
| P-16 | T1070 Indicator removal | As bob, clear the Application log, delete `broker.log`, edit `vaults.json`. | All denied. Search all logs for the test passwords |; | W70 |
| P-17 | Data safety (chaos) | During protection of a 2 GB folder, at each step: kill the Folder Vault window, reboot the VM, fill the disk, unplug the network. Then sign in again. | No file lost in any case. Folder Vault offers to finish or undo; afterwards the folder is either protected or exactly as before |; | UserOps tests |
| P-18 | T1486 Ransomware | (a) User-level ransomware simulation while a vault is unlocked. (b) Admin-level deletion of `Vaults\*.vhdx`. | (a) encrypts unlocked files like any folder; (b) destroys vaults → shows the backup requirement | Defender |; |
| P-19 | T1485 / T1489 Hijack a shared folder | As bob (standard user), protect `D:\Accounts`, which alice and bob both use; then as bob protect `C:\Users\alice\Documents\x`, `C:\Users\Public\x`, `E:\x` on a USB stick and a mapped network drive, through the window and through the raw pipe. | `D:\Accounts`: allowed only after the "only you can open it" warning, and only if bob can already delete it. All others refused (`PathOtherUser`, `PathNotLocalDisk`) | 1000 scope Local; 1040 | W13, W15 |
| P-20 | OneDrive | Protect a OneDrive folder holding online-only, locally available and always-available files, a 1 GB file and an Office file open in another window. Watch OneDrive online, the OneDrive recycle bin and a second device. Remove protection again. | Online-only files refused with instructions; otherwise every file verified before anything is deleted; folder gone from OneDrive online and other devices, back after removal. Record what stays in the recycle bin and version history | 1000 | W14 |

## 6. User acceptance (non-technical staff)

Five office users, no instructions beyond the one-page user guide. Each must,
unaided: protect a folder by right-clicking it, lock it, unlock it from the tray,
change its password, remove protection. Record time taken, errors, and what
they said. Target: all five complete all tasks; median under 2 minutes each.

## 7. Scoring and report

For each test: Prevented (Yes/Partly/No), Detected (Yes/No), Evidence
(screenshots, Procmon logs, event IDs), Severity of any gap, Recommendation.

**Exit criteria for the pilot:** all W-tests pass on both VMs; no open
Critical or High finding; every Medium has a fix or written acceptance; the
client signs off R-01 to R-04 and has agreed actions for the shared Windows
passwords.
