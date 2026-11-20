# Folder Vault: specification

Version 0.4.0, November 2026.

> **In plain words.** This is the list of what Folder Vault must do, and how
> each point is checked. Every requirement has a number (FR for what it does,
> SR for security, NFR for qualities such as speed and ease of use, C for
> fixed constraints). The last column names the test that proves it: unit
> tests in `tests/unit`, Windows tests (W..) in
> `tests/windows/Invoke-FolderVaultIntegrationTests.ps1`, and purple team
> cases (P..) in [PURPLE-TEAM-PLAN.md](PURPLE-TEAM-PLAN.md).

## 1. Purpose

In many small offices, several people know each other's Windows passwords.
Anyone who signs in as a colleague can open that colleague's files. Folder
Vault puts a second, separate password on chosen folders, so that knowing
someone's Windows password is no longer enough to read them.

The original brief, in short:

1. Staff choose folders to protect, and set the password that opens each one.
2. A password can be shared with chosen colleagues.
3. Adding and removing protection, locking and unlocking must be very easy.
4. It must be security tested and purple team audited.
5. Later additions: easy install and removal; very light on the computer;
   documents that non-technical readers understand; any of the person's own
   folders can be protected, including OneDrive.

## 2. Users

| Who | What they do |
|---|---|
| **Staff** (standard Windows users) | Protect, unlock, lock and unprotect their own folders; share passwords |
| **IT team** (local administrators) | Install, configure, check health, recover forgotten passwords, remove |
| **Managers** | Decide whether to use it; accept the remaining risks in writing |
| **Snooper** (the threat) | Someone who knows a colleague's Windows password and signs in as them |

## 3. Constraints

| ID | Constraint | Why |
|---|---|---|
| C-01 | Windows 10 and 11 Pro, Enterprise or Education. Not Home. | Needs BitLocker |
| C-02 | Workgroup (no domain, no server) | The office it was built for |
| C-03 | Written in Windows PowerShell 5.1 on .NET Framework 4.8, using only parts of Windows | No compiler or extra software available; nothing to install but scripts |
| C-04 | No internet connection needed | Offices with poor connectivity |
| C-05 | Runs from double-clickable files for install, check and removal | Installed by people who do not use PowerShell |

## 4. Functional requirements

| ID | Requirement | Where | Checked by |
|---|---|---|---|
| FR-01 | A person can protect a folder from the right-click menu or the Folder Vault window. The folder stays where it is, with the same name. | UserOps, UI | UserOps tests; W10, W11 |
| FR-02 | Each protected folder has its own password, separate from the Windows password, chosen by the person. | BrokerCore | BrokerCore tests; W20, W21 |
| FR-03 | A locked folder shows a single item, "Locked - double-click here to unlock". Double-clicking it, or the right-click menu, asks for the password. | Engine, UI | W11 |
| FR-04 | Unlocking gives back every file exactly as it was. | UserOps | Hash verification tests; W21 |
| FR-05 | A person can lock a folder from the right-click menu, the tray icon, the window, or Ctrl+Alt+L (all folders). | UI, Tray | Manual; W24 |
| FR-06 | Folders lock by themselves when the screen locks, when the person signs out, when the background service restarts, and after a maximum time (`MaxUnlockMinutes`, 240 by default). | Broker | BrokerCore tests; W40 to W43 |
| FR-07 | A person can change a folder's password. | BrokerCore | W50 |
| FR-08 | A person can remove protection; the files come back as an ordinary folder, checked file by file, and the container is deleted. | UserOps | UserOps tests; W60 |
| FR-09 | **Sharing.** Folders inside an IT-defined shared area can be unlocked by anyone signed in on that PC who knows the password. All other folders can be unlocked only by the person who protected them. | BrokerCore | BrokerCore tests; W23, W42 |
| FR-10 | **Which folders.** A person can protect any folder of their own: inside their user folder (including OneDrive), or elsewhere on the PC's fixed drives if `AllowFoldersOutsideProfile` is on (default). | Common (`Get-FVPathScope`) | Common tests; W13, W14 |
| FR-11 | **Always refused,** with a plain reason: system folders on any drive, AppData, Folder Vault's own folders, a whole Documents, Desktop, Downloads, OneDrive, user folder or shared area, other people's folders, `C:\Users\Public`, removable and network drives, folders that are or contain links, OneDrive folders with online-only files. | Common, UserOps | Common and UserOps tests; W15, W30, W32 |
| FR-12 | **Recovery.** A forgotten password can be reset by the IT team, using a recovery key that only the IT team can decrypt. The key is replaced after use. | Engine, admin tools | W51 |
| FR-13 | **Install, check and remove** by double-clicking `Install.cmd`, `Check-ThisPC.cmd` and `Uninstall.cmd`; removal also from Settings > Apps. Removal lists protected folders and offers to stop or keep them. | install | Setup tests; manual |
| FR-14 | **Health check** for the IT team: program and data permissions, service state and identity, BitLocker, restore points, new sign-in programs, event counts, memory and CPU use. | admin | Health and HealthScript tests; W71 |
| FR-15 | **Settings** in one file (`config.json`), each validated with a safe default (SETUP-GUIDE 5.5). | Common | Common tests |
| FR-16 | **Events.** Every protect, unlock, lock, refusal and recovery is written to the Windows event log, without passwords. | Broker | W70 |

## 5. Security requirements

| ID | Requirement | Where | Checked by |
|---|---|---|---|
| SR-01 | Files at rest are encrypted with BitLocker XTS-AES-256 inside a VHDX container. Without the password the container shows no plaintext. | Engine | W12, W22; P-03, P-12 |
| SR-02 | The only key protectors are the password and an escrowed recovery key. No automatic unlock. | Engine | W22 |
| SR-03 | Only the background service (SYSTEM) can create, unlock or lock containers. Staff cannot read containers, recovery keys or the registry of vaults. | install, Engine | W03; P-04, P-05 |
| SR-04 | The service identifies callers from Windows (named pipe client token), never from the request. Network callers are refused. | Broker | W01, W02; P-07, P-08 |
| SR-05 | The service never opens a path a person sends; it only records it. All file work is done by the person's own process with the person's own rights (no confused deputy). | BrokerCore, UserOps | W30; P-05 |
| SR-06 | The client checks it is talking to the genuine service (pipe owner is SYSTEM or Administrators) before sending a password. | Client | W33; P-07 |
| SR-07 | Passwords: at least `MinPasswordLength` (12) characters; refused if mostly a common word, a word from `LocalWeakWords`, the user name, repeated or sequential characters. Checked by the service; the window's check is only a hint. | Common | Common and BrokerCore tests |
| SR-08 | Guessing is slowed after `BackoffStartAfter` (3) wrong passwords and locked out for `LockoutMinutes` (15) after `MaxFailedAttempts` (10). | BrokerCore | BrokerCore tests; W25; P-02 |
| SR-09 | Passwords never appear in logs, error messages or events. | Common, Broker | Common tests (A-01); W70 |
| SR-10 | Recovery keys are encrypted (CMS, RSA-3072) to a certificate whose private key never sits on a client PC. Recovery needs that key and a local administrator. | Engine, admin | W51, W52; P-14 |
| SR-11 | The installer checks its own files against the release's SHA-256 fingerprints, shows the package and certificate fingerprints, refuses packages that staff could have changed (unless confirmed), and installs from a private copy. | install | Setup tests |
| SR-12 | Copies are verified (SHA-256 by default) before any original is deleted; a failure rolls back. | UserOps | UserOps tests; P-17 |
| SR-13 | Program folder writable only by administrators; data folder readable only by SYSTEM and administrators. | install | W03, W71 |

## 6. Non-functional requirements

| ID | Requirement | Target | Checked by |
|---|---|---|---|
| NFR-01 | Light on the computer while every folder is locked | Service under 120 MB and 0.2 % CPU; tray icon under 90 MB | Measured on a Windows 11 test PC: 96 to 99 MB, 0.00 % CPU; W80 |
| NFR-02 | Easy for staff | Every message in plain English, saying what to do; one-page user guide | Common tests (message text); trial with five staff (planned) |
| NFR-03 | Easy for IT | No typing needed for install, check or removal; every installer problem explains the fix | Manual |
| NFR-04 | Works on Windows PowerShell 5.1 | No PowerShell 7-only syntax or APIs; scripts saved as UTF-8 with BOM and CRLF | Static tests, PSScriptAnalyzer (5.1 profiles), .NET Framework 4.8 API test |
| NFR-05 | Data safety first | No step deletes data before the copy is verified; any failure leaves the original in place | UserOps tests; P-17 |
| NFR-06 | Documented for each reader | Staff, IT, managers, technical reviewers | docs/ |

## 7. Out of scope

* Protection against a local administrator. An administrator can get round
  any protection on the same PC.
* Protection against a keylogger planted in the person's own account by
  someone who knows their Windows password (accepted risk R-01: give each
  person their own account and change shared passwords).
* Domain or central management, and Windows Home.
* Removing copies made before a folder was protected (old email
  attachments, USB copies, restore points, OneDrive recycle bin).

## 8. Acceptance

Folder Vault is ready for real use when:

1. the unit tests pass (`Invoke-Pester ./tests/unit`);
2. the Windows test programme (W01 to W80) passes on a Windows 11 Pro and a
   Windows 10 Pro test computer;
3. a throwaway folder, a OneDrive folder and a folder on another drive are
   each protected, unlocked, locked by Win+L and unprotected by hand;
4. the live purple team exercise (P-01 to P-20) leaves no open Critical or
   High finding; and
5. the managers accept the remaining risks in writing (FOR-MANAGERS.md).

**Status at 0.4.0:** 1 passes; 2 to 5 are still to do. The installer,
service, health check and folder rules have run on a Windows 11 test PC; the
container work (BitLocker, VHDX, copying, linking) has not yet run on Windows.
