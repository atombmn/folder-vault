# Folder Vault: security audit report (pre-pilot)

Audit of the prototype source code.
Version 0.1 audited 29 October 2026; 0.2 changes reviewed 12 November 2026 (section 6);
pre-deployment readiness audit of 0.2.4 on 13 November 2026 (section 7);
review of the 0.3.0 "protect any folder" change on 20 November 2026 (section 8);
publication review of 0.4.0 on 21 November 2026 (section 9);
first protection attempt on Windows, 22 November 2026 (section 10).

> **In plain words.** We read every line of Folder Vault looking for ways it could
> be broken into or could lose files, and ran hundreds of automated tests.
> Every serious problem found has been fixed and has a test that would catch
> it coming back. Four smaller risks cannot be fixed inside Folder Vault and are
> explained in [FOR-MANAGERS.md](FOR-MANAGERS.md). The one big thing still to
> do is run it on real Windows computers (section 5). Until that passes, it
> must not be installed for the client.
>
> **13 November 2026.** A second full review before deployment (section 7)
> found one fault that would have stopped every folder from being protected,
> and ten smaller ones. All are fixed in 0.2.5. The verdict is unchanged:
> run the Windows test programme on a test computer first.

## 1. Verdict

**Ready for Windows integration testing on a test VM. Not yet ready for a client
pilot.** The design and code have passed static analysis, 282 automated tests
and a manual line-by-line review, and every defect found has been fixed with a
regression test. Everything that depends on Windows itself (BitLocker, VHDX,
NTFS links, pipe security, the WPF window) has been written against documented
behaviour but **has not yet run on Windows**. The integration suite
`tests/windows/Invoke-FolderVaultIntegrationTests.ps1` (W01 to W71) proves or disproves
those assumptions and must pass on a VM before any client PC is touched.

## 2. Scope and method

| Item | Covered |
|---|---|
| Source | `src/` (7 files, ~3,700 lines), `install/`, `admin/` |
| Static analysis | PSScriptAnalyzer 1.25 with the Windows PowerShell 5.1 compatibility profiles (syntax, commands, types). Remaining 6 findings are false positives: WinForms types loaded with Add-Type (4) and the certificate-provider `-DeleteKey` parameter (2) |
| Custom static checks | Parse every file; no PowerShell 7-only syntax; no `Invoke-Expression`; no downloads; no `-Command` launches; no raw requests in logs; broker never imports user-side file code; XAML well-formed and every referenced control exists |
| Unit / scenario tests | Pester, 282 tests, all passing (PowerShell 7.4, Linux) |
| Mutation testing | 8 deliberate defects planted (skip verification, encrypt before escrow, remove throttling, loosen path checks, log every field, follow links when deleting, show other users' vaults and one more). **All 8 caught** |
| Manual review | Every function in the broker, engine, client and user-side modules, against the threat model in `ARCHITECTURE.md` |
| Not covered yet | Execution on Windows (see section 5) |

## 3. Findings

Severity: Critical / High / Medium / Low / Info. All findings below are **fixed**
unless marked *Accepted*.

| ID | Sev. | Finding | Resolution | Test |
|---|---|---|---|---|
| D-01 | Critical | First design had the SYSTEM broker copy, delete and mount at the user's folder path. A user could swap that folder for a junction to `C:\Windows` or another user's profile mid-operation and make SYSTEM read, destroy or overlay files (privilege escalation / data theft). | Redesigned: the broker only ever touches `C:\ProgramData\FolderVault\{Vaults,Escrow,Mounts}\<guid>`. All copying and deleting of user files runs in the user's own session with the user's own rights. | Engine/Static tests; W30, purple test P-05 |
| D-02 | High | A standard user could create a fake `FolderVaultBroker` pipe and harvest vault passwords. | Client sends nothing until it has verified the pipe's owner is SYSTEM/Administrators (a standard user cannot set that owner). Broker keeps one persistent pipe instance; users get no CreateNewInstance right. | W01, W33 |
| D-03 | High | A client holding the pipe busy could postpone auto-lock indefinitely. | Watchdog also runs after every connection; each request is cut off after 10 s. | W31 |
| D-04 | Medium | UI event handlers built with `GetNewClosure()` cannot see the script's own functions or `$script:` state when run with `-File`: buttons and the auto-lock timer would have failed. | Handlers rewritten to use dynamic scope / script-level state; background jobs tracked in a script table. | Manual UAT |
| A-01 | Medium | Exception text (for example a type-conversion error) can echo request values, so a password could reach the log despite the field allow-list. | Every secret of the current request is redacted from every log line. | Common A-01, W20, W70 |
| A-02 | Low | Any user could force-lock a shared vault someone else had unlocked, discarding their unsaved work. | Only the person who unlocked a vault can force it; others get a normal lock. | BrokerCore A-02 |
| A-03 | High | The engine initialised and formatted whatever disk number the attach step returned. Any mismatch would have wiped a real disk. | Before partitioning, formatting or unlocking, the disk must be the file-backed virtual disk of this vault's VHDX, and must be empty (RAW) to be formatted. (As first written the check used the disk's Location, which Windows leaves empty for VHDX disks; see A-20.) | Engine A-03 |
| A-04 | Medium | A file saved into the original folder between the copy and the deletion would have been lost. | The renamed original is re-hashed before deletion; if anything changed it is kept and the user is told. | UserOps A-04 |
| A-05 | Low | A failed forced BitLocker lock returned an undefined error code to the client. | Mapped to `InternalError`; logged. | Engine tests |
| A-06 | Low | A failure deleting the empty mount folder after deleting the container was reported as a failed removal, leaving a dangling registry entry. | Made best-effort; the container deletion is what is checked. | Engine tests |
| A-07 | Info | Unused privileged helper (local-admin group lookup) in the engine. | Removed. | n/a |
| A-08 | Medium | A string interpolation (`"$DiskNumber:"`) was a parse error: the engine would not have loaded on Windows. | Fixed; every file is now parse-checked by the test suite. | Static |
| A-09 | Medium | Windows PowerShell 5.1 reads BOM-less UTF-8 scripts as ANSI, corrupting non-ASCII text. | The package build saves every script as UTF-8 with BOM and CRLF line endings, and verifies it. | Package check |
| A-10 | Info | `@($genericList)` and `Join-Path` behave differently on PowerShell 7 / non-existent drives. | Replaced with `.ToArray()` and a pure path joiner. Installer insists on Windows PowerShell 5.1. | Unit tests |
| A-11 | Info | Auto-lock relies on the screen locking. Many PCs never lock when idle. | Installer sets "Machine inactivity limit" (default 10 minutes). | n/a |
| R-01 | Medium, accepted | **Shared Windows passwords remain a risk.** Someone who knows a user's Windows password can plant a sign-in program (keylogger, fake Folder Vault prompt) in that account and capture the vault password later. Not preventable from inside the same account. | Recommend own accounts + changing shared passwords (the root cause) and application control. Health check lists sign-in programs and fails on overrides of Folder Vault's menu entries. | P-10 |
| R-02 | Low, accepted | Anyone who can see a shared vault can trigger its lockout with wrong guesses (denial of service). | Logged (1010/1011); lockout is temporary; admin reset clears it. | P-15 |
| R-03 | Low, accepted | Shadow copies made before protection, Office AutoRecover, Windows Search and thumbnail caches may hold earlier plaintext. | Full-disk BitLocker required by installer; health check warns about restore points; covered by purple test P-04. | P-04 |
| R-04 | Low, accepted | Passwords exist briefly as .NET strings in the UI and broker processes. | Cleared after use; only an administrator can read another process's memory. | n/a |

## 4. Positive controls confirmed by tests

* Paths are normalised by hand with Windows rules and fail closed (19 hostile path forms rejected: traversal, UNC, device paths, streams, short names, reserved names, trailing dots/spaces).
* Requests: strict schema, case-sensitive, unknown fields rejected, size-capped frames, invalid UTF-8 rejected.
* Identity comes only from the pipe token; a request cannot claim to be someone else.
* Other users' personal vaults return `NotFound` for every operation (no existence oracle).
* Back-off after 3 wrong passwords, lockout at 10, persisted across broker restarts, shared across unlock / change-password / remove.
* Recovery key escrowed *before* encryption starts; no vault can exist without an escrowed key; new key escrowed before the old is deleted on rotation.
* New password protector added *before* old ones are deleted.
* Copy verified with SHA-256 on every file; silent single-byte corruption is caught.
* Deletion never follows links; link targets survive (tested with real symlinks).
* Damaged registry → broker refuses all vault operations and never overwrites the file.

## 5. Windows behaviour still to prove (integration suite)

| Assumption | Proven by |
|---|---|
| BitLocker WMI calls (passphrase/recovery protectors, XTS-AES-256 used-space encryption, unlock/lock, rotate) work on a VHDX volume as written | W10, W22, W50, W51 |
| A mounted volume's root ACL governs access through the mount point; the locked placeholder is empty | W11, W23 |
| Users reach `Mounts\<id>` through their junction while unable to list `C:\ProgramData\FolderVault` | W21, W23, W03 |
| Pipe owner/ACL as designed; identity from `RunAsClient` at identification level; NETWORK refused | W01, W02, W23, W52 |
| Owner check defeats a squatting pipe | W33 |
| robocopy as the user, including from the mount root, long and Unicode names | W10, W60 |
| Session-based auto-lock (signed out, screen locked) and maximum unlock time | W42, W43, W41 |
| WPF window, tray icon, Explorer menu | Manual UAT (see purple test plan) |

**Gate for pilot:** W01 to W80 all PASS on a Windows 11 Pro VM *and* on one
Windows 10 Pro VM, no open Critical/High findings after the purple team
exercise, and the client accepts R-01 to R-04 in writing.

## 6. Review of the 0.2 changes (12 November 2026)

Scope: the new tray script, the reworked window script, friendly locking, the
unlock shortcut, the faster session check, the idle broker, the set-up module,
installer, uninstaller, readiness check and the three `.cmd` launchers.
Method as before: line-by-line review, PSScriptAnalyzer (5.1 profiles), 321 unit
tests (39 new) and 6 new planted defects, all caught.

| ID | Sev. | Finding | Resolution | Test |
|---|---|---|---|---|
| A-12 | Medium | `Show-ProtectDialog` returned the text of a message box when the background service was down, which callers read as "protected". (Present since 0.1.) | Message results discarded everywhere; the function returns `$false` explicitly. | Manual UAT |
| A-13 | Low | The new lock helpers had a parameter named `-Confirm`, which clashes with PowerShell's built-in switch and could be bound by accident. | Renamed `-AskUser`. | UserOps 0.2 |
| A-14 | Low | `Uninstall.cmd` used an `if (...) else (...)` block; a package folder whose path contains a bracket, for example `FolderVault (1)` after a repeat download, would have broken it. | Rewritten without brackets; a static test forbids bracket blocks in launchers. | Static 0.2 |
| A-15 | Info | Uninstalling from Settings runs the uninstaller from inside the folder it deletes. | It continues from a temporary copy. | W-suite (manual) |
| A-17 | Medium | **Found on the first Windows install (0.2.1).** The health check called `.Count` on a function result that is empty when all is well. Windows PowerShell 5.1 strict mode throws on that, so the check crashed before reporting anything. The same class of fault could hide anywhere and is invisible to tests on PowerShell 7. | Fixed in 0.2.2. A static scanner now checks every `.Count` in every script; it found no other case. | Static 0.2.2 |
| A-19 | Medium | **Found on the first Windows run (0.2.3).** The health check crashed on an ordered table with number keys. This was the third crash in code that only runs on Windows: the unit tests had never executed the health script at all. | Text keys; static check for the pattern; the whole health script now runs end to end in the tests against simulated Windows answers, and that test catches A-17, A-18 and A-19 when they are put back. Fixed in 0.2.4. | HealthScript, Static 0.2.4 |
| A-18 | Low | **Found on the first Windows run (0.2.2).** The health check reported read-only access for Users as write access (false alarm), and its sign-in program list flagged every normal app, which teaches people to ignore it. | Write test uses the specific write bits only. Sign-in programs are compared with an administrator-only baseline and only changes are reported. Fixed in 0.2.3. | Health tests |
| A-16 | High | **Found on the first Windows install (0.2.0).** The background service took its program folder from `$PSScriptRoot` in `param()`, which Windows PowerShell 5.1 left empty under the scheduled task, so it never started. A start-up crash also left no trace. Unit tests ran on PowerShell 7 and never started the script this way. | Folder worked out in the script body; start-up trap writes `broker-startup.log` and event 1930; fixed in 0.2.1. | Static 0.2.1, BrokerStartup |

Security properties checked for the new code:

* **Unlock shortcut.** Written by SYSTEM only inside `Mounts\{id}`, which is
  the broker's own folder (D-01 still holds: the broker writes nothing at user
  paths). The target and arguments are fixed: the installed UI script and a
  GUID. No user-supplied text goes into the target or arguments. The owner (or
  Users, for shared vaults) gets read and execute only, so the shortcut cannot
  be repointed. It is removed before every mount and its creation can never
  fail a lock.
* **Closing Explorer windows** runs in the user's own session through the Shell
  COM object and only closes windows whose location is the vault folder or
  inside it. It cannot affect other users' sessions.
* **Forcing a lock** still needs an explicit yes from the person, or the
  `ForceDismountOnAutoLock` policy for automatic locks. Planted defects that
  force without asking were caught.
* **Idle broker.** Sleeping only skips the session query when no vault is
  unlocked or unfinished. Every request still wakes the broker at once, and the
  watchdog still runs after every connection. The maximum-unlock-time rule is
  unaffected, because a vault can only be timing out while it is unlocked.
* **Faster session check.** `Get-Process -IncludeUserName` (needs SYSTEM, which
  the broker has) replaces WMI. If it fails, the old WMI method is used; if both
  fail, only the timeout rule applies, as in 0.1. Name-to-SID results are cached.
* **Set-up.** Elevation uses Windows' own prompt (`-Verb RunAs`); nothing is
  run with `-Command` or from user-writable paths after installation. The
  readiness check changes nothing. The installer still refuses a `.cer` that
  contains a private key.
* **Tray.** Runs as the user with no extra rights and loads no WPF. It talks to
  the broker through the same owner-checked pipe client as everything else.

No new residual risks.

## 7. Pre-deployment readiness audit (13 November 2026)

**What this was.** A purple team *readiness* audit of 0.2.4, done without
Windows: an adversarial review of every script against purple test cases
P-01 to P-18, and a check that every Windows and .NET call is used as
Microsoft documents it. **It was not the live purple team exercise.** Nothing
was attacked on a real PC, and the vault code (BitLocker, VHDX, robocopy,
links) has still never run on Windows. The live exercise in
[PURPLE-TEAM-PLAN.md](PURPLE-TEAM-PLAN.md) is still required.

**Method.**

| Check | Result |
|---|---|
| Line-by-line review of `src`, `install`, `admin`, the launchers and the integration suite, attacker's view first | 11 findings (below) |
| Each WMI, Storage and BitLocker call checked against Microsoft's documentation (Win32_EncryptableVolume, MSFT_Disk, MSFT_DiskImage, Set-Partition, robocopy exit codes) | 3 findings (A-20, A-24, A-25) |
| Every .NET type, static method, constructor and property, every XAML element and attribute, and every member used on a named control, checked against the .NET Framework 4.8 reference assemblies (`tests/tools/Test-FVNetFrameworkApi.ps1`) | No problems. 2 reports were checked and are false positives (a variable enum name, and `New-Object byte[]`) |
| PSScriptAnalyzer with the Windows PowerShell 5.1 profiles | Only the known false positives (WinForms types loaded with Add-Type, the certificate provider's `-DeleteKey`) and empty `catch` blocks in the test suite |
| Unit tests (Pester, PowerShell 7 on Linux) | 407 passed, 1 skipped (a Windows-only folder permission test) |
| Planted defects: each fix below undone in turn | All 10 caught by a failing test |
| Verified on a real PC (the first test PC, Windows 11 Enterprise, 0.2.4) | Installer, readiness check, background service start-up, pipe owner check, health check, recovery certificate creation; 96 to 99 MB memory and 0.00 % idle CPU for the service |

**Findings.** All fixed in 0.2.5.

| ID | Sev. | Finding | Resolution | Test |
|---|---|---|---|---|
| A-20 | Critical | The disk check from A-03 compared `MSFT_Disk.Location` with the VHDX path. Microsoft documents Location as empty (NULL) for VHD and VHDX disks, so on Windows **every protection would have been refused**. No test caught it because the fake disks in the tests had a Location. | The link is now made through the disk image: `MSFT_DiskImage.ImagePath` must be this vault's file, the image must be attached, its `Number` must be this disk's number, and BusType must be File Backed Virtual (15), accepted as number or text. | Engine A-03 / A-20, W26 |
| A-21 | High | Removing protection copied from the volume's root folder with `robocopy /DCOPY:DAT`, which also copies the root's Hidden and System attributes, so the restored folder would have been hidden. The vault root also lost its "not indexed" mark after the copy. | The copy sets the destination folder's attributes in a `finally` block: plain Directory when restoring, Directory plus NotContentIndexed for the vault. | UserOps A-21, W60 |
| A-22 | High | The installer ran and copied whatever was in the package folder. If the folder was in a place staff can write to (Downloads, the desktop), someone who knows that account's password could swap a script or the recovery certificate before the installer ran, and their code would be installed to run as SYSTEM. | Before anything is installed: every file the installer uses is compared with `SHA256SUMS.txt`, and any extra script is refused; the package and certificate fingerprints are shown so the technician can compare them with the IT team's records; a folder that people other than administrators could change is refused unless the technician confirms (removable drives excepted). The files are then copied to a private folder under `C:\Windows\Temp` and checked again, and installed from there. | Setup tests |
| A-23 | Medium | Windows can give a new or newly attached partition a drive letter by itself, so an unlocked vault could have shown up in This PC as a separate drive. | `Set-Partition -NoDefaultDriveLetter $true` before formatting, and any letter given is removed after partitioning and after formatting. | Engine A-23, W26 |
| A-28 | Medium | In Windows PowerShell 5.1, a program's error output redirected with `2>` becomes a stopping error when ErrorActionPreference is Stop. The uninstaller called mountvol that way, so a harmless message would have stopped it half-way. | Every call to diskpart, mountvol, robocopy and reg goes through one function, `Invoke-FVNative`, which runs with Continue and checks the exit code. The uninstaller's one direct call is guarded the same way. A static test forbids any other form. | Static 0.2.5 |
| A-29 | Medium | If the health check could not close a signed-out person's registry (for example because PowerShell still held a handle), it said nothing. A registry left open stops that person signing in normally. | Up to five attempts, each after releasing handles; success is checked. If it is still open the check reports FAIL and says to restart the PC before that person signs in. | Health A-29 |
| A-24 | Low | BitLocker method arguments were checked against Microsoft's parameter lists: `Passphrase` casing matched to the documentation, and `PrecisionFactor` now passed as an unsigned number. | As described. | Engine A-24 |
| A-25 | Low | Every failed lock was reported to the person as "files are open". | Only 0x80070005 (documented as "applications are accessing this volume") on a normal lock means files in use; anything else is an error. | Engine A-25 |
| A-26 | Low | When run from Settings > Apps, the uninstaller continued from a copy in the person's own TEMP folder, which that person can change. | The copy goes to a private folder under `C:\Windows\Temp` that only SYSTEM and administrators can open. | Review |
| A-27 | Low | A junction's target can be reported as `\??\C:\...` instead of `C:\...`, which would have made a correct link look wrong. | Targets are converted to the plain form before comparing. | UserOps A-27 |
| A-30 | Info | Two window colours were set from text and left to PowerShell's type conversion. | Set through `BrushConverter` explicitly. | Review |

**What the purple test cases rest on now.**

| Case | Status after this audit |
|---|---|
| P-01, P-03, P-12, P-13 | Depend on BitLocker on the vault volume and on C:. Code reviewed; not yet run on Windows |
| P-02, P-06, P-14, P-15, P-16 | Broker logic covered by unit tests; pipe security proven on the first test PC (W01). Live run needed |
| P-04 | Residual risk R-03 unchanged; the live disk image search is still needed |
| P-05 | D-01 design re-checked: the broker writes only under `C:\ProgramData\FolderVault`. Needs the Process Monitor capture |
| P-07, P-08 | Owner check confirmed on the first test PC; network refusal still to run (W02) |
| P-09 | Strengthened by A-22 (installation) and A-26 (removal). Health check integrity check proven on the first test PC |
| P-10 | Accepted risk R-01, unchanged |
| P-11 | Needs the live screen-lock and sleep tests (W42, W43) |
| P-17 | Copy, verify and rollback covered by unit tests; A-21 fixed. Needs the live interruption tests |
| P-18 | Unchanged: backups of `Vaults` are the client's control |

**Not covered by this audit.** Anything that needs Windows to happen: real
BitLocker, VHDX and robocopy behaviour, the WPF window and tray, Explorer
menus, screen-lock detection, and the uninstaller and recovery tools end to end.

**Verdict.** **Do not deploy 0.2.5 at the client yet.** A-20 shows why: the
core of Folder Vault has never run, and the first time it runs it will meet
behaviour that only Windows can show. Deployment can be proposed once:

1. the integration suite (W01 to W80) passes on a Windows 11 Pro test VM and
   a Windows 10 Pro test VM;
2. a throwaway folder is protected, unlocked, locked by Win+L and unprotected
   by hand through the right-click menu on the test VM;
3. the live purple team exercise has no open Critical or High finding; and
4. the client has signed off the four risks in FOR-MANAGERS.md.

## 8. Review of 0.3.0: protecting any of your own folders (20 November 2026)

**The change.** People may now protect OneDrive folders and their own folders
outside their user folder on the PC's fixed drives (scope `Local`). Method as
in section 7: adversarial review, unit tests, planted defects. Nothing in this
change has run on Windows yet.

**Threats considered.**

| Threat | Decision |
|---|---|
| A staff member protects a folder others rely on (`D:\Accounts`) and keeps the password | Not new power: protecting needs rename and delete rights on the folder, done with the person's own token, so they could already move the files away. Warned in the window, logged (event 1000, scope `Local`), and IT can switch it off. Folders several people use should be shared areas. Purple case P-19 |
| Protecting another person's folder, `C:\Users\Public`, or `C:\Users` | Refused by the broker from Windows' ProfileList, read fresh on every request, so it holds for profiles on any drive (`PathOtherUser`) |
| Removable, optical and network drives | Refused unless `DriveType` is Fixed (`PathNotLocalDisk`): the junction would break, and the data would leave the PC |
| System folders on other drives (`D:\$Recycle.Bin`, System Volume Information, Windows.old) | Refused on every drive by first folder name |
| The broker as a confused deputy | Unchanged: the broker still never opens the folder path. Widening the policy widens only what the person's own code may do with the person's own rights |
| A junction disguised as a OneDrive file | Only the cloud tag family `0x9000x01A` is accepted, read from the file system itself. Any other or unreadable tag is a link. If the helper cannot be compiled, every reparse point is a link (fail-safe) |
| Online-only files changing or failing to download mid-copy | Refused before anything starts. All copies are still verified by SHA-256 before anything is deleted |
| Plaintext left in OneDrive after protection | Accepted, documented, and stated in the confirmation the person must accept: recycle bin (30 or 93 days) and version history |
| Plaintext left on an unencrypted D: | Check-ThisPC.cmd lists fixed drives without BitLocker; SETUP-GUIDE 5.6 |

**Findings during the work.** Both were caught by tests before release.

| ID | Sev. | Finding | Resolution |
|---|---|---|---|
| A-31 | High | Hex numbers such as `0xFFFFFFFF` and `0x9000001A` are negative Int32 values in PowerShell, so the first version of the cloud check threw on every reparse point. On Windows it would have stopped every protection. | Decimal constants; static test refusing 8-digit hex literals from `0x80000000` up |
| A-32 | Medium | The `WIN32_FIND_DATAW` structure was first declared with 64-bit FILETIME fields, which adds 4 bytes of padding and moves `dwReserved0` (the reparse tag). Every OneDrive file would have read as tag 0 and been refused as a link (fail-safe, but the feature would not have worked). | Two 32-bit fields per FILETIME; a test checks the offsets (tag at 36, name at 44) |

**Tests.** 445 unit tests pass (1 more runs only on Windows). Eleven planted
defects in the new code were each caught: structure layout, cloud tag mask,
cloud treated as link, other users' folders, fixed drives, the IT switch,
online-only files, the .NET copy for OneDrive, `OneDrive\Documents` as a whole
folder, Windows.old, and the hex literal rule. New Windows tests W13 to W15.

**Still to prove on Windows.** That `FindFirstFileW` returns the cloud tag to
Windows PowerShell 5.1 for OneDrive files (W14 records it), that OneDrive
accepts the folder being replaced by a junction without errors, and the
end-to-end round trips in W13 and W14.

**Verdict.** Unchanged from section 7: not for client PCs until the Windows
test programme and the manual throwaway-folder test pass on a test computer.

## 9. Publication review of 0.4.0 (21 November 2026)

The code was renamed and prepared for a public repository. The full record of
each step is in [PUBLICATION-AUDIT.md](PUBLICATION-AUDIT.md). Points that
matter for security:

| Check | Result |
|---|---|
| No private data in the repository: names, computer names, user names, e-mail addresses, web links, keys, certificates | None found. Private words checked with `Find-FVPrivateWords.ps1` against a list kept outside the repository; generic checks run in `Publication.Tests.ps1` on every push |
| Keys and certificates cannot be committed by mistake | `.gitignore` excludes `*.pfx`, `*.cer`, `*.p12` and `private-words.txt` |
| Rename did not change behaviour | All unit tests passed straight after the mechanical rename, before any other change |
| Weak-password list | Regional words moved to the `LocalWeakWords` setting; validated (letters and digits, 3 to 40 characters, at most 200), enforced by the service, hints in the window |
| Release packages | Downloaded reference assemblies are excluded from the build; the client kit passes the installer's own file check |

No new findings. The verdict in section 7 stands: not for real data until
the Windows test programme and the live exercise have passed.

## 10. First protection attempt on Windows (22 November 2026)

The first attempt to protect a folder on a real PC (Windows 11, 0.4.0, a
folder outside the user folder) failed safely: the copy could not be
checked, so nothing was changed, and the vault was removed.

| ID | Sev. | Finding | Resolution |
|---|---|---|---|
| A-33 | High | The vault root's permissions were applied through its mount point folder (`Mounts\{id}`). Windows applies such permissions to the mount point folder, not to the mounted volume's root (Microsoft KB 237701, 832234), so the root kept its format-time permissions and its owner was refused. It failed closed (nothing was changed, no one else could read the vault) but no folder could be protected. The unit tests did not catch it because they replaced the permission step with a stand-in. | Permissions are set with `SetFileSecurity` on the volume's own path (`\\?\Volume{GUID}\`), read back, and compared entry by entry with what was asked for; any difference stops the creation and rolls it back. Windows test W26 now checks the root's permissions. |
| A-34 | Medium | The second attempt (0.4.2) got past A-33 and the copy, then failed when the window set the vault root's attributes through `Mounts\{id}`: like permissions, attributes set through a mount point land on the mount point folder, which the person may only read. Failed closed. | The window no longer sets attributes on a mount point; the service sets "not indexed" on the root through the volume path when creating and on every unlock (a failure there does not block the unlock). |
| A-35 | High | The third attempt (0.4.3) was refused again even though the vault root's permissions were now right. Vaults were attached with `Mount-DiskImage`; Microsoft documents that a virtual disk attached without its own security descriptor takes the .vhdx file's, and the .vhdx files are SYSTEM and Administrators only, so the disk refused its owner. Failed closed. | Attach with diskpart `attach vdisk` (no descriptor of its own: behaves like a physical disk, so the root's permissions decide). Static rule against `Mount-DiskImage` in program code; diagnostic `admin\Test-FVVaultAccess.ps1`. |

**Lesson.** Behaviour that depends on how Windows treats a mount point cannot
be shown by a stand-in in a unit test. The Windows test programme (W10, W26)
would have found this on a test computer; it is still required before real use.

## 11. Changes in 0.4.5 (22 November 2026)

| ID | Sev. | Finding | Resolution |
|---|---|---|---|
| A-36 | Low | A failed copy check (fourth attempt, 0.4.4) told the person and IT nothing about what differed, so the cause could not be found from the report. Failed closed. | The message names up to three missing or different items with both sides' records (size and the first 8 characters of the SHA-256) and the copy tool's result; both full lists go to `%LOCALAPPDATA%\FolderVault\last-copy-check.txt` in the person's own profile. The log holds file names and sizes, no contents; file names inside a protected folder can be sensitive, so the file sits where only that person and administrators can read it. |
| D-1 | Decision | At the owner's request, the installer no longer sets the machine inactivity limit (`InactivityTimeoutSecs`). This removes one control: before, an unlocked folder at an unattended PC locked within 10 minutes. Now that depends on the PC's own screen lock settings, or on `-InactivityLockMinutes` at install. | Accepted risk, documented in FOR-MANAGERS.md (residual risk 2) and the setup guide. Folders still lock on screen lock, sign-out, restart and after `MaxUnlockMinutes` (4 hours). Removal on update and uninstall touches only a value a Folder Vault installer would have set. Recommendation: set a screen lock through Windows settings or policy on every PC. |
| A-37 | High | Fifth attempt (0.4.5), with A-36's detail: robocopy was refused opening the vault's top folder ("ERROR 5 Accessing Destination Directory ...\Mounts\{id}\") yet exited 0, so nothing was copied and only the copy check stopped it. robocopy sets the top folder's attributes and dates, which through a mount point land on the mount point folder (read-only for the person). Failed closed. | robocopy is given only folders below the top on both sides; top-level files are copied directly. Any "Accessing Source/Destination Directory" error counts as failure regardless of exit code. Behaviour and static tests, each shown to fail against the 0.4.5 code. The copy check (verify) remains the final guard. |
