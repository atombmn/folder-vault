# Changelog

All notable changes. Versions before 0.4.0 were developed under an internal
working name; they are listed here under the name Folder Vault.

## 0.4.6 (22 November 2026)

### Fixes
- **Protecting a folder failed with "The copy could not be verified"**. The
  detail added in 0.4.5 showed robocopy reporting "ERROR 5 Accessing
  Destination Directory ...\Mounts\{id}\ Access is denied" and then exiting
  with code 0, having copied nothing. robocopy opens the top folder it is
  given to set its attributes and dates; on a mount point those land on the
  mount point folder, which the person may only read (the same Windows
  behaviour as A-33 and A-34). robocopy is now never given the top of either
  side: each top-level folder gets its own robocopy run, and top-level files
  are copied directly with their attributes and dates (A-37).
- A robocopy line saying it could not open a source or destination folder now
  counts as failure even when the exit code says success.

### Added
- Tests: robocopy is only given folders below the top (by behaviour and by a
  static check, both shown to catch the old code); a refused folder with exit
  code 0 stops the copy; a file that was retried and then copied does not.

## 0.4.5 (22 November 2026)

### Changes
- **The screen lock time is now optional.** Earlier installers always set
  Windows' machine inactivity limit (10 minutes by default). From 0.4.5 the
  installer leaves the screen lock alone unless `-InactivityLockMinutes` is
  given. Updating a PC, or removing Folder Vault, takes away the limit an
  earlier installer set, so Windows' own screen lock settings apply again. A
  limit is removed only when it is what a Folder Vault installer would have
  set (a whole number of minutes from 1 to 60, or from 0.4.5 the exact value
  recorded in `install-manifest.json`); a value set some other way is left as
  it is. Folders still lock when the screen locks (`LockOnScreenLock`, which
  can be turned off in config.json).

### Fixes
- **"The copy could not be verified" said nothing about why.** The message
  now names the items that are missing or different, shows both sides'
  records (size and the start of the file's fingerprint), and gives the copy
  tool's exit code and output. Both full lists are saved to
  `%LOCALAPPDATA%\FolderVault\last-copy-check.txt` (names and sizes only, no
  file contents). The same applies when unprotecting.

### Added
- Tests for the new detail and log, and for when the screen lock is and is
  not put back.

## 0.4.4 (22 November 2026)

### Fixes
- **Protecting a folder was still refused** ("Access to the path
  ...\Mounts\{id} is denied") after 0.4.1 and 0.4.3. Vaults were attached
  with `Mount-DiskImage`. Microsoft documents that a virtual disk attached
  without a security descriptor of its own takes the descriptor of its
  .vhdx file, and Folder Vault's .vhdx files can be opened only by SYSTEM and
  Administrators, so the attached disk turned away everyone else, its owner
  included. Vaults are now attached with diskpart's `attach vdisk`, which by
  default gives the disk no descriptor, so it behaves like a physical disk
  and the vault root's own permissions (A-33) decide who gets in (A-35). Any
  drive letter Windows gives an attached vault is removed.

### Added
- `admin\Test-FVVaultAccess.ps1`: a three-step check for IT (set up as
  administrator, check as the person, clean up) that builds two small test
  disks, attached both ways, and reports exactly what the person can and
  cannot do with each. Changes nothing in Folder Vault.
- Tests: vaults are attached with diskpart, never twice, with any drive letter
  removed; diskpart paths cannot carry extra commands; a static check that no
  program code calls `Mount-DiskImage`.

## 0.4.3 (22 November 2026)

### Fixes
- **Protecting a folder still failed**, now with "Exception setting
  "Attributes": Access to the path is denied". After copying, the window set
  the vault root's attributes through the mount point folder, and Windows
  applied them to the mount point folder (which only the background service
  may change) instead of the vault: the same Windows behaviour as A-33, for
  attributes. The window now leaves a vault root's attributes alone; the
  background service marks the root "not indexed" through the volume's own
  path when it creates the vault and every time it unlocks it (A-34).
  Restoring a folder still resets its attributes as before (A-21).

### Added
- Tests: attributes are never set through a mount point; the service marks
  the root on every unlock, and a failure to mark it does not stop the unlock.

## 0.4.2 (22 November 2026)

### Fixes
- **Updating stopped at step 2** with "Invoke-CimMethod : Not found". The
  installer stops the old background service's scheduled task, then ends any
  Folder Vault processes still running. The service often ended by itself in
  between, and asking Windows to end a process that had already gone was
  treated as a fatal error. Processes are now ended with one shared function,
  `Stop-FVProcesses`, which ignores processes that have already gone, waits up
  to 10 seconds for the rest, and says so plainly if one will not stop. The
  uninstaller uses it too.

### Added
- Four unit tests for stopping processes (including the one that has already
  gone, with ErrorActionPreference set to Stop), and a static check that no
  script ends a process with the WMI Terminate method.

## 0.4.1 (22 November 2026)

First fault found when protecting a folder on a real Windows PC.

### Fixes
- **Protecting a folder failed** with "The copy could not be verified ...
  Access to the path 'C:\ProgramData\FolderVault\Mounts\{id}' is denied".
  The vault's permissions were set through its mount point folder, and
  Windows applies permissions set that way to the mount point folder itself,
  not to the root of the mounted volume (Microsoft KB 237701 and 832234). The
  vault's root kept the permissions it was formatted with, which did not let
  its owner in. The background service now sets the root's permissions
  through the volume's own path (`\\?\Volume{GUID}\`), reads them back, and
  stops with a clear error if they are not exactly right (A-33). The "do not
  index" mark is set on the root the same way.

### Added
- Unit tests for the new permission step (it runs after mounting, on the
  volume path, and a failure rolls everything back), for comparing security
  descriptors, and that the native helper compiles.
- Windows test W26 now reads the vault root's permissions and checks that
  they let in its owner and nobody else.

## 0.4.0 (21 November 2026)

**First public release as Folder Vault.** No change to how folders are
protected; existing behaviour and the background service protocol are the
same as 0.3.0. **Still a prototype:** see SPECIFICATION.md, section 8.

### Changed
- Renamed to **Folder Vault** throughout: program folder
  `C:\Program Files\FolderVault`, data folder `C:\ProgramData\FolderVault`,
  service, scheduled tasks, event source, registry keys and commands
  (`FV` prefix). This is a new product name, so 0.4.0 installs alongside, not
  over, earlier test installs: remove those first.
- Names of people, organisations and computers removed from code, tests and
  documents. The organisation's role is now "the IT team".
- The built-in list of weak password words no longer contains regional
  words. Add your own with the new **LocalWeakWords** setting (place names,
  the organisation's name, products). The background service sends them to
  the window, so its hints match the service's decision.

### Added
- `docs/SPECIFICATION.md`: every requirement, and the test that proves it.
- `docs/PUBLICATION-AUDIT.md`: how the code was prepared for publication, and
  what was checked at each step.
- `docs/PUBLISHING.md`: putting the project on GitHub and making releases.
- `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, `.gitattributes`,
  `.gitignore`, and a GitHub Actions workflow that runs the unit tests, the
  analyzer and the package build on every push.
- The .NET Framework 4.8 API check is now a unit test
  (`NetFrameworkApi.Tests.ps1`); `tests/tools/Get-FVReferenceAssemblies.ps1`
  downloads what it needs from nuget.org.
- `Publication.Tests.ps1`: no e-mail addresses, no unexpected links, only
  made-up user names in examples. `tests/tools/Find-FVPrivateWords.ps1` checks
  for your own private words, kept in a list outside git.
- Every PowerShell file in the repository is saved as UTF-8 with a byte order
  mark, as Windows PowerShell 5.1 needs.

### Removed
- The "about" web link in Settings > Apps.

## 0.3.0 (20 November 2026)

**Protect any of your own folders.** Until now a folder had to be inside the
person's user folder, and OneDrive folders were refused (the "That folder
cannot be protected" message seen on the first test PC for
`OneDrive\Documents\VaultTest`). **Still not for client PCs** until the
Windows test programme has passed on a test computer.

### New
- **OneDrive folders** can be protected. Folder Vault now tells OneDrive's own
  files (cloud placeholders) apart from links, by reading each item's reparse
  tag. Junctions and symbolic links are still refused.
- Before a OneDrive folder is protected, the window explains that it will
  stop syncing and leave OneDrive online, and asks to confirm. Folders with
  online-only files are refused with instructions ("Always keep on this device").
- **Folders outside the user folder** on the PC's own drives, such as
  `D:\Accounts` or `C:\Data\HR`, can be protected. They are personal: only the
  person who protected them can open them, and the window warns about that.
- IT can switch that off: setting `AllowFoldersOutsideProfile`, or installer
  option `-FolderRule UserFoldersOnly`.
- **Clearer refusals.** The window now says why a folder cannot be protected:
  a whole Documents or OneDrive folder, someone else's folder, a USB stick or
  network drive, a system folder, or online-only files.
- **Client kit.** The build makes `FolderVault-<version>-client.zip`, with only
  what a client PC needs and its own fingerprints.
- Check-ThisPC.cmd lists other fixed drives without BitLocker.
- SETUP-GUIDE Part 2a: installing from a folder only administrators can
  change (`C:\FVInstall`), and section 5.6 on which folders can be protected.

### Still refused, on purpose
System folders on any drive, AppData, Folder Vault's own folders, a whole
Documents, Desktop, Downloads, OneDrive or user folder, other people's folders
(found from Windows' list of profiles, wherever they are), `C:\Users\Public`,
removable and network drives, and folders that contain links.

### Fixes found while building this
- PowerShell 5.1 reads `0xFFFFFFFF` as -1, so the first version of the cloud
  check would have crashed. Decimal numbers are used, and a static test now
  refuses such hex numbers anywhere in the code.
- The Windows file-information structure was first declared with 64-bit time
  fields, which would have shifted the reparse tag by 4 bytes and made every
  OneDrive folder look like a link. A test now checks every field offset.

### Tests
- Windows tests W13 (folder outside the user folder), W14 (OneDrive, skipped
  if OneDrive is not set up) and W15 (other people's folders, Public, unused
  drive letter, whole Documents). The suite can now report SKIP.
- 38 more unit tests (445 in total, plus 1 that runs only on Windows). Eleven
  planted defects in the new code were each caught.
- Purple team cases P-19 (taking over a folder others use) and P-20 (OneDrive).

## 0.2.5 (13 November 2026)

From the pre-deployment readiness audit (SECURITY-AUDIT.md, section 7).
**Still not for client PCs:** run the Windows test programme on a test computer first.

### Fixes
- **Protecting a folder would always have failed on Windows.** The safety
  check that makes sure Folder Vault only formats its own virtual disk relied on a
  disk property that Windows leaves empty for virtual disks. It now uses the
  disk image's own record of which disk it is (A-20).
- **A folder would have come back hidden** after "Remove protection", because
  the copy carried over the attributes of the vault's root folder (A-21).
- An unlocked vault could have appeared in This PC as an extra drive. Vault
  disks are now told never to take a drive letter (A-23).
- The uninstaller could have stopped half-way on a harmless message from a
  Windows program. All such programs now run through one safe helper (A-28).
- The health check now makes sure it has closed each signed-out person's
  registry, and says so plainly if it could not (A-29).
- A failed lock is no longer always reported as "files are open" (A-25).
- Smaller corrections to BitLocker call arguments, link target comparison and
  window colours (A-24, A-27, A-30).

### Security
- **The installer checks its own files** against the published fingerprints before
  installing, refuses extra scripts, shows the package and certificate
  fingerprints for the technician to compare, warns when the folder it runs
  from could have been changed by staff, and installs from a private copy (A-22).
- The uninstaller's temporary copy is kept in a private folder (A-26).

### Added
- Windows test W26 (vault disk has no drive letter and is the right disk);
  W60 now also checks the restored folder's attributes.
- 36 unit tests (407 in total), including the installer package checks and a
  static check that no script redirects a program's error output unsafely.
- The release build prints the package fingerprint for the release note, and
  the changes zip now carries the new fingerprints file.

### Changed
- `Test-FVGrantsWrite` moved from the health check module to
  `FolderVault.Common.psm1`, so the installer and the health check share one copy.

## 0.2.4 (13 November 2026)

### Fixes
- **The health check crashed** with "Index was out of range". The table of
  event names (added in 0.2.3) used numbers as keys in an ordered table, and
  PowerShell reads `$table[1003]` on such a table as "item number 1003", not
  "the item with key 1003". The keys are now text.

### Added
- **A test that runs the whole health check from start to finish**, with
  Windows' answers simulated (task, WMI, permissions, event log, registry,
  shortcuts). The three health check crashes found on the first PC were all in
  code no test had run; this one catches each of them when they are put back.
- A static check across every script for number keys in ordered tables.
- The health check's registry and shortcut reads and its event summary moved
  into `admin\FolderVault.Health.psm1`, so they can be tested.

### Changed
- User profiles are no longer required to be on drive C:.

## 0.2.3 (13 November 2026)

Health check fixes from the first run on a real PC (the first test PC).

### Fixes
- **"Program folder permissions: FAIL" was a false alarm.** Staff are meant to
  be able to read and run Folder Vault. The check compared against the Windows
  groups "Modify" and "Full control", which include the read rights, so read
  access counted as write access. It now looks only at rights that allow
  changing things.
- The CPU figure was an average since the service started, so straight after
  a start it mostly measured start-up (0.63% after one minute). The check now
  takes a live 10-second sample as well, and says when the average still
  includes start-up.

### Changed
- **Sign-in programs are compared with a baseline.** The first run records
  what starts when each person signs in. Later runs warn only about programs
  that are new or now run something different, and list them by name. Normal
  apps no longer raise warnings on every run. After checking new ones, accept
  them with `-ResetBaseline`. A replaced Folder Vault menu item is still an
  immediate FAIL.
- People who are signed out are now checked too (their registry is opened
  briefly and closed again), and service accounts such as IIS pool profiles
  are left out.
- Failed service starts (event 1930) are counted, and an earlier failed start
  is shown with its reason.
- Plainer wording in the report, and a summary line that counts warnings.

### Added
- `admin\FolderVault.Health.psm1`, the health check's decision logic, with
  27 unit tests (364 in total).

## 0.2.2 (13 November 2026)

### Fixes
- **The health check crashed** on Windows with "The property 'Count' cannot be
  found on this object". When no folder permissions were wrong, the permission
  check returned nothing, and Windows PowerShell 5.1 in strict mode will not
  count nothing. (PowerShell 7 allows it, which is why the tests missed it.)

### Added
- `tests\tools\Find-FVUnsafeCount.ps1` and a test that runs it over every
  script: each `.Count` must be on something that is certainly a collection.
  It found the health check bug and nothing else.

### Notes
- A scheduled-task result of `2147946720` (0x800710E0, "request refused") is
  normal while the service is running: the 5-minute safety trigger is refused
  because a copy is already running. Check the task's **State** instead.

## 0.2.1 (12 November 2026)

### Fixes
- **The background service would not start** on Windows (task result 1, error
  "Cannot bind argument to parameter 'Path' because it is an empty string").
  Its program folder came from `$PSScriptRoot` in the script's `param()` block,
  which Windows PowerShell 5.1 left empty when the scheduled task started it
  with `-File`. The folder is now worked out in the script body.
- The same pattern was removed from the build script.

### Added
- If the background service ever fails to start, the reason and script line
  go to `C:\ProgramData\FolderVault\Logs\broker-startup.log` and the Application
  event log (event 1930). The installer shows that reason when it gives up.
- Tests: a static check that no script uses `$PSScriptRoot`, `$PSCommandPath`
  or `$MyInvocation` in `param()`, and a test that starts the service script
  the way the scheduled task does. 336 unit tests.

## 0.2.0 (12 November 2026)

Easier to install, easier to use, lighter on the computer, and documentation
rewritten for non-technical readers. The background service protocol is
unchanged, so 0.2 updates 0.1 in place and existing protected folders keep
working.

### Installing and removing
- **Install.cmd, Uninstall.cmd, Check-ThisPC.cmd**: double-click files that ask
  Windows for administrator permission themselves. No PowerShell typing.
- The installer finds the client's recovery certificate next to Install.cmd,
  checks the PC first, asks at most two plain questions and explains every
  problem with what to do about it.
- New **Check-ThisPC.cmd** readiness check (edition, BitLocker, drive C:,
  free space, administrator accounts). Changes nothing.
- Folder Vault now appears in **Settings > Apps** and can be removed from there.
- The uninstaller lists folders that are still protected and offers to stop,
  or to remove only the program and keep the folders for a later reinstall.
  It now also works when started from Settings, from inside its own folder.

### Locking and unlocking
- A locked folder now shows one item, **"Locked - double-click here to
  unlock"**, instead of looking mysteriously empty.
- New right-click item **Lock with Folder Vault**.
- New Start menu shortcut **Lock all Folder Vault folders**, on **Ctrl+Alt+L**.
- If a folder will not lock because a File Explorer window is showing it,
  Folder Vault closes that window and tries again before asking the person anything.
- Left-clicking the tray icon now opens its menu (before, only right-click did).
  The menu offers Open as well as Lock for unlocked folders, and the icon's
  tooltip says how many folders are unlocked.

### Lighter on the computer
- The tray icon is now a separate, small script using Windows Forms only.
  Windows open in their own short-lived process that ends when they close.
- The tray no longer asks the background service for the folder list every
  3 seconds while the screen is locked. It checks the lock screen every
  10 seconds and talks to the service only when something changes.
- The background service does no session checks at all while every folder is
  locked, and wakes once a minute instead of once a second.
- The session check uses one quick process query instead of a WMI call per
  signed-in user.
- The background service runs at below-normal priority.
- Installer option **-NoTrayIcon** for the lightest set-up.
- Health check and new Windows test **W80** report the memory and processor
  use actually measured.

### Fixes
- The "protect a folder" window could report success when the background
  service was not running, because a message box's result leaked into its
  return value.
- A function parameter called `-Confirm` clashed with PowerShell's own
  `-Confirm` switch. It is now `-AskUser`.

### Documentation
- New: README "which document do I need", USER-GUIDE (rewritten),
  SETUP-GUIDE (replaces ADMIN-GUIDE), FOR-MANAGERS, GLOSSARY, this CHANGELOG.
- The technical documents each start with a plain-English summary.
- British English throughout. Em dashes removed.

### Removed
- `docs/ADMIN-GUIDE.md` (now `docs/SETUP-GUIDE.md`).
- The `-Action Tray` mode of `FolderVault.UI.ps1` (now `FolderVault.Tray.ps1`).

## 0.1.0 (29 October 2026)

First prototype: BitLocker-encrypted VHDX vaults, SYSTEM background service
with named-pipe protocol, user-side protect and unprotect with SHA-256
verification, recovery-key escrow, automatic locking, installer, admin tools,
282 unit tests, security audit and purple team plan.
