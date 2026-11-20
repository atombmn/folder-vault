# Folder Vault: project record

Everything done on Folder Vault from the first idea to version 0.4.0, in one
place. Last updated 21 November 2026.

Folder Vault was built for one small office, then published as an open
project. Names of the people, organisations and computers involved have been
left out; "the IT team" is whoever installs and supports it.

For what each version changed in detail, see [CHANGELOG.md](../CHANGELOG.md).
For the security findings, see [SECURITY-AUDIT.md](SECURITY-AUDIT.md).
For the requirements, see [SPECIFICATION.md](SPECIFICATION.md).

---

## 1. The problem

An office runs a Windows workgroup of 15 computers. Most non-office staff know
the office users' Windows passwords and sign in to read sensitive files. The
office asked for folders that need a separate password, which can be shared
with chosen people, and which staff can protect and unprotect themselves
without IT. The system had to be security tested, purple team audited and
very easy to use.

Constraints given at the start:

- Windows 10 and 11 Pro machines in a workgroup (no domain).
- Some Windows 10 machines were said not to have BitLocker. Folder Vault needs
  BitLocker, so those machines must be checked with Check-ThisPC.cmd; Home
  editions cannot run it.
- No compiler available to the IT team: everything had to be built, tested and audited
  without one. Folder Vault is therefore written in Windows PowerShell 5.1, which
  every Windows 10 and 11 PC already has.

## 2. The design chosen

Several approaches were brainstormed. The one built ("Option B"):

- Each protected folder's files live in an **encrypted container**: a VHDX
  virtual disk encrypted with BitLocker (XTS-AES-256), with its own password.
- A small **background service** runs as SYSTEM and does only the privileged
  work: create, attach, unlock, lock and delete containers. It listens on a
  named pipe and checks who is calling from Windows itself.
- Everything that touches the person's files (copying, verifying, linking) is
  done **in the person's own session, with their own rights**. The service
  never opens a folder a person names, which removes a whole class of
  privilege-escalation attacks.
- The original folder is replaced by a **junction** to the container, so it
  stays in the same place with the same name. Locked, it shows only
  "Locked - double-click here to unlock".
- Folders **lock by themselves** on screen lock, sign-out, and after a
  maximum time (4 hours by default).
- Each container's **recovery key** is encrypted to the IT team's certificate (escrow)
  before encryption starts. Only the IT team, holding the private key (.pfx), can
  recover a forgotten password.
- Wrong passwords are slowed down after 3 attempts and locked out at 10.

Details: [ARCHITECTURE.md](ARCHITECTURE.md).

## 3. Timeline

| Date (2026) | Version | What happened |
|---|---|---|
| 29 Oct | 0.1.0 | First prototype: containers, background service, protect and unprotect with SHA-256 verification, escrow, automatic locking, installer, admin tools. 282 unit tests, first security audit (A-01 to A-14), purple team plan (P-01 to P-18). |
| 12 Nov | 0.2.0 | Easier and lighter. Double-click Install.cmd, Uninstall.cmd and Check-ThisPC.cmd; Settings > Apps entry; "Lock with Folder Vault" menu item and Ctrl+Alt+L; a lighter tray icon; the service sleeps while everything is locked. All documents rewritten for non-technical readers. |
| 12 Nov | 0.2.1 | **First Windows run, on a test PC.** The service would not start: `$PSScriptRoot` is empty in a `param()` default under Windows PowerShell 5.1. Fixed; start-up failures now logged. |
| 13 Nov | 0.2.2 | Health check crashed on `.Count` of nothing (5.1 strict mode). Fixed; a scanner now checks every `.Count`. |
| 13 Nov | 0.2.3 | Health check false alarm on read permissions; sign-in programs compared with a baseline instead of warning every time. |
| 13 Nov | 0.2.4 | Health check crashed on an ordered table with number keys. Fixed; the whole health check now runs in the tests. **All checks passed on the first test PC.** |
| 13 Nov | 0.2.5 | **Pre-deployment readiness audit** (purple team readiness review, not a live exercise). 11 findings fixed (A-20 to A-30), including a critical one: the disk safety check used a property Windows leaves empty for virtual disks, so every protection would have failed. Installer now checks its own files and shows fingerprints. **Installed on the first test PC: all checks passed, 99 MB, 0.00 % CPU idle.** |
| 20 Nov | 0.3.0 | Protect **any of your own folders**: OneDrive folders (refused before, as seen on the first test PC) and folders on the PC's other drives. Client install kit. `C:\FVInstall` steps in the setup guide. Review findings A-31 and A-32 fixed before release. |
| 21 Nov | 0.4.0 | **Published as Folder Vault.** Renamed throughout; personal and organisation details removed; regional weak-password words moved into a setting (`LocalWeakWords`); specification written; GitHub files added (licence, security policy, automatic tests); publication audit (PUBLICATION-AUDIT.md). |

## 4. What has been verified, and how

| Part | On a real Windows PC (the first test PC, Windows 11 Enterprise) | In code (unit tests on PowerShell 7) | Still needs a Windows test computer |
|---|---|---|---|
| Installer, package fingerprints, readiness check | Yes (0.2.5) | Yes | |
| Background service start-up, pipe owner check | Yes | Yes | |
| Health check, memory and CPU figures | Yes: 96 to 99 MB, 0.00 % idle | Yes (whole script) | |
| Folder rules (which folders may be protected) | The refusal of a OneDrive folder in 0.2.5 was seen | Yes, 0.3.0 rules | W13, W15 |
| Creating, unlocking, locking containers (BitLocker, VHDX) | **No** | Yes, with Windows simulated | W10 to W26 |
| Copying, verifying, linking, restoring files | **No** | Yes, on a real file system | W10, W21, W60 |
| OneDrive folders | **No** | Yes, with cloud files simulated | W14 |
| Window, tray icon, Explorer menu | **No** | Partly (API checks) | Manual test |
| Automatic locking on screen lock, sign-out | **No** | Yes (logic) | W41 to W43 |
| Uninstaller, password recovery | **No** | Partly | W51, manual |

Other checks run on every release: PSScriptAnalyzer with the Windows
PowerShell 5.1 profiles; every .NET type and method checked against the .NET
Framework 4.8 reference assemblies; static rules for the Windows PowerShell
5.1 faults found so far; planted-defect (mutation) checks on each fix.

Unit tests: 282 (0.1.0) > 336 (0.2.1) > 364 (0.2.3) > 371 (0.2.4) >
407 (0.2.5) > 445 (0.3.0) > 455 (0.4.0), plus 1 that runs only on Windows.

## 5. Security work

- First audit (0.1) and the 0.2 review: A-01 to A-15, all closed. See SECURITY-AUDIT.md sections 1 to 6.
- Faults found on the first real PC: A-16 to A-19 (0.2.1 to 0.2.4).
- Readiness audit (13 Nov): A-20 to A-30, all fixed in 0.2.5 (section 7).
- 0.3.0 review (20 Nov): A-31, A-32, fixed before release (section 8).
- Purple team plan: P-01 to P-20, with the Windows test that covers each.
  The live exercise has **not** been run yet.

Risks the client must accept in writing (FOR-MANAGERS.md): shared Windows
passwords still allow a planted keylogger; an unlocked folder is open to
whoever is at the PC; old copies (including OneDrive's recycle bin) survive;
repeated wrong guesses can block a shared folder for 15 minutes.

## 6. Lessons from this project

1. **Windows PowerShell 5.1 is not PowerShell 7.** Every fault found on the
   real PC was a 5.1 difference the tests on PowerShell 7 could not see:
   `$PSScriptRoot` in `param()`, `.Count` on nothing under strict mode,
   ordered tables with number keys, program error output stopping a script,
   hex numbers turning negative. Each now has a static rule.
2. **Fakes must match Windows, not the code.** The critical A-20 slipped
   through because the test's fake disk had a property that real virtual
   disks do not. Behaviour is now checked against Microsoft's documentation.
3. **Run the whole script in tests,** not only its functions: the health
   check crashed three times in code no test had run.
4. **Plant a defect to prove a test works.** Every fix since 0.2.5 has been
   undone once to confirm its test fails.
5. **Get it onto a real PC early.** The first runs on the first test PC found four
   faults that no review or test had found.

## 7. Files

| File | What it is |
|---|---|
| `FolderVault-<version>-client.zip` | Install kit for the client's computers (made by `build/Build-Package.ps1`) |
| `FolderVault-<version>.zip` | Full package: code, tests, technical documents, build script |
| `docs/SPECIFICATION.md` | What Folder Vault must do, and which test proves each requirement |
| `docs/SETUP-GUIDE.md` | How to check, install, update and remove; settings; recovery |
| `docs/USER-GUIDE.md` | The guide for staff |
| `docs/FOR-MANAGERS.md` | Plain summary, risks and sign-off sheet |
| `tests/windows/Invoke-FolderVaultIntegrationTests.ps1` | The Windows test programme (W01 to W80) |

## 8. What happens next

1. On a **Windows 11 Pro test VM**, then a **Windows 10 Pro test VM** (never a
   client PC, and not a PC used for everyday work): install the client kit and run the Windows test
   programme. About 20 minutes each.
2. On the test VM, by hand: protect a throwaway folder with the right-click
   menu, unlock it, lock it with Win+L, remove protection. Repeat with a
   OneDrive folder and a folder on another drive.
3. Run the two-day live purple team exercise (P-01 to P-20).
4. Five members of staff try it with only the user guide.
5. The client signs off the risks; then a pilot on two or three client PCs.

Until steps 1 to 3 pass, Folder Vault must not be installed on the client's computers.
