# Folder Vault: setting it up

For the person who installs Folder Vault on the client's computers. Parts 1 to 4
need no programming knowledge: you double-click files and answer simple
questions. Part 5 is reference material for the IT team.

Words in **bold** that you may not know are explained in [GLOSSARY.md](GLOSSARY.md).

---

## Part 1. Before you start (once per client)

You need four things.

1. **Windows Pro on every computer.** Folder Vault works on Windows 10 and 11
   **Pro**, **Enterprise** or **Education**. It does not work on **Home**.
   To check a computer, double-click **Check-ThisPC.cmd** (see Part 2).

2. **BitLocker switched on for drive C:** on every computer. This encrypts the
   whole disk, so nobody can take the disk out and read it elsewhere.
   Control Panel > **BitLocker Drive Encryption** > **Turn on BitLocker**.
   Save the BitLocker recovery key somewhere safe, away from the computer.

3. **Staff use standard accounts, not administrator accounts.** Someone with
   an administrator account can get round any protection on that computer.
   Each computer should have one administrator account for IT, with a password
   only IT knows. Check-ThisPC.cmd lists the administrator accounts.

4. **The client's recovery certificate.** The IT team makes this once per client
   (Part 5.1). It is a file ending in **.cer**. It lets the IT team recover a protected
   folder if someone forgets the password. It is safe to copy onto the client's
   computers. Its partner, the **.pfx** file, is not: that stays locked away with the IT team.

One more thing to agree with the client before installing: the protection is
only as good as their Windows passwords. If staff know each other's Windows
passwords, give each person their own account and change the shared ones.
[FOR-MANAGERS.md](FOR-MANAGERS.md) explains why in plain words.

## Part 2. Check a computer (2 minutes)

Use the **client kit**, `FolderVault-<version>-client.zip`. It holds only what a
client computer needs. (The full package also has the tests and technical
documents; it installs the same way.)

1. Copy the Folder Vault folder to a USB stick, with the client's **.cer** file
   inside it, next to Install.cmd. If you have no USB stick, see
   **Part 2a** instead.
2. On the client's computer, open the USB stick and double-click
   **Check-ThisPC.cmd**.
3. Windows asks "Do you want to allow this app to make changes?" Click **Yes**.
   (You may need to type the IT administrator password.)
4. Read the list:
   - **[OK]**: fine.
   - **[CHECK]**: should be fixed, but does not stop the installation.
   - **[PROBLEM]**: must be fixed before Folder Vault can be installed.
     Each one says what to do.

Nothing is changed on the computer by this check.

## Part 2a. Installing from the computer's own disk (no USB stick)

The installer refuses, or asks before going on, if the Folder Vault folder sits
where staff could change its files: Downloads, the desktop, `C:\Temp`, or any
new folder made directly on drive C:. (Windows lets every signed-in person
change files in a folder made directly on C:, so someone could swap a file
before you run the installer.) Make a folder that only administrators can
change, and unzip Folder Vault into it:

1. Right-click **Start** and choose **Terminal (Admin)** or
   **Windows PowerShell (Admin)**. Click **Yes**.
2. Type these two lines, pressing Enter after each:

   ```
   mkdir C:\FVInstall
   icacls C:\FVInstall /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F"
   ```

   The second line removes every permission the folder inherited and gives
   full control to **Administrators** and **SYSTEM** only. It should end with
   `Successfully processed 1 files`.
3. Still in that window, unzip the release zip file into the new folder. For example,
   if the zip file is in your Downloads folder:

   ```
   Expand-Archive "$env:USERPROFILE\Downloads\FolderVault-0.4.6-client.zip" C:\FVInstall
   ```

4. Copy the client's **.cer** file into `C:\FVInstall\FolderVault-0.4.6-client`,
   next to Install.cmd (File Explorer will ask for administrator permission:
   click **Continue**).
5. Double-click `C:\FVInstall\FolderVault-0.4.6-client\Check-ThisPC.cmd`, then
   **Install.cmd** in the same folder. The installer should now show no
   warning about who could change the folder.
6. When every computer is done, delete `C:\FVInstall` from the same
   administrator window: `Remove-Item C:\FVInstall -Recurse -Force`

To check the folder is right before installing:
`icacls C:\FVInstall` should list only `BUILTIN\Administrators` and
`NT AUTHORITY\SYSTEM`.

## Part 3. Install (about 2 minutes per computer)

1. Double-click **Install.cmd** in the Folder Vault folder.
2. Click **Yes** when Windows asks for permission.
3. The installer first checks that the Folder Vault files are exactly the ones in the
   release. It shows two **fingerprints** (groups of letters and numbers):
   - **Package fingerprint**: compare it with the one in the release notes.
   - **Certificate fingerprint**: compare it with the one the IT team recorded for this
     client: the first 16 characters of the **Thumbprint** that
     New-FVEscrowCertificate.ps1 showed when it made the .cer file.

   If either is different, stop and call the IT team. If the installer says the
   folder **could have been changed by people other than administrators**,
   run it from the IT team's USB stick instead of a copy on the computer.
4. The installer checks the computer again. If drive C: is not encrypted it
   asks whether to carry on. The safer answer is **N**: switch on BitLocker
   first, then run Install.cmd again.
5. It asks whether this computer needs a **shared area** for folders that
   several people open. Press **Enter** for none, or type a folder such as
   `C:\Shared`.
6. Wait for **"Folder Vault ... is installed"**, then press Enter.

That's all. From each person's next sign-in, a **shield icon** appears near
the clock, and right-clicking a folder shows **Protect with Folder Vault...**

Give every member of staff [USER-GUIDE.md](USER-GUIDE.md), printed or as a PDF.

**Updating** to a newer version: run the new Install.cmd. Protected folders
stay protected. They lock during the update and people unlock them again
afterwards.

## Part 4. Remove Folder Vault

The normal way, like any other program:
**Settings > Apps > Installed apps > Folder Vault > Uninstall.**
(Or double-click **Uninstall.cmd** in the Folder Vault folder.)

If folders are still protected, the uninstaller lists them and gives two choices:

- **1. Stop now** (recommended). Each owner opens Folder Vault and uses
  **Remove protection**. Then uninstall again.
- **2. Remove the program only.** The protected folders stay locked and
  encrypted on the computer. They look empty until Folder Vault is installed
  again, and then they come straight back.

The uninstaller never deletes what is inside a protected folder.

---

## Part 5. Reference for IT

### 5.1 Make the client's recovery certificate (once per client, on an IT admin machine)

```powershell
.\admin\New-FVEscrowCertificate.ps1 -ClientName 'Client Name' -OutputDirectory E:\Escrow
```

This makes two files:

| File | Where it goes |
|---|---|
| `FolderVault-Escrow-Client-Name.cer` | Into the Folder Vault folder you install from. Safe to copy. |
| `FolderVault-Escrow-Client-Name.pfx` | **Never** onto a client computer. Encrypted USB in the IT team's safe, plus a second copy in another place. Store its password separately. |

Anyone with the .pfx and its password can open every protected folder of that
client. Treat it like the master key to their office.

### 5.2 Forgotten password

1. On the client's computer, open PowerShell as administrator, go to the
   Folder Vault folder and run `.\admin\Reset-FolderVaultPassword.ps1`. It lists the
   protected folders and shows each one's ID.
2. Copy `C:\ProgramData\FolderVault\Escrow\<ID>.cms` to the IT admin machine that holds
   the .pfx and run:
   `.\admin\Get-FolderVaultRecoveryKey.ps1 -EscrowFile <file> -PfxPath <pfx>`
3. Type the 48-digit recovery key into Reset-FolderVaultPassword.ps1 on the
   client's computer and set a temporary password. Give it to the person face
   to face and ask them to change it.

Folder Vault replaces the recovery key automatically after it is used, so the one
you saw stops working. Every reset is recorded (event 1051) and should match
a support ticket.

### 5.3 Scripted installation (RMM tools, many PCs)

From an elevated Windows PowerShell 5.1 prompt:

```powershell
.\install\Install-FolderVault.ps1 -EscrowCertificate .\client.cer -SharedRoot C:\Shared
```

| Option | Meaning |
|---|---|
| `-EscrowCertificate <file>` | The .cer file. Optional if exactly one .cer sits next to Install.cmd. |
| `-SharedRoot C:\Shared` | Folders under which shared protected folders may be made. |
| `-NoTrayIcon` | No shield icon. Lightest option; folders still lock by themselves. |
| `-InactivityLockMinutes 10` | Optional. Screen locks after this many idle minutes. Left out (or 0), Folder Vault does not touch the screen lock, and removes a screen lock time an earlier Folder Vault installer set (versions before 0.4.5 always set 10 minutes). |
| `-AllowUnencryptedSystemDrive` | Install although C: is not encrypted. Not recommended. |
| `-FolderRule AnyFolder` | Staff may protect any of their own folders on the PC's fixed drives, including OneDrive and folders such as `D:\Accounts` (the default from 0.3.0). |
| `-FolderRule UserFoldersOnly` | Staff may protect only folders inside their own user folder. Left out, an update keeps the current choice. |
| `-AllowWritablePackageFolder` | Install from a folder staff could change. Not recommended: see Part 2a. |

Exit code 0 means success. Removal: `.\install\Uninstall-FolderVault.ps1 [-LeaveVaultsInPlace]`.

### 5.4 Settings

`C:\ProgramData\FolderVault\config.json`. Restart the task
*Task Scheduler > Folder Vault > Folder Vault Broker* after editing.

| Setting | Default | Meaning |
|---|---|---|
| MinPasswordLength | 12 | Shortest folder password allowed (8 to 128) |
| MaxUnlockMinutes | 240 | A folder locks after this long, whatever happens |
| LockOnScreenLock | true | Lock folders when the screen locks. Set to false to keep folders open across a screen lock (they still lock at sign-out, restart and after MaxUnlockMinutes) |
| ForceDismountOnAutoLock | true | Lock even if files are open (unsaved changes are lost) |
| MaxFailedAttempts, LockoutMinutes | 10, 15 | After 10 wrong passwords, wait 15 minutes |
| BackoffStartAfter | 3 | Wrong passwords before waits begin |
| SharedRoots | none | Shared areas |
| AllowUserCreateInShared | true | Staff may protect folders in shared areas |
| LocalWeakWords | (none) | Extra words refused when they make up most of a password: the town, the organisation's name, its products. Example: `["springfield", "acme"]`. Letters and digits only, 3 to 40 characters |
| AllowFoldersOutsideProfile | true | Staff may protect their own folders outside their user folder, on this PC's fixed drives (for example `D:\Accounts`). False = only inside their user folder |
| DefaultVaultSizeGB, MinVaultSizeGB, MaxVaultSizeGB | 5, 1, 500 | Size choices offered |
| VerifyMode | Hash | Hash checks every copied file exactly (safe). Size is faster but weaker. |

### 5.5 Monthly health check

```powershell
.\admin\Get-FolderVaultHealth.ps1          # readable report
.\admin\Get-FolderVaultHealth.ps1 -Json    # for an RMM tool
```

It checks the program files have not been changed, folder permissions, the
background service, drive C: encryption, every protected folder and its
recovery record, old restore points, programs that start at sign-in, how much
memory and processor Folder Vault is using, and recent security events.

**Sign-in programs.** The first run records what starts when each person signs
in. That is the baseline. After that, the check warns only when something new
appears, because a program planted to capture passwords would be exactly that.
When it warns, look up each named program. If they are all expected (the person
installed a new app, say), accept them:

```powershell
.\admin\Get-FolderVaultHealth.ps1 -ResetBaseline
```

Run the first check on a PC you trust is clean, ideally straight after
installing, so the baseline is a good one.

| Event (Windows Logs > Application, source FolderVault) | Action |
|---|---|
| 1011 folder locked out, 1012 attempts refused | Ask the owner; someone may be guessing |
| 1040 protect request refused | Someone tried to protect a folder they are not allowed to |
| 1050, 1060 to 1062 | Someone is probing Folder Vault: investigate |
| 1051 password reset by IT | Must match a ticket |
| 1900 to 1930 | Errors (1930 = the service failed to start): send the files in `C:\ProgramData\FolderVault\Logs` to the IT team |

### 5.6 Which folders staff can protect

From 0.3.0 a person can protect **any folder of their own** on the
computer's own drives:

- anything inside their user folder, such as `Documents\Payroll`,
  `Desktop\Contracts` or `OneDrive\Documents\HR`;
- folders elsewhere on a fixed drive, such as `D:\Accounts` or `C:\Data\HR`
  (only if `AllowFoldersOutsideProfile` is on, which is the default).

These are always refused, and the window says why:

| Refused | Reason shown |
|---|---|
| Windows, Program Files, ProgramData, `$Recycle.Bin`, System Volume Information, Windows.old, any AppData | System folders |
| A whole Documents, Desktop, Downloads, OneDrive or user folder, or a whole shared area | Protect a folder inside it instead |
| Anything in another person's user folder, `C:\Users\Public`, or `C:\Users` itself | Belongs to someone else |
| USB sticks, memory cards, DVDs, network drives | Not this computer's own drive |
| A folder that is or contains a junction or symbolic link | Cannot be protected safely |
| A OneDrive folder with files that are online-only | Make them "Always keep on this device" first |

**Folders outside the user folder** become personal: only the person who
protected them can open them. Before protecting one, the window warns them
about this. If several people use a folder such as `D:\Accounts`, make it (or
its parent) a shared area with `-SharedRoot` instead.

**OneDrive folders** stop syncing once protected. OneDrive removes the folder
from OneDrive online and from the person's other devices, and keeps the old
copies in its recycle bin (30 days for personal accounts, 93 days for work or
school accounts, unless the administrator changed it). The window warns the
person first. The protected copy is then only on this computer, so it needs a
backup (5.7). Removing protection puts the files back, and OneDrive syncs them again.

**Other drives.** A folder protected on drive D: leaves deleted copies of its
files on D:. Check-ThisPC.cmd now lists fixed drives without BitLocker. Turn
BitLocker on for them too, or ask staff to keep protected folders on C:.

### 5.7 Backups

Back up `C:\ProgramData\FolderVault`. The folder files in it are already
encrypted, so the backup is too. Back up the .pfx separately.
Do not back up protected folders through their normal location while they are
unlocked: that would copy the files unencrypted.

### 5.8 Problems

| Symptom | Check |
|---|---|
| Task Scheduler shows Last Run Result 0x800710E0 ("The operator or administrator has refused the request") | Normal while the service is running: a second copy was refused, as intended. Check that the task's Status is **Running**, or run the health check |
| "The background service is not running" | Look in `C:\ProgramData\FolderVault\Logs\broker-startup.log`: if the service failed to start, the reason is there. Also Task Scheduler > Folder Vault > Folder Vault Broker, and `broker.log`. Then restart the PC |
| "Could not confirm it is talking to the genuine background service" | Treat it as an attack until shown otherwise. Restart, run the health check, look for unknown programs |
| A folder shows "Needs IT" | Its encrypted file is missing or damaged. Restore it from backup, then reset the password |
| A folder named `...foldervault-original-...` appeared | A file changed while the folder was being protected, so Folder Vault kept the original. Copy any newer file into the protected folder, then delete that one |
| Ctrl+Alt+L does nothing | Windows picks up new shortcut keys at sign-in. Sign out and back in |
| "Some files in that folder are only in OneDrive online" | In File Explorer, right-click the folder > **Always keep on this device**, wait for the green ticks, try again |
| Protecting fails with "The copy could not be verified" | From 0.4.5 the message names the items that did not match and what the copy tool reported, and the full list is saved to `%LOCALAPPDATA%\FolderVault\last-copy-check.txt` (names and sizes, no file contents). Send that file to whoever supports Folder Vault. Nothing was changed: the original folder is as it was. |
| Protecting fails with "Access to the path ...\Mounts\... is denied" | Run `admin\Test-FVVaultAccess.ps1`: `-Setup` as administrator, `-Check` as the person in ordinary PowerShell, then `-Cleanup` as administrator. Send the file it saves on the desktop to your support contact |
| "That folder cannot be protected" for a folder the person owns | Read the reason in the window, then the table in 5.6. A folder on another drive also needs `AllowFoldersOutsideProfile` on |
