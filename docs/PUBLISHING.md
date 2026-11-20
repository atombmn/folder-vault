# Publishing Folder Vault on GitHub

How to put this repository on GitHub, check that nothing private goes with
it, and publish a release with the install zips. About 30 minutes the first
time.

## 1. Before you start

You need:

- a GitHub account;
- **Git for Windows** (<https://gitforwindows.org> or `winget install Git.Git`),
  or GitHub Desktop if you prefer clicking to typing;
- **PowerShell 7** for the checks and the build (`winget install Microsoft.PowerShell`),
  with Pester 6 and PSScriptAnalyzer:

  ```powershell
  Install-Module Pester -RequiredVersion 6.2.0 -Scope CurrentUser -Force -SkipPublisherCheck
  Install-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Scope CurrentUser -Force
  ```

Unzip the repository zip into a working folder, for example
`C:\Code\folder-vault`, and open PowerShell 7 there.

## 2. Keep your identity out of it

**Commits carry a name and an e-mail address**, and both are public. Use
GitHub's private address:

1. On GitHub: **Settings > Emails**, tick **Keep my email addresses private**
   and **Block command line pushes that expose my email**. Copy the address
   shown, which ends in `@users.noreply.github.com`.
2. In the working folder:

   ```powershell
   git init
   git config user.name  "Folder Vault"            # or any name you are happy to show
   git config user.email "12345678+you@users.noreply.github.com"   # the address you copied
   ```

   These settings apply to this repository only.

**Check for private words.** Make a text file **outside** the working folder,
say `C:\Code\private-words.txt`, with one word per line: your name, your
company, its domain, computer names, Windows user names, client names, your
town. Then:

```powershell
pwsh -File tests/tools/Find-FVPrivateWords.ps1 -WordsFile C:\Code\private-words.txt
```

It must say **No private words found.** Fix anything it lists before going on.

**Check for keys.** `.gitignore` already keeps out `*.pfx`, `*.cer` and
`private-words.txt`, but look anyway:

```powershell
Get-ChildItem -Recurse -Include *.pfx, *.cer, *.p12 -File
```

This should list nothing.

## 3. Run the checks

```powershell
pwsh -File tests/tools/Get-FVReferenceAssemblies.ps1      # once; about 21 MB from nuget.org
Invoke-Pester ./tests/unit                                  # all must pass
Invoke-ScriptAnalyzer -Path src, install, admin -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
```

The analyzer lists some known warnings (Windows Forms types and the
certificate provider's `-DeleteKey`); they are explained in
`docs/PUBLICATION-AUDIT.md`. There should be no errors.

## 4. Create the repository on GitHub

1. On GitHub, click **+ > New repository**.
2. Name: `folder-vault`. Description, for example: *Password-protected
   folders for Windows, using BitLocker-encrypted virtual disks and only
   built-in Windows tools (PowerShell 5.1).*
3. Choose **Public**. Do **not** tick "Add a README", ".gitignore" or
   "licence": this repository already has them.
4. Click **Create repository** and copy its address
   (`https://github.com/<your-account>/folder-vault.git`).

## 5. Upload

### Option A: Git command line (recommended)

```powershell
git add .
git status                      # read the list: no .pfx, .cer, dist\ or tests\.refs\
git commit -m "Folder Vault 0.4.0"
git branch -M main
git remote add origin https://github.com/<your-account>/folder-vault.git
git push -u origin main
```

Git will open a browser window to sign in to GitHub the first time.

### Option B: GitHub Desktop

**File > Add local repository**, choose the working folder, accept "create a
repository", check the name and e-mail under **File > Options > Git**, commit,
then **Publish repository** (untick "Keep this code private" if it should be public).

### Option C: the website only

On the new repository page, click **uploading an existing file** and drag
in the **contents** of the working folder. Files and folders whose names
start with a dot (`.github`, `.gitignore`, `.gitattributes`) can be skipped
by some file pickers: drag them in from File Explorer with **View > Show >
Hidden items** switched on, and check they arrived. Option A or B is more
reliable.

## 6. After the first push

1. **Actions** tab: the *Tests* workflow runs by itself. It should finish
   green in a few minutes. Its *folder-vault-build* artefact holds the zips.
2. **Settings > Code security**: switch on **Private vulnerability
   reporting** (SECURITY.md tells people to use it), **Dependabot alerts**
   and **Secret scanning** if offered.
3. **About** (cog on the main page): add the description and topics such as
   `windows`, `powershell`, `bitlocker`, `encryption`, `security`, `vhdx`.
4. Optional: **Settings > Branches**, protect `main` so the tests must pass
   before a change is merged.

## 7. Publish a release

Releases are where people download the install zips.

```powershell
pwsh -File build/Build-Package.ps1
```

This makes `dist\FolderVault-0.4.0-client.zip` and `dist\FolderVault-0.4.0.zip`
and prints two **fingerprints**. Then on GitHub:

1. **Releases > Draft a new release**.
2. **Choose a tag**: type `v0.4.0` and pick **Create new tag on publish**.
3. Title: `Folder Vault 0.4.0 (prototype)`.
4. Notes: paste the 0.4.0 section of `CHANGELOG.md`, then add:

   ```
   Package fingerprints (the installer shows these; they must match):
     FolderVault-0.4.0-client.zip  XXXX XXXX XXXX XXXX
     FolderVault-0.4.0.zip         XXXX XXXX XXXX XXXX

   Prototype: the container code has not yet run end to end on Windows.
   Do not use it for real data. See docs/SPECIFICATION.md, section 8.
   ```

5. Drag both zips into the release, tick **Set as a pre-release**, and
   **Publish release**.

## 8. Later changes

```powershell
# edit, then:
Invoke-Pester ./tests/unit
git add .
git commit -m "Short description of the change"
git push
```

For a new release: raise `$script:FVProductVersion` in
`src/FolderVault.Common.psm1`, add a section to `CHANGELOG.md`, build, tag and
release as in step 7.
