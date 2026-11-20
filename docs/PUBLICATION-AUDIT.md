# Publication audit (version 0.4.0)

How the working prototype (0.3.0, built for one office under an internal
working name) became this public repository, and what was checked after
each step. Done on 21 November 2026, on Linux with PowerShell 7.4.6,
Pester 6.2.0 and PSScriptAnalyzer 1.25.0.

**Rule followed throughout:** after every step that changed code, the unit
tests were run again before the next step. A step that broke a test was
fixed before going on.

## Step 0. Starting point

| Check | Result |
|---|---|
| Unit tests on the 0.3.0 source | 445 passed, 1 skipped (Windows only) |
| What had run on real Windows | Installer, service start-up, pipe owner check, health check, folder rules (one Windows 11 test PC). Not the container code |

## Step 1. Copy and rename

The source was copied (without build output) and renamed by script, in this
order, so that longer names were replaced before shorter ones:

| Rule | Replacements |
|---|---|
| Product name in text | 240 |
| Product name in identifiers, paths, registry keys, pipe and task names | 626 |
| Lower-case product name | 15 |
| Two-letter command prefix changed to `FV` (for example `Get-FVPathScope`) | 1,708 |
| Temporary folder prefixes in tests | 15 |
| Test vault names, test account names, `.cmd` variables | 15 |
| File names | 20 files |

**Check:** all unit tests passed straight after the rename (444 passed, 2
skipped: one Windows-only, one that needs a built package). Behaviour was
unchanged.

## Step 2. Remove the organisation's role

The organisation that installed and supported the system was mentioned
about 80 times ("call ...", "...'s safe", "... built the package"). These
became **the IT team** (who supports it) or **the release** (where the files
come from). Every changed line was then read in context, and those that read
awkwardly were reworded by hand, for example "unzip the release zip
file" rather than a possessive.

## Step 3. Remove personal and identifying details

| What | Where it was | What was done |
|---|---|---|
| Organisation name | 10 file headers, certificate subject, service description, Settings > Apps publisher, 6 document headers, sign-off table | Removed, or replaced with "Folder Vault" / "the IT team" |
| Organisation web address | Settings > Apps "about" link | Link removed |
| Test PC name | 16 places in documents and tests | "the first test PC" |
| Windows user name | 2 places in a test (a real OneDrive path) | Replaced with `jsmith` |
| Admin test account name (contained the old initials) | Tests and purple team plan | `itadmin` |
| Regional words in the weak-password list | 14 words in the code, 1 test | Removed from code; new `LocalWeakWords` setting so each deployment adds its own (step 4) |
| Regional-language file names in tests | 2 tests | Replaced with accented French names (still tests non-ASCII names) |
| A variable named with the old initials | Health check | Renamed |

**Two independent scans** were then run over every text file:

1. a text search for each private word; and
2. a second scan that split every file into words and compared each word
   (case-insensitive) with the private list.

The second scan found **4 items the first had missed**: the web address in
the uninstall entry, the variable name, a file name in the Windows test
programme, and one test PC name in a table. All were fixed and both scans
then found nothing.

**Check:** unit tests passed.

## Step 4. Weak-password words become a setting

Removing regional words would have weakened the password check for the
office it was built for, so they became a setting instead:

* `LocalWeakWords` in `config.json`: letters and digits, 3 to 40 characters,
  at most 200, stored in lower case; bad entries are ignored with a warning.
* The background service enforces them, and sends them to the window so
  its hints agree with the service.
* 6 new unit tests, including one through the service's `Create` request.

**Check:** unit tests passed (one test first failed because it expected the
wrong refusal code; the test was corrected to the code the service really
returns, `PasswordPolicy`).

## Step 5. Repository files and documents

Added: `README.md` (rewritten for GitHub), `LICENSE` (MIT),
`SECURITY.md`, `CONTRIBUTING.md`, `.gitignore`, `.gitattributes`,
`.github/workflows/tests.yml`, `docs/SPECIFICATION.md`,
`docs/PUBLISHING.md`, this file. Updated: `CHANGELOG.md` (0.4.0),
`docs/PROJECT-RECORD.md`, `docs/SECURITY-AUDIT.md` (section 9),
`docs/SETUP-GUIDE.md` (the new setting), `docs/FOR-MANAGERS.md`.

`docs/SPECIFICATION.md` was written from the original brief and every later
request, and each requirement names the test that proves it. Every claim in
it was checked against the code (defaults, key length RSA-3072, refusal codes).

## Step 6. Checks that stay with the repository

| New check | What it does | Proved by |
|---|---|---|
| `Publication.Tests.ps1` | No e-mail addresses; links only to Microsoft, NuGet, GitHub and standards sites; only made-up user names in example paths | Runs on every push |
| `tests/tools/Find-FVPrivateWords.ps1` | Finds your own private words, from a list kept **outside** git (`private-words.txt` is in `.gitignore`) | A planted file with two private words: both found |
| `NetFrameworkApi.Tests.ps1` | Every .NET type and method used exists in .NET Framework 4.8 (Windows PowerShell 5.1) | A planted call to a method that does not exist: caught |
| `tests/tools/Get-FVReferenceAssemblies.ps1` | Downloads the two NuGet packages that check needs | Run on a clean copy: both downloaded |

The private word list itself is deliberately **not** in the repository:
even as hashes, short words such as place names can be guessed.

## Step 7. File format

Windows PowerShell 5.1 reads a script without a byte order mark as ANSI,
and `cmd.exe` needs Windows line endings:

* 26 PowerShell files were given a UTF-8 byte order mark;
* 38 scripts and `.cmd` files were saved with Windows (CRLF) line endings;
* `.gitattributes` keeps them that way on every checkout;
* Markdown and YAML files are plain UTF-8 with Unix line endings.

## Step 8. Final verification

| Check | Result |
|---|---|
| Unit tests, clean copy without build output | **455 passed**, 0 failed, 2 skipped (one needs Windows, one needs a built package) |
| Unit tests in a fresh `git clone` (Windows line endings) | 455 passed, 0 failed, 2 skipped |
| GitHub Actions workflow, every step run by hand on a clean copy | Reference download, tests (exit code 0, results file written), build: all succeeded |
| PSScriptAnalyzer, shipped code, Windows PowerShell 5.1 profiles | **0 errors.** 21 known warnings: 14 Windows Forms types loaded with `Add-Type` at run time; 3 uses of the certificate provider's `-DeleteKey`; 4 empty `catch` blocks in the Windows test programme's clean-up |
| .NET Framework 4.8 API check | No problems apart from 2 known false positives (a variable enum name; `New-Object byte[]`) |
| `git add` on a copy with a `.pfx` file, `dist\` and `tests\.refs\` present | None of them staged |
| Release build | `FolderVault-0.4.0.zip` and `FolderVault-0.4.0-client.zip`; downloaded reference assemblies excluded |
| Both zips unpacked and checked with the installer's own package check | Both pass (14 files checked each) |
| Private word scan of the repository and of both unpacked zips | Nothing found |
| Em dashes in documents and messages | None (two tests contain one on purpose, to check messages have none) |

## Not done, and why

* **Nothing in 0.4.0 has run on Windows.** The rename touched every file, so
  the parts that had run on the test PC (installer, service, health check)
  should be tried again on a test computer before anything else.
* **GitHub Actions has not run on GitHub itself.** Each step was run by hand
  with the same commands; the first push will run it for real.
* **Earlier test installs** used the old name. Folder Vault 0.4.0 installs
  alongside them, not over them: remove an earlier install with its own
  `Uninstall.cmd` first.
