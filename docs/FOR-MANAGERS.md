# Folder Vault: summary for managers

Version 0.4.5, November 2026.

## The problem

Several people in the office know each other's Windows passwords. Anyone who
signs in as a colleague can open that colleague's files, including salaries,
contracts and client records.

## What Folder Vault does

It puts a separate password on chosen folders. A locked folder looks empty,
even to someone signed in as its owner. Only someone who knows that folder's
password can open it. Staff can protect any folder of their own on their
computer, including folders in OneDrive and on other drives of that computer.

- The files are **encrypted** (scrambled) with BitLocker, the encryption built
  into Windows. Copying the folder to a USB stick does not help a snooper:
  the copy is scrambled too.
- Folders **lock by themselves** when the screen locks, when the person signs
  out, or after four hours.
- A folder can be **shared** with chosen colleagues by telling them its password.
- If someone forgets a password, **only the IT team** can recover the folder, using a
  key the IT team keeps locked away.
- Every wrong password is recorded. After repeated wrong guesses the folder
  refuses all attempts for 15 minutes.

## What it does not do

Folder Vault is a strong lock on certain folders. It does not make the whole
office secure, and four risks remain. Management needs to accept them in
writing, or act on them.

1. **Shared Windows passwords are still dangerous.** Someone who knows a
   colleague's Windows password could install a hidden program in that
   colleague's account to record what they type, and so learn the folder
   password later. Folder Vault cannot stop this from inside the same account.
   *The fix is cheap: give each person their own Windows account and change
   the shared passwords.* We recommend doing this in any case.
2. **An unlocked folder is open to whoever is at that computer.** If someone
   unlocks a folder and walks away without locking the screen, it stays open
   until the screen locks or they return. Folder Vault uses the PC's own
   screen lock settings; IT can set a time when installing if wanted.
3. **Old copies may survive.** Copies made before a folder was protected (old
   email attachments, files on USB sticks, older Windows restore points) are
   not touched by Folder Vault. A folder protected from OneDrive also stays in
   the OneDrive recycle bin for up to 30 days (93 days for work or school
   accounts) unless someone empties it.
4. **Someone who keeps guessing can block a shared folder** for 15 minutes at
   a time. They cannot open it, but they can be a nuisance. Every attempt is
   recorded, so they can be identified.

## What the client needs to do

| Action | Who | Why |
|---|---|---|
| Confirm every PC runs Windows Pro (not Home) | Office manager with the IT team | Folder Vault needs Pro |
| Switch on BitLocker for drive C: (and any other internal drive staff keep protected folders on) on every PC | IT | Stops anyone reading a removed disk |
| Decide whether staff may protect folders outside their own user folder (on by default) | Office manager with the IT team | Such folders become personal; folders several people use should be a shared area |
| Give each person their own Windows account; change shared passwords | Office manager | Removes risk 1 |
| Make sure staff accounts are not administrators | IT | An administrator can get round any protection |
| Train staff on the one-page guide | Office manager | Mostly: lock the screen when you leave the desk |
| Sign off the four risks above | Management | So everyone knows what is and is not covered |

## Effect on the computers

Folder Vault is built from parts already inside Windows. It installs no other
software and needs no internet connection.

It runs as a small background service on each PC, and each signed-in person
gets a small icon near the clock. The background service sleeps whenever every
folder is locked. On the first test computer the service used 96 to 99 MB of
memory and no measurable processor time while idle, which is about the same as
one browser tab. The icon's figures will be measured by test W80.

## Where the project stands

Folder Vault 0.4.5 is a **prototype**. Its logic has been checked with 488 automated
tests and two line-by-line security reviews. The installer, background service
and health check have run on a real Windows computer; the first try found and
fixed four faults there. A second review before deployment (13 November 2026)
found a fault that would have stopped any folder from being protected, and ten
smaller ones; all are fixed. The part that protects, locks and unlocks folders
has **not yet run on Windows**. Before it goes near the client's PCs, the IT team will:

1. run the full test programme on two test computers (Windows 11 Pro and Windows 10 Pro);
2. run a two-day security exercise in which one team attacks it while another watches (a "purple team" exercise);
3. try it with five members of staff who are given only the one-page guide.

Only when all three pass will the IT team propose a pilot on a few of the client's PCs.

## Sign-off

We have read this summary and accept risks 1 to 4, with the actions above.

| | Name | Signature | Date |
|---|---|---|---|
| For the client | | | |
| For the IT team | | | |
