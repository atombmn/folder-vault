# Security policy

Folder Vault is a **prototype**. Its container code (BitLocker, VHDX) has not
yet been run end to end on Windows, and the live purple team exercise has not
been done. Do not rely on it for real data yet.

## Reporting a vulnerability

Please report security problems privately, not in a public issue: use
**Security > Report a vulnerability** on this repository's GitHub page
(private vulnerability reporting). Include:

- the version (`Get-FVProductVersion`, or the version shown by the health check);
- what you did, what happened, and what you expected;
- whether a standard (non-administrator) user can do it.

You should get a reply within two weeks. Please give a reasonable time to fix
the problem before you publish it.

## Scope

In scope: anything that lets someone without a folder's password read its
files, change them, or stop its owner using them; anything that lets a
standard user gain administrator or SYSTEM rights through Folder Vault; any
way a password could leak (logs, events, memory dumps written by Folder Vault).

Out of scope (documented, accepted risks): a local administrator getting
round the protection; a keylogger planted in the person's own account; copies
made before a folder was protected. See `docs/ARCHITECTURE.md`, section 4.

## What has been reviewed

See `docs/SECURITY-AUDIT.md` (findings A-01 to A-32, all closed) and
`docs/PURPLE-TEAM-PLAN.md` (the attacks still to be run live).
