# Folder Vault: words explained

| Word | What it means here |
|---|---|
| **Administrator account** | A Windows account that can change anything on the computer. Staff should not use one day to day. |
| **Background service** | The part of Folder Vault that runs out of sight with full rights. It does the locking and unlocking, and nothing else. Its technical name in the files is the *broker*. |
| **BitLocker** | Encryption built into Windows Pro. Folder Vault uses it for each protected folder. Switch it on for drive C: as well. |
| **Encrypted** | Scrambled so that it can only be read with the right password or key. |
| **Escrow, recovery certificate (.cer), recovery key (.pfx)** | How a forgotten password is rescued. Each protected folder has a long recovery number. It is stored on the PC scrambled, and only the IT team's private key (the .pfx file, kept locked away at the IT team) can unscramble it. The .cer is the public half, safe to copy onto PCs. |
| **Fingerprint** | A short code (four groups of four letters and numbers) worked out from the files. If even one character in a file changes, the fingerprint changes. The installer shows it so you can compare it with the IT team's. |
| **Client kit** | The zip file to install from on the client's computers. It has only what those computers need. |
| **Online-only file** | A OneDrive file whose contents are kept only in OneDrive online, not on the computer. File Explorer shows it with a cloud symbol. **Always keep on this device** downloads it. |
| **OneDrive** | Microsoft's storage that copies (syncs) a folder on the computer to the internet and to the person's other devices. |
| **Locked** | The folder looks empty apart from the "double-click here to unlock" shortcut. The files are encrypted and cannot be opened. |
| **Unlocked** | The folder shows its files as normal, for the person who unlocked it. |
| **Protect** | Turn an ordinary folder into a password-protected one. The files are moved into an encrypted container, checked one by one, and only then removed from the unprotected place. |
| **Remove protection** | Turn it back into an ordinary folder. |
| **Shared area** | A folder such as `C:\Shared` where folders can be protected for several people on the same PC. |
| **Standard account** | An ordinary Windows account that cannot change system settings. All staff should have one of these. |
| **Tray icon, shield icon** | The small Folder Vault shield near the clock. Click it to see your folders. |
| **Vault** | Another word for a protected folder. The encrypted container behind it is a `.vhdx` file in `C:\ProgramData\FolderVault\Vaults`. |
| **Windows Home / Pro** | Editions of Windows. Folder Vault needs Pro, Enterprise or Education. |
| **Purple team exercise** | A security test where one team attacks the system while another watches and checks it was noticed. |
