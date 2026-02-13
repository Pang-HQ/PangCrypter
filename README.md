# PangCrypter

PangCrypter is an encrypted text editor for `.enc` files. It combines authenticated encryption, optional USB-bound key material, and a desktop UI for editing encrypted notes.

<details>
<summary><strong>Table of Contents</strong></summary>

- [General Information](#general-information)
- [Project Highlights](#project-highlights)
- [Platform Support](#platform-support)
- [Using PangCrypter](#using-pangcrypter)
  - [Install (recommended: GitHub Releases)](#install-recommended-github-releases)
  - [Install (from source)](#install-from-source)
  - [Encryption modes](#encryption-modes)
  - [Auto-updates](#auto-updates)
  - [Manual update verification (step-by-step)](#manual-update-verification-step-by-step)
- [Security Notes](#security-notes)
  - [What this protects against](#what-this-protects-against)
  - [What this does NOT protect against](#what-this-does-not-protect-against)
- [File Format (v1)](#file-format-v1)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

</details>

## General Information

- Website: https://www.panghq.com
- Source code: https://github.com/Pang-HQ/PangCrypter
- Issue tracker: https://github.com/Pang-HQ/PangCrypter/issues

## Project Highlights

- XChaCha20-Poly1305 authenticated encryption
- Three encryption modes: password-only, USB-only, password+USB
- File header includes version, mode, content mode, salt, UUID, nonce
- Update verification with SHA-256 and minisign
- Backup/rollback logic during update installation

## Platform Support

- Windows: Supported
- Linux: Supported
- macOS: Supported

Platform behavior can vary by filesystem and keychain availability.

## Using PangCrypter

### Install (recommended: GitHub Releases)

For normal use, install from the latest release artifacts:

1. Go to: https://github.com/Pang-HQ/PangCrypter/releases
2. Download the latest `PangCrypter.zip`
3. Extract and run `PangCrypter.exe`

### Install (from source)

Source install is mainly for development/testing.

```bash
git clone https://github.com/Pang-HQ/PangCrypter.git
cd PangCrypter
pip install -r requirements.txt
```

Optional editable install:

```bash
pip install -e .
```

### Encryption modes

- **Password only**: key derived from password
- **USB key only**: key material bound to selected drive
- **Password + USB key**: combines both sources

### Auto-updates

- Open **Help → Check for Updates**
- Updater checks release metadata, downloads ZIP, verifies SHA-256 and minisign, and installs with rollback support

### Session caching and memory guard

- **Session caching** is enabled by default and keeps secrets only for an active session so autosave and panic snapshots can work.
- Re-auth can be configured in Preferences to trigger after focus loss (1–5 minutes).
- **Memory guard** is available on Windows only and supports:
  - Off
  - Normal (recommended): suspicious unknown/unsigned readers
  - Ultra aggressive: any non-whitelisted reader with process VM access
- If memory guard detects suspicious access, PangCrypter attempts to write `filename.enc.panic.enc`, clears plaintext/secrets, and prompts you to continue, whitelist, or exit.
- Panic snapshots are overwritten on each incident; automatic deletion after successful restore is configurable.

### Manual update verification (step-by-step)

1. Download release artifacts:
   - `PangCrypter.zip`
   - `PangCrypter.zip.sha256`
   - `PangCrypter.zip.minisig`
2. Get the trusted minisign public key from a trusted channel.
3. Verify SHA-256 digest:
   - **Windows (PowerShell):**
     ```powershell
     Get-FileHash .\PangCrypter.zip -Algorithm SHA256
     ```
   - **Linux/macOS:**
     ```bash
     sha256sum PangCrypter.zip
     ```
   Confirm it matches `PangCrypter.zip.sha256`.
4. Verify minisign signature:
   ```bash
   minisign -Vm PangCrypter.zip -x PangCrypter.zip.minisig -P "<TRUSTED_PUBLIC_KEY>"
   ```
   (Or use `-p minisign.pub` if the public key is in a file.)
5. Install only when both checks succeed.

## Security Notes

### What this protects against

- Offline disclosure when an attacker only has the encrypted `.enc` file
- Undetected ciphertext/header tampering (authenticated encryption)
- Unsigned/modified update payloads when verification is configured correctly
- Accidental local exposure of USB key files via basic filesystem hardening

### What this does NOT protect against

- Malware/keyloggers on a running host
- Full system compromise (admin/root-level attackers)
- Credential loss (forgotten password and lost USB material)
- Operational mistakes such as bypassing signature verification

## File Format (v1)

```
settings (16 bytes):
  - bytes 0-1: version (uint16)
  - byte 2   : encryption mode
  - byte 3   : content mode (0x00 plaintext, 0x01 HTML)
  - bytes 4-15: reserved
salt (16 bytes, zeroed for key-only mode)
uuid (16 bytes)
nonce (24 bytes)
ciphertext (variable)
```

## Development

Run local checks:

```bash
ruff check pangcrypter tests
pytest -q
bandit -r pangcrypter
pip-audit -r requirements.txt
```

Developer security and release process:

- `docs/DEVELOPER_SECURITY_RELEASE.md`

## Contributing

Contributions are welcome. Please open an issue before large changes.

## License

MIT License. See `LICENSE`.

## Contact

- https://www.panghq.com/contact
