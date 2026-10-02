# Local Password Manager

A simple command-line password manager built in Python as part of my Syntecxhub Cybersecurity internship (Week 1 task).

## What it does
Stores login credentials (site, username, password) encrypted on disk, locked behind a single master password. Supports adding, retrieving, deleting, and searching entries.

## Features
- Master password unlocks the whole vault
- Credentials encrypted at rest using AES (via the `cryptography` library's Fernet implementation)
- Master password is never stored — it's used to derive the encryption key each time
- Add, retrieve, delete, and search credential entries
- Password input is hidden while typing (no plaintext on screen)

## Technologies used
- Python 3
- `cryptography` (PBKDF2HMAC for key derivation, Fernet for AES encryption)
- `json` - for structuring stored data
- `getpass` - for hidden password input
- `base64` - for encoding keys/salt into a storable format

## How it works
The master password is never stored directly. Instead, it's run through PBKDF2 (a key derivation function) along with a random salt to produce the actual encryption key. That key is used with Fernet (which implements AES under the hood) to encrypt and decrypt the stored credentials. The salt is stored alongside the encrypted data so the same key can be re-derived next time you enter the correct master password - if the password is wrong, decryption fails and access is denied.

## How to run
Install the one dependency first:
```bash
pip install cryptography
```
Then run:
```bash
python password_manager.py
```
First run creates a new vault (`vault.json`) and sets your master password. Every run after that asks for the same master password to unlock it.

## Security considerations
- The master password is the single point of failure - if it's weak or lost, the vault is either easily broken into or permanently inaccessible (there's no recovery mechanism here, intentionally, since a backdoor would defeat the purpose).
- PBKDF2 with a high iteration count is used specifically to slow down brute-force attempts against the master password.
- The salt is stored in plaintext alongside the data — this is normal and expected (salts aren't meant to be secret, they just prevent precomputed attacks like rainbow tables).
- This is a learning project, not a production-grade password manager - it hasn't been audited and shouldn't be used to store real, sensitive credentials.

## Limitations
- No password strength checking when adding entries
- No protection against someone with direct file access tampering with `vault.json` (no integrity check beyond decryption failing)
- Single local vault file - no sync, no backup mechanism
- No autofill/browser integration (CLI only)

## Future improvements
- Add password strength validation when creating entries
- Add a password generator for creating strong new passwords
- Add integrity verification (e.g., HMAC) separate from encryption
- Export/import functionality for backups

## Real-world relevance
Encryption at rest and proper key derivation are core concepts behind every real password manager and credential storage system. Weak or missing encryption for stored credentials is a common root cause behind data breaches - building this from scratch makes it easier to recognize the difference between properly protected credential storage and insecure practices (like plaintext storage or weak hashing) when reviewing systems or investigating incidents.
