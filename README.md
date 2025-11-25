# SecurePWM – Zero‑Knowledge Password Manager (course project)

SecurePWM is a small, inspectable password manager wrote for cryptography course.  
All encryption happens on the client side, and the code is meant to be readable enough that you can trace every step: key derivation, encryption, audit logging, and recovery.

---

## 1. What this project does

- Stores passwords in a local SQLite database, never in plaintext on disk.
- Derives a vault key from your master password using `scrypt` (memory‑hard KDF).
- Uses AES‑256‑GCM with Associated Data (AD) so that metadata tampering breaks decryption.
- Keeps a tamper‑evident audit log using an HMAC chain.
- Supports Shamir `k‑of‑n` recovery shares over a recovery key.

If you want the deeper security rationale (threat model, attack scenarios, etc.), see `SECURITY_OVERVIEW.md` and the docs under `docs/`.

---

## 2. Repository layout (high level)

- `securepwm/crypto.py` – all cryptographic building blocks (scrypt, HKDF, AES‑GCM, HMAC chain, label hashing).
- `securepwm/vault.py` – SQLite schema and high‑level vault operations (add/get/search/delete/verify audit log).
- `securepwm/recovery.py` – Shamir `k‑of‑n` recovery utilities using `shamir-mnemonic`.
- `spwm_main.py` – interactive text UI (what a normal user would run).
- `demo.py` – scripted “guided tour” of the CLI, with explanations printed along the way.
- `attack_demo.py` – scripted attack scenarios (wrong password, tampering, etc.) to show defenses in action.
- `test_simple.py` – small test script that checks the main crypto properties.
- `SECURITY_OVERVIEW.md` – short write‑up explaining design choices and how they relate to security.
- `requirements.txt` – minimal Python dependencies.

---

## 3. Requirements

The project is pure Python and should run on:

- Windows (10/11)
- Linux
- WSL (Windows Subsystem for Linux)

You will need:

- Python 3.9 or newer (3.10+ recommended)
- `pip` to install the dependencies listed in `requirements.txt`

SQLite is used via the Python standard library (`sqlite3`), so you do not need to install it separately.

To check your Python version:

```bash
python --version
```

On some Linux/WSL systems the command is `python3` instead of `python`:

```bash
python3 --version
```

In the commands below, use `python` or `python3` depending on what works on your machine.

For dependencies, I kept things deliberately small: the core project only needs two Python packages for normal use. There is a single crypto library (`cryptography`) that powers all the encryption/KDF logic, and one extra library (`shamir-mnemonic`) that is only used for the Shamir recovery feature. Anything else you see (`pytest` for tests, `pyperclip` for clipboard in the CLI) is optional and not required to run the password manager itself.

---

## 4. Setup and installation

The commands are slightly different on Windows and Linux/WSL, so I’ll write both.

### 4.1. Get the code

Either clone the repository or download/unzip it so that you have a folder like:

```text
CryptoLab-SecurePWM/
    securepwm/
    spwm_main.py
    demo.py
    attack_demo.py
    test_simple.py
    requirements.txt
    README.md
```

Open a terminal in this folder.

### 4.2. Create a virtual environment (recommended)

#### Windows (PowerShell or Command Prompt)

```powershell
cd path\to\CryptoLab-SecurePWM
python -m venv .venv
.venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

#### Linux / WSL

```bash
cd path/to/CryptoLab-SecurePWM
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Dependencies installed from `requirements.txt`:

- `cryptography` – for scrypt, AES‑GCM, HKDF.
- `shamir-mnemonic` – for Shamir secret sharing (recovery kit).
- `pytest` – only used if you want to run tests with `pytest`; not required for normal usage.

`pyperclip` is optional; if you install it (`pip install pyperclip`), the “Quick copy” feature will copy passwords to your clipboard instead of just printing them.

---

## 5. Running the interactive password manager

Once the virtual environment is activated and dependencies are installed, you can start the main CLI.

From the project root:

```bash
python spwm_main.py
```

Typical first‑time flow:

1. Choose `1) Initialize vault`.
2. Accept the default vault path or type a custom path.
3. Enter a strong master password (this is the only thing you need to remember).
4. After initialization, use:
   - `2) Add entry (manual)` to store an existing password.
   - `3) Add entry (generated)` to let the tool generate a strong password.
   - `4) List entries` to see what is stored (only metadata, not the secret).
   - `5) Get entry` to decrypt and view details.
   - `6) Quick copy` to put a password on the clipboard (if `pyperclip` is installed).
   - `7) Search entries` for basic fuzzy searching over username/site/url/category.
   - `8) Delete entry` (soft delete by default, with an option for hard delete).
   - `9) Verify audit log` to check that the tamper‑evident log is intact.
   - `10) Create recovery kit` to generate Shamir shares for the recovery key.
   - `12) Lock vault` to wipe keys from memory when you are done.

You can exit from the main menu with `0) Exit`.

---

## 6. Scripted demos (no typing required)

If you prefer to just run a demonstration without clicking through the menu, there are two ready‑made scripts.

### 6.1. Guided CLI journey

```bash
python demo.py
```

This script:

- Creates a temporary vault file.
- Shows a snapshot of the interactive menu.
- Simulates adding entries, listing, searching, decrypting, quick copy, deleting, audit verification, and recovery shares.
- After each step, prints a “[Behind the scenes] …” explanation that points to the relevant functions in `securepwm/vault.py` and `securepwm/crypto.py`.

The temporary vault is deleted at the end of the run.

### 6.2. Attack demonstration

```bash
python attack_demo.py
```

This script also uses a temporary vault and walks through a few attack attempts:

1. Unlocking with the wrong master password (decryption fails).
2. Editing metadata directly in SQLite (AD binding breaks decryption).
3. Flipping bits in the ciphertext (AES‑GCM detects tampering).
4. Corrupting the audit log MAC (HMAC chain verification fails).
5. Trying to reconstruct the recovery key with too few Shamir shares.

Again, the temporary file is cleaned up at the end, so this will not touch any real data.

---

## 7. Running tests

There is a small test script that checks the main crypto properties and some end‑to‑end behavior.

From the project root:

```bash
python test_simple.py
```

This covers:

- scrypt key derivation behavior.
- AEAD with Associated Data (metadata binding).
- Envelope encryption (per‑entry keys, wrapping/unwrapping).
- Audit chain integrity verification.
- Shamir recovery combinations (`k‑of‑n`).

If you prefer using `pytest` and have it installed (it is listed in `requirements.txt`), you can also run:

```bash
pytest -q
```

---

## 8. Security notes (high‑level)

Very briefly, the design is meant to defend against:

- Someone copying the vault database file and trying to brute‑force passwords offline.
- Tampering with ciphertext or metadata inside the database.
- Editing or reordering the audit log.
- Trying to reconstruct the recovery key with fewer than `k` shares.

And it explicitly does **not** try to defend against:

- Keyloggers on the host.
- Someone with physical access while the vault is unlocked.
- Clipboard sniffing once a password has been copied.
- Adversary deletes the database file or entries in the database

For more details, including which fields are in the AEAD Associated Data and exactly what the audit MAC covers, see `SECURITY_OVERVIEW.md`.

---
