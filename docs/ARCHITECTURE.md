# SecurePWM – architecture notes

This file is for people who want to see how the pieces fit together without reading the whole codebase line by line.

---

## 1. Module map

At a high level:

- `securepwm/crypto.py`
  - scrypt KDF (`derive_vault_key`)
  - HKDF key hierarchy (`derive_subkeys`)
  - AES‑GCM AEAD helpers (`encrypt` / `decrypt`)
  - Entry content helpers (`encrypt_entry_content` / `decrypt_entry_content`)
  - Audit HMAC chain (`compute_audit_mac` / `verify_audit_chain`)
  - Label hashing (`hash_label`)

- `securepwm/vault.py`
  - SQLite schema and PRAGMAs.
  - `Vault` class:
    - `initialize`, `unlock`, `lock`
    - `add_entry`, `get_entry`, `list_entries`, `search`, `search_exact`, `delete_entry`
    - `verify_audit_log`
    - `recover_vault_with_shares`
  - Internal helpers `_derive_keys`, `_audit`, `_require_unlocked`.

- `securepwm/recovery.py`
  - Shamir k‑of‑n wrappers around `shamir-mnemonic`:
    - `generate_recovery_shares`
    - `combine_recovery_shares`
    - `print_recovery_kit`

- `spwm_main.py`
  - Text UI and menu loop.
  - One `cmd_*` function per user action, calling into `Vault` or the recovery helpers.

- `demo.py`, `attack_demo.py`, `test_simple.py`
  - Scripted demonstrations and basic tests for the crypto behavior.

The dependency direction is:

`crypto.py` ← `vault.py` ← (`spwm_main.py`, `demo.py`, `attack_demo.py`, `test_simple.py`)  
`recovery.py` is used by `spwm_main.py`, `demo.py`, `attack_demo.py`, and tests.

---

## 2. Core flows (diagrams)

These are intentionally rough ASCII diagrams; they match what the CLI and the demos actually do.

### 2.1. Vault initialization

```text
User
  |
  | 1) "Initialize vault" (menu)
  v
spwm_main.cmd_init
  |
  |--> Vault(path)
       .initialize(master_password)
           |
           |--> derive_vault_key(password, salt)   [scrypt]
           |--> derive_subkeys(vault_key)          [HKDF]
           |--> write vault_state row
           |--> _audit("VAULT_INIT")
```

### 2.2. Unlock and get an entry

```text
User
  |
  | "Get entry" (menu 5)
  v
spwm_main.cmd_get_entry
  |
  | (if not unlocked) --> Vault.unlock(master_password)
  |                        |
  |                        |--> read vault_state
  |                        |--> derive_vault_key + derive_subkeys
  |
  |--> Vault.get_entry(entry_id)
       |
       |--> SELECT row FROM entries
       |--> unwrap entry_key with content_key  [wrap_entry_key inverse]
       |--> build AD with vault_id, ids, timestamps, metadata
       |--> decrypt_entry_content(entry_key, ...)  [AES‑GCM]
       |--> _audit("ENTRY_GET")
       |--> return secret + metadata
```

### 2.3. Add entry

```text
User
  |
  | "Add entry" (menu 2 or 3)
  v
spwm_main.cmd_add_manual / cmd_add_generated
  |
  |--> Vault.add_entry(secret, username, site_name, ...)
       |
       |--> create_entry_key()
       |--> hash_label(label_key, username/site)
       |--> encrypt_entry_content(entry_key, secret, AD)
       |--> wrap_entry_key(content_key, entry_key, AD)
       |--> INSERT into entries
       |--> _audit("ENTRY_ADD")
```

### 2.4. Recovery and re‑key

```text
User
  |
  | "Create recovery kit" (menu 10)
  v
spwm_main.cmd_recovery_create
  |
  |--> generate_recovery_shares(vault.vault_key, k, n)
  |--> print_recovery_kit(...)

User (later, after forgetting password)
  |
  | "Recover vault" (menu 11)
  v
spwm_main.cmd_recover
  |
  |--> collect >= k Shamir shares
  |--> recovery_key = combine_recovery_shares(shares)
  |--> Vault(vault_path).recover_vault_with_shares(recovery_key, new_pw)
       |
       |--> open DB, read vault_state
       |--> set self.vault_key = recovery_key
       |--> derive_subkeys(self.vault_key)
       |--> verify by decrypting one entry
       |--> decrypt all entries with old keys
       |--> derive_vault_key(new_pw, new_salt)
       |--> derive_subkeys(new_vault_key)
       |--> re‑encrypt all entries with new keys
       |--> update vault_state.kdf_salt
       |--> _audit("VAULT_RECOVERY")
```

---

## 3. Design choices in one place

Some of the choices I made and where they show up:

- **Memory‑hard KDF over PBKDF2**  
  - I used scrypt (not PBKDF2) to better resist GPU/ASIC offline cracking, even in a teaching project.  
  - Code: `derive_vault_key` in `securepwm/crypto.py`.

- **Per‑entry keys + wrapping**  
  - Each entry gets its own key; the vault‑level `content_key` only wraps entry keys.  
  - This limits the damage if one key ever leaks and lets me change wrapping in the future without re‑encrypting contents.  
  - Code: `create_entry_key`, `wrap_entry_key`, `encrypt_entry_content` in `securepwm/crypto.py`.

- **Plaintext metadata but authenticated**  
  - I kept usernames/site names as plaintext in the DB for UX (fuzzy search, nice listing), but I bind them into AEAD AD so any change is detected at decryption time.  
  - Code: `encrypt_entry_content` / `decrypt_entry_content` and `Vault.get_entry`.

- **Audit log as a hash chain, not just “log records”**  
  - Every log entry authenticates the previous MAC; timestamps and payload hashes are included.  
  - That makes basic tampering (edit/delete/reorder) obvious.  
  - Code: `compute_audit_mac`, `verify_audit_chain` in `securepwm/crypto.py`, and `Vault._audit` / `Vault.verify_audit_log`.

- **Shamir over the vault key for recovery**  
  - For this course project I chose the simple route: split the vault key itself into Shamir shares.  
  - On recovery, any `k` shares reconstruct the key, which is then used to decrypt and re‑key everything.  
  - Code: `generate_recovery_shares`, `combine_recovery_shares` in `securepwm/recovery.py`, and `Vault.recover_vault_with_shares` in `securepwm/vault.py`.

If you want to see how these choices play out in tests, `docs/TRACEABILITY.md` links each claim to code and a test case.

