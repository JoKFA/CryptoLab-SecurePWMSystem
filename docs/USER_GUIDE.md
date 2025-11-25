# SecurePWM – user guide

This is the “how do I actually use this thing?” document. It focuses on the CLI and gives just enough internals so you can connect what you see on screen to what happens in the code.

---

## 1. First‑time setup

### 1.1. Install and run

From the project root:

```bash
python spwm_main.py
```

On some systems you may need `python3` instead of `python`.

The first screen shows the interactive menu and the default vault path. By default the vault lives under:

- Windows: `C:\Users\<you>\.securepwm\vault.db`
- Linux/WSL: `/home/<you>/.securepwm/vault.db`

You can always change this path later (menu option `12) Change vault path`).

### 1.2. Initialize a new vault

1. Choose `1) Initialize vault`.
2. Accept the default vault path or type a different path.
3. Enter and confirm a strong master password (minimum 8 chars).

Under the hood this calls:

- `Vault.initialize` in `securepwm/vault.py`, which:
  - Creates the SQLite file and tables.
  - Generates a random salt and `vault_id`.
  - Derives the vault key with scrypt.
  - Derives the content/audit/recovery/label subkeys with HKDF.
  - Writes everything into `vault_state` and logs `VAULT_INIT`.

After this step, the vault is ready for entries.

---

## 2. Everyday usage

### 2.1. Unlock and lock

- If the vault is locked, any action that needs it will prompt you for the master password.
- Internally this calls `Vault.unlock`, which:
  - Reads `vault_state`,
  - Runs the same scrypt KDF,
  - Rebuilds the subkeys,
  - Updates `last_unlock_at`,
  - Logs `VAULT_UNLOCK`.

To lock manually, choose `13) Lock vault`. This calls `Vault.lock`, wipes keys from memory, and closes the DB handle.

### 2.2. Add entries

There are two ways to add entries:

- **Manual** – option `2) Add entry (manual)`  
  You type the username, site/service name, URL, category, and the secret/password.

- **Generated** – option `3) Add entry (generated)`  
  The tool generates a random password based on length and symbol preferences.

Both routes end up in `Vault.add_entry`, which:

- Generates a fresh random `entry_key`.
- Encrypts the secret with `encrypt_entry_content` (AES‑GCM + metadata AD).
- Wraps `entry_key` with `wrap_entry_key` using the `content_key`.
- Computes `username_hash` / `site_name_hash` with `hash_label`.
- Inserts a row into `entries` and logs `ENTRY_ADD`.

### 2.3. List and search

- **List everything** – option `4) List entries`  
  Shows username, site, category, and the first 8 chars of the ID for non‑deleted entries. This is just `Vault.list_entries`.

- **Fuzzy search** – option `7) Search entries`  
  Searches across four fields (`username`, `site_name`, `url`, `category`) using SQL `LIKE`. The method behind it is `Vault.search`.

- **Exact search (code‑only)**  
  In `vault.py` there is a `search_exact` that uses label hashes; I mainly use fuzzy search in the CLI for convenience.

### 2.4. Get an entry

Option `5) Get entry (view details)`:

1. You paste or type an entry ID.
2. The CLI calls `Vault.get_entry`.
3. You decide whether to show the password, copy it to clipboard (requires `pyperclip`), or both.

`Vault.get_entry`:

- Loads the row from `entries`.
- Unwraps the `entry_key` with `wrap_entry_key`’s inverse.
- Rebuilds the AD dict including metadata and timestamps.
- Calls `decrypt_entry_content`; if anything important was changed in the DB, AES‑GCM rejects.

### 2.5. Delete entries

Option `8) Delete entry`:

1. Shows a numbered list of entries.
2. You pick by number or by ID prefix.
3. Confirms with you and asks if this should be a permanent delete.

Internally:

- Soft delete calls `Vault.delete_entry(entry_id, hard=False)` and just sets `deleted=1`.
- Hard delete calls `Vault.delete_entry(entry_id, hard=True)` and removes the row.
- Both variants append an audit log entry (`ENTRY_DELETE` or `ENTRY_HARD_DELETE`).

### 2.6. Quick copy

Option `6) Quick copy (copy password)`:

1. Lists entries.
2. Lets you select by number or ID prefix.
3. Decrypts the entry and copies the password to clipboard (if `pyperclip` is installed).

This uses the same `Vault.get_entry` path underneath, but never prints the secret unless clipboard support is missing.

---

## 3. Audit log and tamper checks

### 3.1. Verify audit log

Option `9) Verify audit log`:

- Calls `Vault.verify_audit_log`, which:
  - Reads all rows from `audit_log`.
  - Recomputes each MAC with `compute_audit_mac`.
  - Ensures the chain matches using `verify_audit_chain`.

If anything in the audit log was edited, inserted, deleted, or reordered, verification fails and the CLI prints a warning.

### 3.2. What gets logged

The vault logs the main operations:

- `VAULT_INIT`, `VAULT_UNLOCK`
- `ENTRY_ADD`, `ENTRY_GET`, `ENTRY_DELETE`, `ENTRY_HARD_DELETE`
- `VAULT_RECOVERY` (when the recovery flow is used)

The audit log also records timestamps and an optional payload, so you can later tell when critical events happened.

---

## 4. Recovery flow (what to do when you forget the password)

The recovery feature is built on Shamir secret sharing. You create a recovery kit once (when you still know the master password), and you can later use any `k` shares from that kit to reset the vault to a new password.

### 4.1. Create a recovery kit

Do this once for each vault after initialization:

1. From the main menu, choose `10) Create recovery kit`.
2. Pick a threshold `k` (for example 3) and total shares `n` (for example 5).
3. Choose an output file, e.g. `recovery_kit.txt`.

The CLI calls:

- `generate_recovery_shares(vault.vault_key, k, n)` from `securepwm/recovery.py`.
- `print_recovery_kit` to produce human‑readable text with the shares and instructions.

Print the kit and store each share in a different place. Any `k` of them together are as powerful as your master password, so they should not all live in the same drawer.

### 4.2. Recover a vault

If you forget the master password but still have at least `k` shares:

1. Start the CLI with `python spwm_main.py`.
2. Make sure the `Vault:` path at the top points to the right file (option `12) Change vault path` if needed).
3. Choose `11) Recover vault`.
4. Paste in one share per line (from the printed kit). Press Enter on an empty line when you are done.
5. The CLI reconstructs the secret using `combine_recovery_shares`.
6. You choose a brand new master password and confirm it.

Under the hood:

- The reconstructed secret is treated as the current vault key.
- `Vault.recover_vault_with_shares`:
  - Verifies the key by decrypting an entry.
  - Decrypts all entries into memory.
  - Derives a new vault key from the new master password and a fresh salt.
  - Re‑encrypts everything with the new keys.
  - Updates `vault_state` and logs `VAULT_RECOVERY`.

After recovery:

- The old master password no longer works.
- You should immediately generate a new recovery kit under the new password.

---

## 5. How to “kick the tires” quickly

If you only have a few minutes and want to see the behavior end‑to‑end:

- Run `python demo.py` for a guided, non‑interactive tour through the main operations with commentary.
- Run `python attack_demo.py` to see:
  - Metadata tampering detected via AEAD AD.
  - Audit MAC tampering detected by the chain.
  - Recovery failing when given too few shares.
- Run `python test_simple.py` to exercise the individual crypto pieces and end‑to‑end vault logic.

