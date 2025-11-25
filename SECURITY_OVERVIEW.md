# SecurePWM – Security Overview (course edition)

This note is the place where we justify the design, tie it to concrete code, and show how to demo the interesting bits without hand‑waving.

---

## Goals

- Local, zero‑knowledge vault: the master password never leaves the host; only ciphertext and metadata land on disk.
- Memory‑hard password derivation to slow offline guessing.
- Per‑entry isolation and authenticated metadata to stop context confusion / rollback.
- Tamper‑evident audit trail.
- Offline recovery without a single point of failure.

---

## Threat model (practical scope)

**Defends against:**

- Someone stealing / copying the SQLite DB file.
- Offline brute‑force within “reasonable student project” cost bounds.
- Tampering with ciphertext, metadata, or trying replay/rollback.
- Editing, deleting, or reordering audit log entries.
- Trying to reconstruct the recovery secret with fewer than `k` shares.

**Does not even try to defend against:**

- A compromised OS or keylogger that sees keystrokes.
- An attacker with physical access while the vault is unlocked.
- Clipboard sniffing after a password has been copied.

---

## Cryptographic building blocks

- **Password → vault key (scrypt)**  
  `securepwm/crypto.py:derive_vault_key` uses scrypt with:
  - `N = 2^17` (~16 MB RAM, ~250 ms on a normal laptop),
  - `r = 8`, `p = 1`,
  to raise the cost of offline guessing.

- **Key hierarchy (HKDF)**  
  `securepwm/crypto.py:derive_subkeys` turns the vault key into four independent subkeys:
  - `content_key` – wraps per‑entry keys.
  - `audit_key` – HMAC for the audit chain.
  - `recovery_key` – reserved for recovery (see below).
  - `label_key` – HMAC for exact‑match search labels.

- **Envelope encryption (per‑entry keys)**  
  Each entry gets a random `entry_key`. The secret is encrypted with AES‑256‑GCM under `entry_key`; then `wrap_entry_key` encrypts `entry_key` using `content_key` + Associated Data (AD) that binds it to `vault_id` and `entry_id`.

- **AEAD with Associated Data**  
  `encrypt_entry_content` / `decrypt_entry_content` bind:
  - `vault_id`, `entry_id`,
  - `schema_version`, `entry_version`,
  - `created_at`, `updated_at`,
  - plus metadata (`username`, `site_name`, `url`, `category`)  
  into the AD. Any change to those fields makes GCM reject.

- **Audit integrity (HMAC chain)**  
  `compute_audit_mac` and `verify_audit_chain` build a hash chain over `{seq, ts, action, payload_hash, prev_mac}`. Any edit, insert, or reorder breaks the chain.

- **Recovery (Shamir k‑of‑n)**  
  `generate_recovery_shares` / `combine_recovery_shares` use `shamir-mnemonic` to split a 32‑byte secret into `n` shares so that any `k` shares reconstruct it and fewer than `k` leak nothing.

- **Exact search without leaking labels**  
  `hash_label` computes `HMAC(label_key, label.lower())` and stores that alongside plaintext metadata. The plaintext exists for UX (fuzzy search), but is still authenticated via AEAD AD.

---

## Data model bindings (SQLite, `securepwm/vault.py`)

- **`vault_state`**  
  Single row with:
  - `vault_id`, `schema_version`,
  - KDF name + JSON params, `kdf_salt`,
  - AEAD algorithm, creation + last‑unlock timestamps.

- **`entries`**  
  For each password entry:
  - Plaintext metadata: `username`, `site_name`, `url`, `category`.
  - HMAC for exact search: `username_hash`, `site_name_hash`.
  - Wrapped entry key: `key_nonce`, `key_wrapped`.
  - Ciphertext: `content_nonce`, `content_ciphertext`.
  - Timestamps: `created_at`, `updated_at`.
  - `deleted` flag (soft delete).

- **`audit_log`**  
  - `seq`, `ts`, `action`,
  - `payload` (optional),
  - `prev_mac`, `mac` (HMAC chain).

The schema lives in `SCHEMA` at the top of `securepwm/vault.py`.

---

## Attack scenarios and defenses

- **Stolen DB**  
  - Secrets and entry keys are AEAD‑encrypted.
  - scrypt slows down brute‑force attempts on the master password.
  - HKDF keeps subkeys separated (no cross‑use between content, audit, recovery, label).

- **Metadata tampering / UI spoofing**  
  - Metadata is plaintext for UX, but included in AEAD AD.
  - Changing `site_name` to “evil.com” in SQLite causes decryption to fail.

- **Replay / rollback**  
  - AD includes `created_at`, `updated_at`, and version fields.
  - Re‑using old ciphertext in a newer context fails verification.

- **Audit manipulation**  
  - Each audit record authenticates `seq`, `ts`, `action`, `payload_hash`, and `prev_mac`.
  - Insert/delete/reorder/edit breaks the recomputed chain in `verify_audit_chain`.

- **Label enumeration**  
  - Exact search uses HMAC over labels, not raw strings.
  - Metadata is still plaintext for fuzzy search, but any change is detected by AEAD.

- **Recovery key exposure**  
  - The k‑of‑n shares follow Shamir; fewer than `k` are information‑theoretically useless.
  - Any `k` valid shares are as powerful as the master password (by design).

---

## Code snippets – key pieces

These are the small pieces of code I usually point at when explaining the design.

### 1. Key derivation (scrypt + HKDF)

```python
# securepwm/crypto.py
VAULT_KEY_SIZE = 32
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1

def derive_vault_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=VAULT_KEY_SIZE,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode("utf-8"))

def derive_subkeys(vault_key: bytes) -> Dict[str, bytes]:
    def hkdf(info: str) -> bytes:
        h = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info.encode("utf-8"),
        )
        return h.derive(vault_key)

    return {
        "content_key": hkdf("spwm-content-v1"),
        "audit_key": hkdf("spwm-audit-v1"),
        "recovery_key": hkdf("spwm-recovery-v1"),
        "label_key": hkdf("spwm-label-v1"),
    }
```

`Vault.initialize` and `Vault.unlock` call these to set up `content_key`, `audit_key`, `recovery_key`, and `label_key`.

---

### 2. AEAD and metadata binding

```python
# securepwm/crypto.py
def encrypt_entry_content(
    entry_key: bytes,
    content: bytes,
    vault_id: str,
    entry_id: str,
    created_at: int,
    updated_at: int,
    schema_version: int = 1,
    entry_version: int = 1,
    metadata: Optional[Dict[str, Optional[str]]] = None,
) -> Tuple[bytes, bytes]:
    ad = {
        "ctx": "entry_content",
        "vault_id": vault_id,
        "entry_id": entry_id,
        "aead": "aes256gcm",
        "schema_version": schema_version,
        "entry_version": entry_version,
        "created_at": created_at,
        "updated_at": updated_at,
    }
    if metadata:
        ad["metadata"] = metadata
    return encrypt(entry_key, content, ad)
```

On decryption, `decrypt_entry_content` rebuilds the same AD dict. `Vault.get_entry` is responsible for passing in the metadata read from SQLite; if any of those fields were edited directly in the DB, AES‑GCM refuses to decrypt.

---

### 3. Audit chain

```python
# securepwm/crypto.py
def compute_audit_mac(
    audit_key: bytes,
    seq: int,
    ts: int,
    action: str,
    prev_mac: Optional[bytes],
    payload: Optional[bytes] = None,
) -> bytes:
    if payload:
        payload_hash = hashlib.sha256(payload).hexdigest()
    else:
        payload_hash = ""

    message = {
        "seq": seq,
        "ts": ts,
        "action": action,
        "payload_hash": payload_hash,
        "prev_mac": prev_mac.hex() if prev_mac else "",
    }
    message_bytes = canonical_ad(message)
    return hmac.new(audit_key, message_bytes, hashlib.sha256).digest()
```

`Vault._audit` calls this for each operation, storing `{seq, ts, action, payload, prev_mac, mac}`. `Vault.verify_audit_log` pulls all rows, reconstructs the chain with `verify_audit_chain`, and returns `False` if any MAC does not line up.

---

### 4. Recovery

```python
# securepwm/recovery.py
def generate_recovery_shares(recovery_key: bytes, k: int, n: int) -> List[List[str]]:
    groups = shamir.generate_mnemonics(
        group_threshold=1,
        groups=[(k, n)],
        master_secret=recovery_key,
    )
    return groups[0]

def combine_recovery_shares(shares: List[str]) -> bytes:
    return shamir.combine_mnemonics(shares)
```

In the current CLI wiring:

- When you choose **“Create recovery kit”** (menu option 10), `cmd_recovery_create` calls:

  ```python
  shares = generate_recovery_shares(vault.vault_key, k, n)
  ```

- When you choose **“Recover vault”** (option 11), `cmd_recover` reads any `k` shares, calls `combine_recovery_shares`, and then:

  ```python
  vault = Vault(vault_path)
  vault.recover_vault_with_shares(recovery_key, pw)
  ```

Inside `recover_vault_with_shares` (in `securepwm/vault.py`) I:

1. Open the DB and read `vault_state`.
2. Treat the reconstructed secret as the vault key: `self.vault_key = recovered_vault_key`.
3. Derive subkeys and verify I can unwrap + decrypt at least one entry.
4. Decrypt all entries to memory with the old keys.
5. Pick a fresh salt and derive a new vault key from the new master password.
6. Re‑encrypt all entries under the new keys and update `vault_state.kdf_salt`.
7. Add a `VAULT_RECOVERY` record to the audit log.

So, possessing any valid `k`‑of‑`n` shares is equivalent to knowing the master password; fewer than `k` shares are useless on their own.

---

## Security flows (end‑to‑end)

These are the flows I actually show when I demo the project.

### Vault initialization

- `Vault.initialize`:
  - Creates the SQLite file, applies PRAGMAs.
  - Picks a random salt and `vault_id`.
  - Stores KDF parameters and salt in `vault_state`.
  - Runs `derive_vault_key` + `derive_subkeys`.
  - Logs `VAULT_INIT` in `audit_log`.

### Unlock

- `Vault.unlock`:
  - Reads `vault_state`.
  - Runs the same scrypt with the stored salt.
  - Rebuilds `content_key`, `audit_key`, `recovery_key`, `label_key`.
  - Updates `last_unlock_at`.
  - Logs `VAULT_UNLOCK`.

### Add / get entry

- `Vault.add_entry`:
  - Generates a random `entry_key`.
  - Computes label HMACs using `label_key`.
  - Encrypts the secret with `encrypt_entry_content` and wraps `entry_key` with `wrap_entry_key`.
  - Inserts into `entries` with metadata + hashes + ciphertext.
  - Logs `ENTRY_ADD`.

- `Vault.get_entry`:
  - Loads the row from `entries` (if `deleted = 0`).
  - Unwraps `entry_key` with `wrap_entry_key`’s inverse.
  - Re‑builds metadata AD and calls `decrypt_entry_content`.
  - Logs `ENTRY_GET`.

### Audit verification

- `Vault.verify_audit_log`:
  - Reads all rows from `audit_log`.
  - Calls `verify_audit_chain` with `audit_key`.
  - Returns `True` if the chain is intact; otherwise `False`.

### Recovery and re‑key

- While you still know the master password:
  - Use menu option `10) Create recovery kit` once.
  - Print the kit and store shares in separate places.

- If you later forget the master password:
  - Use menu option `11) Recover vault`.
  - Paste any `k` shares from the kit.
  - The CLI reconstructs the secret, verifies it can decrypt entries, and then re‑keys the vault to a new master password.

---

## Future hardening (ideas only)

Things I would add if this were more than a course project:

- Side‑channel hardening around password input and secret handling.
- Auto‑lock timers and clipboard scrubbing.
- Hardware token or TPM‑backed wrapping of the vault key.
- Rate limiting / unlock delay at the UI layer.

