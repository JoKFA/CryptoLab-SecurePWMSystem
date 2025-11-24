# SecurePWM - Security Overview (Course Edition)

This note explains why SecurePWM is a solid crypto specimen for a security-focused presentation. It links design choices to concrete defenses and shows how to demo them credibly.

## Goals
- Local, zero-knowledge vault: master password never leaves the host; only ciphertext on disk.
- Memory-hard password derivation to slow offline guessing.
- Per-entry isolation and authenticated metadata to stop context confusion/rollback.
- Tamper-evident audit trail.
- Offline recovery without a single point of failure.

## Threat Model (practical scope)
- Defends: stolen vault DB, offline brute force within reasonable cost bounds, metadata spoofing, ciphertext tampering/rollback, audit log manipulation.
- Does not defend: compromised OS/keylogger, physical access while unlocked, clipboard snooping.

## Cryptographic Building Blocks
- Password → Vault key: scrypt (N=2^17, r=8, p=1) ~16 MB / ~250 ms to raise GPU/ASIC cost. Code: `derive_vault_key` in `securepwm/crypto.py`.
- Key hierarchy: HKDF derives independent subkeys (content/audit/recovery/label) with distinct info strings. Code: `derive_subkeys`.
- Envelope encryption: random per-entry key encrypts the secret; content_key wraps that entry key. Code: `wrap_entry_key` / `encrypt_entry_content`.
- AEAD with Associated Data: AES-256-GCM binds vault_id, entry_id, versions, timestamps, and optional metadata (username/site/url/category). Tampering or context swap causes decrypt failure. Code: `encrypt_entry_content` / `decrypt_entry_content`.
- Audit integrity: HMAC-SHA256 chain over {seq, ts, action, payload_hash, prev_mac}; any edit/reorder breaks verification. Code: `compute_audit_mac`, `verify_audit_chain`.
- Recovery: Shamir k-of-n over recovery_key; fewer than k shares yield nothing. Code: `generate_recovery_shares`, `combine_recovery_shares`.
- Exact search without leaking labels: HMAC over lowered labels (`hash_label`), plus plaintext metadata for usability; metadata still authenticated via AD.

## Data Model Bindings (SQLite, `securepwm/vault.py`)
- `vault_state`: vault_id, schema_version, KDF params, salt, aead, timestamps.
- `entries`: plaintext metadata (for UX), HMAC hashes (exact search), wrapped entry key, ciphertext, timestamps, deleted flag. Metadata is authenticated via AD even though stored plaintext.
- `audit_log`: seq, ts, action, payload, prev_mac, mac (HMAC chain).

## Attack Scenarios and Defenses
- Stolen DB: secrets and entry keys are AEAD-encrypted; per-entry keys limit blast radius. scrypt slows guesses; HKDF prevents key reuse across domains.
- Metadata tampering/UI spoofing: AD includes metadata; altered metadata causes decryption failure.
- Replay/rollback: AD binds created_at/updated_at and versions; old ciphertext cannot be replayed without detection.
- Audit manipulation: HMAC chain with seq+ts+prev_mac detects insert/delete/reorder/edit.
- Label enumeration: exact search uses HMAC(label_key, label) to hide label values (still supports plaintext fuzzy search as a usability tradeoff).
- Recovery key exposure risk: mitigated by Shamir k-of-n; fewer than k shares give zero info.

## Demo Checklist (what to show live)
1) scrypt cost: init vault and mention ~250 ms delay as intentional KDF hardness.
2) Add entries (one manual, one generated) and list them.
3) Metadata binding: edit metadata in SQLite (username/site) and show decryption failure.
4) Tamper detection: flip a byte in `audit_log.mac`; `verify` fails.
5) Recovery: generate k-of-n shares; recombine any k to recover.
6) Tests: `python test_simple.py` to back claims with automation.

## Future Hardening (talking points, not implemented)
- Side-channel hardening for password input and secret handling.
- Auto-lock timers and clipboard scrubbing.
- Hardware token or TPM-backed wrapping of vault_key.
- Rate limiting/unlock delay at the UI layer.

Use this document to drive the “why” behind each choice during your presentation, and point to the code locations above for proof.***
