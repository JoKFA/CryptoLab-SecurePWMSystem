# SecurePWM – claims, code, and tests

This file is a small map from the security claims I care about to the code and tests that back them up.

---

## 1. Table

| Claim | Code | Test / demo |
| ----- | ---- | ----------- |
| scrypt is deterministic and gives 32‑byte keys; different passwords give different keys | `securepwm/crypto.py: derive_vault_key` | `test_simple.py: test_kdf` |
| AEAD detects ciphertext tampering and wrong AD | `securepwm/crypto.py: encrypt`, `decrypt` | `test_simple.py: test_encryption` (tampering and wrong AD cases) |
| Per‑entry envelope encryption correctly wraps/un‑wraps entry keys | `securepwm/crypto.py: create_entry_key`, `wrap_entry_key`, `unwrap_entry_key` | `test_simple.py: test_envelope_encryption` |
| Metadata is bound into AD, so editing it in SQLite breaks decryption | `securepwm/crypto.py: encrypt_entry_content`, `decrypt_entry_content`; `securepwm/vault.py: Vault.get_entry` | `test_simple.py: test_vault_operations` (“[Attack] Tampering metadata…” block) and `attack_demo.py` |
| Audit log forms a valid HMAC chain and detects tampering | `securepwm/crypto.py: compute_audit_mac`, `verify_audit_chain`; `securepwm/vault.py: Vault._audit`, `Vault.verify_audit_log` | `test_simple.py: test_audit_chain` and the audit tampering part of `attack_demo.py` |
| Normal vault operations (init, add, get, list, lock/unlock) behave as expected | `securepwm/vault.py: Vault.initialize`, `Vault.add_entry`, `Vault.get_entry`, `Vault.list_entries`, `Vault.unlock`, `Vault.lock` | `test_simple.py: test_vault_operations` and the “happy path” in `demo.py` |
| Wrong master password does not let you recover the secret | Same as above plus KDF | Wrong‑password block in `test_simple.py: test_vault_operations` and attack 1 in `attack_demo.py` |
| Shamir recovery reconstructs the secret with any k shares, and fails with fewer than k | `securepwm/recovery.py: generate_recovery_shares`, `combine_recovery_shares` | `test_simple.py: test_recovery` and the recovery section in `attack_demo.py` |
| Recovery flow can re‑key a real vault from shares and invalidate the old password | `securepwm/vault.py: Vault.recover_vault_with_shares`; `spwm_main.py: cmd_recovery_create`, `cmd_recover` | Manual test: create a vault, generate kit, recover, then unlock with the new password and verify the old password fails |
| Search uses HMACs for exact matches and plaintext for fuzzy matches, with metadata still covered by AEAD | `securepwm/crypto.py: hash_label`; `securepwm/vault.py: search`, `search_exact`, `encrypt_entry_content` / `decrypt_entry_content` | Covered indirectly in `test_vault_operations` (listing and metadata tampering) and visible in `demo.py` / `spwm_main.py` |

---

## 2. How to read this with the code open

If you have the repository open in an editor, my suggestion is:

1. Skim `README.md` to see where to run things.
2. Keep this file side‑by‑side.
3. For each row you care about, jump to the code file and test listed here.

That’s usually enough to convince yourself that each security claim has a specific implementation and at least one place where it is exercised.

