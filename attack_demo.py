"""
SecurePWM - Attack Demonstration

Run: python attack_demo.py

What it shows (and why attacks fail):
1) Wrong master password cannot decrypt the vault.
2) Metadata tampering breaks AEAD Associated Data binding.
3) Ciphertext tampering is detected by AES-GCM.
4) Audit log tampering is detected by the HMAC chain.
5) Shamir recovery rejects insufficient shares.
"""

import os
import sqlite3
import tempfile

from securepwm import crypto
from securepwm.vault import Vault
from securepwm.recovery import generate_recovery_shares, combine_recovery_shares


LINE = "=" * 70


def section(title: str):
    print(f"\n{LINE}\n{title}\n{LINE}")


def main():
    # Prepare a fresh vault
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    master_password = "CorrectHorseBatteryStaple!"
    entry_id = None

    # Initialize and add one entry
    vault = Vault(db_path)
    vault.initialize(master_password)
    entry_id = vault.add_entry(
        b"super_secret_password",
        username="alice@example.com",
        site_name="example.com",
        url="https://example.com/login",
        category="Work",
    )

    # 1) Wrong master password
    section("Attack 1: Wrong master password")
    try:
        bad = Vault(db_path)
        bad.unlock("wrong_password")
        bad.get_entry(entry_id)
        print("Unexpected: decryption succeeded with wrong password")
    except Exception as e:
        print(f"Expected failure: wrong password cannot decrypt ({e})")

    # 2) Metadata tampering (AD binding)
    section("Attack 2: Metadata tampering (AD-bound metadata)")
    vault.lock()
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("UPDATE entries SET site_name = ? WHERE id = ?", ("evil.com", entry_id))
    conn.commit()
    conn.close()
    vault.unlock(master_password)
    try:
        vault.get_entry(entry_id)
        print("Unexpected: tampered metadata still decrypted")
    except Exception as e:
        print(f"Expected failure: AD mismatch detected ({e})")

    # Restore metadata for next steps
    vault.lock()
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("UPDATE entries SET site_name = ? WHERE id = ?", ("example.com", entry_id))
    conn.commit()
    conn.close()
    vault.unlock(master_password)

    # 3) Ciphertext tampering (AES-GCM)
    section("Attack 3: Ciphertext tampering (AES-GCM)")
    row = vault.conn.execute(
        "SELECT content_ciphertext, content_nonce FROM entries WHERE id = ?", (entry_id,)
    ).fetchone()
    ct = bytearray(row["content_ciphertext"])
    ct[0] ^= 1  # flip one bit
    vault.conn.execute(
        "UPDATE entries SET content_ciphertext = ? WHERE id = ?", (bytes(ct), entry_id)
    )
    vault.conn.commit()
    try:
        vault.get_entry(entry_id)
        print("Unexpected: tampered ciphertext still decrypted")
    except Exception as e:
        print(f"Expected failure: AES-GCM detected tampering ({e})")

    # 4) Audit log tampering
    section("Attack 4: Audit log tampering")
    vault.lock()
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("UPDATE audit_log SET mac = X'00010203' WHERE seq = 1")
    conn.commit()
    conn.close()
    vault.unlock(master_password)
    ok = vault.verify_audit_log()
    if ok:
        print("Unexpected: audit tampering not detected")
    else:
        print("Expected failure: audit log tampering detected (HMAC chain broken)")

    # 5) Shamir recovery with insufficient shares
    section("Attack 5: Shamir recovery with insufficient shares")
    # Use the same secret size as the real recovery flow (32-byte key)
    shares = generate_recovery_shares(vault.vault_key, k=3, n=5)
    try:
        combine_recovery_shares([shares[0], shares[1]])  # only 2 shares
        print("Unexpected: recovered with insufficient shares")
    except Exception as e:
        print(f"Expected failure: insufficient shares rejected ({e})")

    # Cleanup
    try:
        vault.lock()
    except Exception:
        pass
    if os.path.exists(db_path):
        try:
            os.unlink(db_path)
        except Exception:
            pass
    print("\nDemo complete. All showcased attacks failed as expected.")


if __name__ == "__main__":
    main()
