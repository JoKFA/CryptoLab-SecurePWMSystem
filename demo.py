"""
SecurePWM - Guided CLI Journey (single run, no user input)

Run: python demo.py

This script simulates what a first-time user would see in the interactive menu
(`spwm_main.py`) and explains what happens under the hood. It walks through:
 - Vault initialization (master password setup)
 - Adding entries (manual + generated)
 - Listing entries
 - Fuzzy search
 - Getting an entry (decryption) and quick copy
 - Audit verification
 - Soft delete
 - Metadata tampering detection
 - Audit log tampering detection
 - Recovery kit generation (Shamir k-of-n)
 - Recovery flow (re-key with new master password)
 - Password generator samples
 - Locking and cleanup

All steps print the UI-style output plus a short “behind the scenes” note.
"""

import os
import sqlite3
import tempfile
from textwrap import indent

from securepwm import crypto
from securepwm.vault import Vault
from securepwm.recovery import generate_recovery_shares, combine_recovery_shares


LINE = "=" * 70


def step(title: str, menu_option: str, code_path: str):
    print(f"\n{LINE}\n{title}  (menu option {menu_option}, code: {code_path})\n{LINE}")


def explain(title: str, body: str):
    print(f"\n[Behind the scenes] {title}")
    print(indent(body.strip(), "  "))


def menu_snapshot():
    print("SecurePWM - Interactive Menu (snapshot from spwm_main.py)")
    print(LINE)
    print(" 1) Initialize vault")
    print(" 2) Add entry (manual)")
    print(" 3) Add entry (generated)")
    print(" 4) List entries")
    print(" 5) Get entry (view details)")
    print(" 6) Quick copy (copy password)")
    print(" 7) Search entries (fuzzy)")
    print(" 8) Delete entry")
    print(" 9) Verify audit log")
    print("10) Create recovery kit")
    print("11) Recover vault")
    print("12) Change vault path")
    print("13) Lock vault")
    print(" 0) Exit")


def main():
    step("SecurePWM - Guided CLI Journey", "-", "spwm_main.py")
    menu_snapshot()

    # Prepare a temporary vault file
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db_path = tmp.name
    tmp.close()
    vault = None
    master_password = "CorrectHorseBatteryStaple!"

    try:
        # 1) Initialize vault (option 1)
        step("Initialize vault", "1", "securepwm/vault.py:initialize")
        print(f"Prompt: Vault file path [{db_path}] -> user accepts default")
        print("Prompt: Enter master password -> user chooses a strong password")
        vault = Vault(db_path)
        vault.initialize(master_password)
        print("Output: Vault created!")
        explain(
            "Key derivation",
            "scrypt (N=2^17, r=8, p=1) turns password+salt into a 32-byte vault_key (~250 ms, ~16 MB). "
            "HKDF derives independent content/audit/recovery/label keys with info strings for domain separation.",
        )

        # 2) Add entry (manual) (option 2)
        step("Add entry (manual)", "2", "securepwm/vault.py:add_entry")
        username = "alice@example.com"
        site = "github.com"
        url = "https://github.com/login"
        category = "Work"
        secret = "ghp_super_secret_token"
        print(f"Prompts: username={username}, site={site}, url={url}, category={category}, secret=typed manually")
        entry_id_manual = vault.add_entry(
            secret.encode(),
            username=username,
            site_name=site,
            url=url,
            category=category,
        )
        print(f"Output: Added! ID: {entry_id_manual}")
        explain(
            "Envelope encryption + AD binding",
            "A random entry_key encrypts the secret with AES-GCM; content_key wraps entry_key. "
            "Associated Data binds vault_id, entry_id, schema_version, entry_version, timestamps, and metadata "
            "(username/site/url/category). Any metadata change or context swap breaks decryption.",
        )

        # 3) Add entry (generated) (option 3)
        step("Add entry (generated)", "3", "securepwm/vault.py:add_entry / securepwm/crypto.py:generate_password")
        gen_username = "alice@example.com"
        gen_site = "mail.example.com"
        gen_pwd = crypto.generate_password(20, use_symbols=True)
        print(f"Prompts: username={gen_username}, site={gen_site}, generated password={gen_pwd}")
        entry_id_gen = vault.add_entry(
            gen_pwd.encode(),
            username=gen_username,
            site_name=gen_site,
            url="https://mail.example.com",
            category="Personal",
        )
        print(f"Output: Added! ID: {entry_id_gen}")

        # 4) List entries (option 4)
        step("List entries", "4", "securepwm/vault.py:list_entries")
        entries = vault.list_entries()
        print("UI output:")
        for e in entries:
            print(f"  {e['id'][:8]}...  user={e['username']}  site={e['site_name']}  category={e['category']}")

        # 5) Fuzzy search (option 7)
        step("Search entries (fuzzy)", "7", "securepwm/vault.py:search")
        query = "git"
        print(f"Prompt: search term -> '{query}'")
        results = vault.search(query)
        print("UI output (partial matches on username/site/url/category):")
        for e in results:
            print(f"  {e['id'][:8]}... user={e['username']} site={e['site_name']} url={e['url']}")
        explain(
            "Searchability",
            "Plaintext metadata enables fuzzy SQL LIKE search; exact search uses HMAC(label_key, label). "
            "Metadata is still authenticated via AD, so altering it breaks decryption.",
        )

        # 6) Get entry (option 5)
        step("Get entry (view details)", "5", "securepwm/vault.py:get_entry")
        print(f"Prompt: Entry ID -> {entry_id_manual}")
        e = vault.get_entry(entry_id_manual)
        print("UI output:")
        print(f"  Password: {e['secret'].decode()}")
        print(f"  Username: {e['username']}")
        print(f"  Site: {e['site_name']}")
        print(f"  URL: {e['url']}")
        print(f"  Category: {e['category']}")
        explain(
            "Decryption check",
            "unwrap_entry_key (content_key + AD) -> entry_key; decrypt_entry_content with full AD. "
            "Any mismatch in bound fields causes AES-GCM to reject.",
        )

        # 6b) Quick copy (option 6)
        step("Quick copy (copy password)", "6", "securepwm/vault.py:get_entry")
        print(f"Prompt: select entry -> using {entry_id_manual}")
        try:
            import pyperclip
            pyperclip.copy(e["secret"].decode())
            print("UI output: Copied to clipboard (pyperclip installed)")
        except Exception:
            print("UI output: Clipboard support not installed; would copy this value:")
            print(f"  {e['secret'].decode()}")
        explain(
            "Clipboard note",
            "Quick copy pulls the same decrypted secret and attempts to place it on the clipboard; falls back to printing if pyperclip is absent.",
        )

        # 7) Verify audit log (option 9)
        step("Verify audit log", "9", "securepwm/vault.py:verify_audit_log / securepwm/crypto.py:verify_audit_chain")
        ok = vault.verify_audit_log()
        print(f"Output: {'Audit log intact' if ok else 'Audit log tampered'}")
        explain(
            "Audit chain",
            "compute_audit_mac HMACs {seq, ts, action, payload_hash, prev_mac}; verify_audit_chain recomputes and compares. "
            "Insert/delete/reorder/edit breaks the chain.",
        )

        # 8) Soft delete (option 8)
        step("Delete entry (soft delete)", "8", "securepwm/vault.py:delete_entry")
        print(f"Prompt: choose entry -> deleting {entry_id_gen} (soft delete)")
        vault.delete_entry(entry_id_gen, hard=False)
        print("UI output: Entry marked deleted (still in DB, hidden from list/search)")
        entries_after_delete = vault.list_entries()
        print("List after delete:")
        for e in entries_after_delete:
            print(f"  {e['id'][:8]}... user={e['username']} site={e['site_name']} deleted={e.get('deleted', 0)}")
        explain(
            "Soft delete",
            "Marks deleted=1; entry is excluded from list/search but data remains. Hard delete removes row entirely.",
        )

        # 9) Metadata tampering detection
        step("Metadata tampering demo", "-", "securepwm/crypto.py:decrypt_entry_content (AD binding)")
        print("Directly editing site_name in SQLite to 'evil.com' ...")
        vault.lock()
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("UPDATE entries SET site_name = ? WHERE id = ?", ("evil.com", entry_id_manual))
        conn.commit()
        conn.close()
        vault.unlock(master_password)
        try:
            vault.get_entry(entry_id_manual)
            print("ERROR: decryption unexpectedly succeeded")
        except Exception as ex:
            print(f"Expected failure: metadata tampering detected -> {ex}")
        explain(
            "Why it fails",
            "Metadata is authenticated via AEAD AD; changing site_name makes AD mismatch, so GCM rejects.",
        )
        # Restore metadata for subsequent steps
        vault.lock()
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("UPDATE entries SET site_name = ? WHERE id = ?", (site, entry_id_manual))
        conn.commit()
        conn.close()
        vault.unlock(master_password)

        # 10) Audit log tampering detection
        step("Audit log tampering demo", "-", "securepwm/crypto.py:verify_audit_chain")
        print("Corrupting audit_log.mac for seq=1 in SQLite ...")
        vault.lock()
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("UPDATE audit_log SET mac = X'00010203' WHERE seq = 1")
        conn.commit()
        conn.close()
        vault.unlock(master_password)
        ok = vault.verify_audit_log()
        print(f"After tamper, verify: {'intact (unexpected)' if ok else 'tampering detected as expected'}")

        # 11) Recovery kit (option 10)
        step("Recovery kit (k-of-n)", "10", "securepwm/recovery.py:generate_recovery_shares")
        k, n = 3, 5
        # In the real CLI, the recovery kit is created over the vault key.
        shares = generate_recovery_shares(vault.vault_key, k=k, n=n)
        print(f"Generated {n} shares (need {k} to recover). Sample words per share:")
        for i, share in enumerate(shares, 1):
            print(f"  Share {i}: {' '.join(share[:5])} ...")
        explain(
            "Shamir k-of-n (kit creation)",
            "The 32-byte vault key is split into n shares; any k reconstruct via polynomial interpolation. Fewer than k leak nothing.",
        )

        # 11b) Recovery flow (option 11)
        step(
            "Recover vault with shares",
            "11",
            "securepwm/vault.py:recover_vault_with_shares / spwm_main.py:cmd_recover",
        )
        print("Simulating loss of the master password and recovery using shares 1,3,5...")
        new_master_password = "NewMasterPassword123!"

        # Lock the current vault handle to mimic a fresh process, then reconstruct the key
        vault.lock()
        recovered_key = combine_recovery_shares([shares[0], shares[2], shares[4]])

        # Perform recovery using a fresh Vault instance (same pattern as the CLI)
        vault_for_recovery = Vault(db_path)
        vault_for_recovery.recover_vault_with_shares(recovered_key, new_master_password)
        vault_for_recovery.lock()
        print("Recovery call completed (vault re-keyed).")

        # Show that the old master password no longer works
        print("Checking that the old master password no longer works...")
        old = Vault(db_path)
        try:
            old.unlock(master_password)
            old.get_entry(entry_id_manual)
            print("ERROR: old master password still works after recovery")
        except Exception:
            print("As expected: old master password fails after recovery.")
        finally:
            try:
                old.lock()
            except Exception:
                pass

        # Show that the new master password works and the entry still decrypts
        print("Checking that the new master password works and entries still decrypt...")
        new = Vault(db_path)
        new.unlock(new_master_password)
        recovered_entry = new.get_entry(entry_id_manual)
        print(f"Decryption with new master password still returns the secret: {recovered_entry['secret'].decode()}")
        new.lock()


        # 12) Password generator samples
        step("Password generator", "-", "securepwm/crypto.py:generate_password")
        for label, length, symbols in [
            ("Default", 16, True),
            ("Long", 24, True),
            ("Alphanumeric", 16, False),
        ]:
            pwd = crypto.generate_password(length=length, use_symbols=symbols)
            print(f"  {label}: {pwd}")

        # 13) Lock and exit (option 13 then 0)
        step("Lock and exit", "13 / 0", "securepwm/vault.py:lock")
        if vault:
            vault.lock()
        print("Output: Locked (keys cleared from memory)")
        print("User chooses: 0) Exit")
        print("Goodbye!")

    finally:
        if vault:
            try:
                vault.lock()
            except Exception:
                pass
        if os.path.exists(db_path):
            os.unlink(db_path)
        print(f"\nCleaned up temporary vault at {db_path}")


if __name__ == "__main__":
    main()
