"""
SecurePWM - Interactive Menu

Main user interface for the password manager.
Features:
- Initialize/unlock vault
- Add entries (manual or generated passwords)
- List/search/get/delete entries
- Quick copy to clipboard
- Verify audit log integrity
- Create recovery kits
"""

import os
import sys
import getpass
from datetime import datetime
from securepwm.vault import Vault
from securepwm.recovery import generate_recovery_shares, print_recovery_kit
from securepwm import crypto

DEFAULT_VAULT_PATH = os.path.join(os.path.expanduser("~"), ".securepwm", "vault.db")

def clear_screen():
    try:
        os.system("cls" if os.name == "nt" else "clear")
    except:
        pass

def pause():
    input("\nPress Enter to continue...")

def choose_vault_path(current=None):
    default = current or DEFAULT_VAULT_PATH
    print(f"Vault file path [{default}]: ", end="")
    return input().strip() or default

def ensure_vault_dir(path):
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

def unlock_flow(vault_path):
    if not os.path.exists(vault_path):
        print(f"\nERROR: Vault not found at {vault_path}")
        pause()
        return None
    password = getpass.getpass("\nMaster password: ")
    vault = Vault(vault_path)
    try:
        vault.unlock(password)
        print("\n✓ Vault unlocked.")
        pause()
        return vault
    except Exception as e:
        print(f"\nERROR: Failed to unlock vault ({e}).")
        pause()
        return None

def require_unlocked(vault, vault_path):
    return vault if vault else unlock_flow(vault_path)

def cmd_init(vault_path):
    clear_screen()
    print("=== Initialize New Vault ===\n")
    vault_path = choose_vault_path(vault_path)
    if os.path.exists(vault_path):
        print(f"\nVault exists at: {vault_path}")
        pause()
        return None, vault_path
    while True:
        pw = getpass.getpass("Enter master password: ")
        pw2 = getpass.getpass("Confirm: ")
        if pw != pw2:
            print("Passwords don't match.\n")
            continue
        if len(pw) < 8:
            print("Too short (min 8 chars).\n")
            continue
        break
    ensure_vault_dir(vault_path)
    print("\nInitializing...")
    vault = Vault(vault_path)
    vid = vault.initialize(pw)
    print(f"\n✓ Vault created! ID: {vid}")
    pause()
    return vault, vault_path

def cmd_add_manual(vault, vault_path):
    clear_screen()
    print("=== Add New Entry (Manual) ===\n")
    vault = require_unlocked(vault, vault_path)
    if not vault:
        return None
    username = input("Username (required): ").strip()
    if not username:
        print("Username required.")
        pause()
        return vault
    site_name = input("Site/Service name (optional): ").strip() or None
    url = input("URL (optional): ").strip() or None
    category = input("Category [Work/Personal/Banking/etc.] (optional): ").strip() or None
    secret = getpass.getpass("Secret/Password: ")
    if not secret:
        print("Cancelled.")
        pause()
        return vault
    try:
        eid = vault.add_entry(secret.encode('utf-8'), username, site_name, url, category)
        print(f"\n✓ Added! ID: {eid}")
    except Exception as e:
        print(f"ERROR: {e}")
    pause()
    return vault

def cmd_add_generated(vault, vault_path):
    clear_screen()
    print("=== Add New Entry (Generated) ===\n")
    vault = require_unlocked(vault, vault_path)
    if not vault:
        return None
    username = input("Username (required): ").strip()
    if not username:
        print("Username required.")
        pause()
        return vault
    site_name = input("Site/Service name (optional): ").strip() or None
    url = input("URL (optional): ").strip() or None
    category = input("Category [Work/Personal/Banking/etc.] (optional): ").strip() or None
    try:
        length = int(input("Password length [20]: ").strip() or 20)
    except:
        length = 20
    symbols = input("Include symbols? [Y/n]: ").strip().lower() not in ('n', 'no')
    pw = crypto.generate_password(length, symbols)
    print(f"\nGenerated: {pw}")
    try:
        eid = vault.add_entry(pw.encode('utf-8'), username, site_name, url, category)
        print(f"\n✓ Added! ID: {eid}")
    except Exception as e:
        print(f"ERROR: {e}")
    pause()
    return vault

def cmd_list_entries(vault, vault_path):
    clear_screen()
    print("=== List Entries ===\n")
    vault = require_unlocked(vault, vault_path)
    if not vault:
        return None
    try:
        entries = vault.list_entries()
        if not entries:
            print("No entries.")
        else:
            print(f"{'Username':<22}  {'Site':<20}  {'Category':<12}  {'ID (first 8)'}")
            print("-" * 70)
            for e in entries:
                short_id = e['id'][:8]
                print(f"{e['username']:<22}  {e['site_name'] or '-':<20}  {e['category'] or '-':<12}  {short_id}...")
    except Exception as e:
        print(f"ERROR: {e}")
    pause()
    return vault

def cmd_get_entry(vault, vault_path):
    clear_screen()
    print("=== Get Entry ===\n")
    vault = require_unlocked(vault, vault_path)
    if not vault:
        return None
    eid = input("Entry ID: ").strip()
    if not eid:
        pause()
        return vault
    try:
        e = vault.get_entry(eid)
        print(f"\n  ID: {e['id']}")
        print(f"  Username: {e['username']}")
        if e.get('site_name'):
            print(f"  Site: {e['site_name']}")
        if e.get('url'):
            print(f"  URL: {e['url']}")
        if e.get('category'):
            print(f"  Category: {e['category']}")

        # Ask what to do with the password
        print("\nOptions:")
        print("  1) Show password")
        print("  2) Copy to clipboard (without showing)")
        print("  3) Both")
        print("  0) Cancel")
        choice = input("\n> ").strip()
        
        secret_str = e['secret'].decode('utf-8')
        
        if choice == '1':
            print(f"\n  Password: {secret_str}")
        elif choice == '2':
            try:
                import pyperclip
                pyperclip.copy(secret_str)
                print("\n✓ Copied to clipboard!")
            except ImportError:
                print("\n(pyperclip not installed - run: pip install pyperclip)")
        elif choice == '3':
            print(f"\n  Password: {secret_str}")
            try:
                import pyperclip
                pyperclip.copy(secret_str)
                print("✓ Also copied to clipboard!")
            except ImportError:
                print("(pyperclip not installed for clipboard)")
        else:
            print("Cancelled.")
    except Exception as e:
        print(f"ERROR!! Aborting")
    pause()
    return vault


def cmd_quick_copy(vault, vault_path):
    """Copy password to clipboard without displaying it."""
    clear_screen()
    print("=== Quick Copy ===\n")
    vault = require_unlocked(vault, vault_path)
    if not vault:
        return None
    
    # Show list first for convenience
    try:
        entries = vault.list_entries()
        if not entries:
            print("No entries in vault.")
            pause()
            return vault
        
        print(f"{'#':<4}  {'Username':<20}  {'Site':<25}  {'ID (first 8)'}")
        print("-" * 70)
        for i, e in enumerate(entries, 1):
            short_id = e['id'][:8]
            print(f"{i:<4}  {e['username']:<20}  {e['site_name'] or '-':<25}  {short_id}...")
        
        print(f"\nEnter # (1-{len(entries)}) or full ID:")
        choice = input("> ").strip()
        
        # Determine entry ID
        if choice.isdigit() and 1 <= int(choice) <= len(entries):
            eid = entries[int(choice) - 1]['id']
        else:
            eid = choice  # Assume it's a full/partial ID
            # Try to match partial ID
            matches = [e for e in entries if e['id'].startswith(eid)]
            if len(matches) == 1:
                eid = matches[0]['id']
            elif len(matches) > 1:
                print("Multiple matches. Please use full ID.")
                pause()
                return vault
        
        # Get and copy
        e = vault.get_entry(eid)
        try:
            import pyperclip
            pyperclip.copy(e['secret'].decode('utf-8'))
            print(f"\n✓ Password for '{e['username']}' copied to clipboard!")
        except ImportError:
            print("\nERROR: pyperclip not installed. Run: pip install pyperclip")
            print(f"Password: {e['secret'].decode('utf-8')}")
    except Exception as e:
        print(f"ERROR!! Aborting")
    pause()
    return vault

def cmd_search(vault, vault_path):
    clear_screen()
    print("=== Search Entries ===\n")
    vault = require_unlocked(vault, vault_path)
    if not vault:
        return None
    query = input("Search (username or site): ").strip()
    if not query:
        print("No search term entered.")
        pause()
        return vault
    entries = vault.search(query)
    if not entries:
        print("\nNo matches found.")
    else:
        print(f"\nFound {len(entries)} entries:\n")
        print(f"{'ID':<36}  {'Username':<20}  {'Site':<25}")
        print("-" * 85)
        for e in entries:
            print(f"{e['id']:<36}  {e['username']:<20}  {e['site_name'] or '-':<25}")
    pause()
    return vault


def cmd_delete(vault, vault_path):
    clear_screen()
    print("=== Delete Entry ===\n")
    vault = require_unlocked(vault, vault_path)
    if not vault:
        return None
    
    # Show list first
    try:
        entries = vault.list_entries()
        if not entries:
            print("No entries in vault.")
            pause()
            return vault
        
        print(f"{'#':<4}  {'Username':<20}  {'Site':<25}  {'ID (first 8)'}")
        print("-" * 70)
        for i, e in enumerate(entries, 1):
            short_id = e['id'][:8]
            print(f"{i:<4}  {e['username']:<20}  {e['site_name'] or '-':<25}  {short_id}...")
        
        print(f"\nEnter # (1-{len(entries)}) or full ID to delete:")
        choice = input("> ").strip()
        
        if not choice:
            print("Cancelled.")
            pause()
            return vault
        
        # Determine entry ID
        if choice.isdigit() and 1 <= int(choice) <= len(entries):
            eid = entries[int(choice) - 1]['id']
            entry_info = entries[int(choice) - 1]
        else:
            eid = choice
            matches = [e for e in entries if e['id'].startswith(eid)]
            if len(matches) == 1:
                eid = matches[0]['id']
                entry_info = matches[0]
            elif len(matches) > 1:
                print("Multiple matches. Please use full ID.")
                pause()
                return vault
            else:
                print("Entry not found.")
                pause()
                return vault
        
        # Confirm
        print(f"\nAbout to delete:")
        print(f"  Username: {entry_info['username']}")
        print(f"  Site: {entry_info['site_name'] or '-'}")
        print(f"  ID: {eid}")
        
        confirm = input("\nType 'yes' to confirm: ").strip().lower()
        if confirm != 'yes':
            print("Cancelled.")
            pause()
            return vault
        
        hard = input("Permanently delete? [y/N]: ").strip().lower() == 'y'
        vault.delete_entry(eid, hard=hard)
        print(f"\n✓ Entry deleted{'(permanently)' if hard else ''}.")
    except Exception as e:
        print(f"ERROR: {e}")
    pause()
    return vault

def cmd_verify(vault, vault_path):
    clear_screen()
    print("=== Verify Audit Log ===\n")
    vault = require_unlocked(vault, vault_path)
    if not vault:
        return None
    try:
        if vault.verify_audit_log():
            print("✓ Audit log intact!")
        else:
            print("✗ TAMPERED!")
    except Exception as e:
        print(f"ERROR: {e}")
    pause()
    return vault

def cmd_recovery_create(vault, vault_path):
    clear_screen()
    print("=== Create Recovery Kit ===\n")
    vault = require_unlocked(vault, vault_path)
    if not vault:
        return None
    try:
        k = int(input("Threshold [3]: ").strip() or 3)
        n = int(input("Total shares [5]: ").strip() or 5)
    except:
        k, n = 3, 5
    out = input("Output file [recovery_kit.txt]: ").strip() or "recovery_kit.txt"
    try:
        shares = generate_recovery_shares(vault.recovery_key, k, n)
        kit = print_recovery_kit(shares, vault.vault_id, k)
        with open(out, 'w') as f:
            f.write(kit)
        print(f"\n✓ Saved to: {out}")
    except Exception as e:
        print(f"ERROR: {e}")
    pause()
    return vault

def cmd_recover(vault_path):
    """
    Recover vault using k-of-n Shamir shares and set new master password.
    """
    clear_screen()
    print("=== Recover Vault ===\n")
    
    # Check vault exists
    if not os.path.exists(vault_path):
        vault_path = choose_vault_path(vault_path)
        if not os.path.exists(vault_path):
            print(f"\nERROR: Vault not found at {vault_path}")
            pause()
            return None, vault_path
    
    print(f"Vault: {vault_path}\n")
    print("This will recover your vault using Shamir recovery shares.")
    print("You will need to enter at least k shares from your recovery kit.\n")
    
    # Get shares from user
    shares = []
    print("Enter recovery shares (one per line).")
    print("Each share is a list of words separated by spaces.")
    print("Press Enter on empty line when done.\n")
    
    share_num = 1
    while True:
        print(f"Share {share_num} (or press Enter to finish): ")
        share_input = input().strip()
        
        if not share_input:
            break
        
        # Split by whitespace to get individual words
        share_words = share_input.split()
        
        # shamir_mnemonic expects each share as a single string, not a list
        # Join the words back into a single space-separated string
        share_str = " ".join(share_words)
        shares.append(share_str)
        print(f"✓ Share {share_num} accepted ({len(share_words)} words)\n")
        share_num += 1
    
    if len(shares) < 2:
        print("\nERROR: Need at least 2 shares (typical recovery needs 3-5 shares)")
        pause()
        return None, vault_path
    
    print(f"\nYou provided {len(shares)} shares. Attempting recovery...")
    
    # Combine shares to recover key
    try:
        from securepwm.recovery import combine_recovery_shares
        recovery_key = combine_recovery_shares(shares)
        print("✓ Recovery key reconstructed from shares!\n")
    except Exception as e:
        print(f"\nERROR: Failed to combine shares: {e}")
        print("Make sure you entered valid shares from the same recovery kit.")
        pause()
        return None, vault_path
    
    # Get new master password
    print("Now set a NEW master password for this vault:")
    while True:
        pw = getpass.getpass("New master password: ")
        pw2 = getpass.getpass("Confirm new password: ")
        if pw != pw2:
            print("Passwords don't match. Try again.\n")
            continue
        if len(pw) < 8:
            print("Password too short (min 8 characters). Try again.\n")
            continue
        break
    
    # Perform recovery
    print("\nRecovering vault and re-encrypting with new password...")
    vault = Vault(vault_path)
    try:
        vault.recover_vault_with_shares(recovery_key, pw)
        print("\n" + "="*60)
        print("SUCCESS! Vault recovered and re-encrypted.")
        print("="*60)
        print("\nYour old master password is now invalid.")
        print("Use your NEW master password from now on.")
        print("\nIMPORTANT: Generate a NEW recovery kit with your new password!")
        pause()
        return vault, vault_path
    except Exception as e:
        print(f"\nERROR: Recovery failed: {e}")
        print("The recovery key may be invalid, or the vault may be corrupted.")
        pause()
        return None, vault_path
    
def cmd_lock(vault):
    clear_screen()
    print("=== Lock Vault ===\n")
    if vault:
        vault.lock()
        print("✓ Locked.")
    else:
        print("Not open.")
    pause()
    
def printMenu(vault, vault_path):
    print("SecurePWM - Interactive Menu")
    print("=" * 40)
    print(f"Vault: {vault_path}")
    print(f"Status: {'UNLOCKED' if vault else 'LOCKED'}")
    print("\n 1) Initialize vault")
    print(" 2) Add entry (manual)")
    print(" 3) Add entry (generated)")
    print(" 4) List entries")
    print(" 5) Get entry (view details)")
    print(" 6) Quick copy (copy password)")
    print(" 7) Search entries")
    print(" 8) Delete entry")
    print(" 9) Verify audit log")
    print("10) Create recovery kit")
    print("11) Recover vault")
    print("12) Change vault path")
    print("13) Lock vault")
    print(" 0) Exit")
    
def main_menu():
    vault = None
    vault_path = DEFAULT_VAULT_PATH
    while True:
        clear_screen()
        printMenu(vault,vault_path)
        c = input("\n> ").strip()
        if c == '1':
            vault, vault_path = cmd_init(vault_path)
        elif c == '2':
            vault = cmd_add_manual(vault, vault_path)
        elif c == '3':
            vault = cmd_add_generated(vault, vault_path)
        elif c == '4':
            vault = cmd_list_entries(vault, vault_path)
        elif c == '5':
            vault = cmd_get_entry(vault, vault_path)
        elif c == '6':
            vault = cmd_quick_copy(vault, vault_path)
        elif c == '7':
            vault = cmd_search(vault, vault_path)
        elif c == '8':
            vault = cmd_delete(vault, vault_path)
        elif c == '9':
            vault = cmd_verify(vault, vault_path)
        elif c == '10':
            vault = cmd_recovery_create(vault, vault_path)
        elif c == "11":
            vault, vault_path = cmd_recover(vault_path)
        elif c == '12':
            vault_path = choose_vault_path(vault_path)
            pause()
        elif c == '13':
            cmd_lock(vault)
            vault = None
        elif c == '0':
            if vault:
                vault.lock()
            print("\nGoodbye!")
            break

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)