"""
SecurePWM - Vault Module (Simplified)

This file handles:
- SQLite database (stores encrypted data)
- Vault initialization
- Adding/retrieving/deleting entries
- Audit logging

Database structure:
- vault_meta: Vault configuration (salt, creation time)
- entries: Encrypted password entries
- audit_log: Tamper-evident log of all operations
"""

import sqlite3
import os
import time
import uuid
import json
from typing import Optional, List, Dict

from . import crypto


# =============================================================================
# DATABASE SCHEMA (Per docs/data-model.md)
# =============================================================================

SCHEMA = """
-- Vault state (crypto parameters and versioning) - one row
CREATE TABLE IF NOT EXISTS vault_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    vault_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1,
    kdf TEXT NOT NULL,                -- "scrypt"
    kdf_params TEXT NOT NULL,         -- JSON: {"N": 131072, "r": 8, "p": 1, "dkLen": 32}
    kdf_salt BLOB NOT NULL,           -- 16-32 bytes random
    aead_algo TEXT NOT NULL,          -- "aes256gcm"
    created_at INTEGER NOT NULL,
    last_unlock_at INTEGER
);

-- Password entries (hybrid: plaintext + hashes + AD binding)
CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 1,
    -- Metadata (plaintext for fuzzy search + AD binding for tamper protection)
    username TEXT NOT NULL,        -- Required: account identifier
    site_name TEXT,                 -- Optional: service name (GitHub, Gmail, etc.)
    url TEXT,                       -- Optional: full URL
    category TEXT,                  -- Optional: Work, Personal, Banking, etc.
    -- HMAC hashes (for constant-time exact search)
    username_hash BLOB NOT NULL,    -- HMAC(label_key, username)
    site_name_hash BLOB,            -- HMAC(label_key, site_name) if present
    -- Entry key (wrapped/encrypted)
    key_nonce BLOB NOT NULL,
    key_wrapped BLOB NOT NULL,
    -- Content (encrypted with AD binding to prevent metadata tampering)
    content_nonce BLOB NOT NULL,
    content_ciphertext BLOB NOT NULL,
    -- Timestamps
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_entries_username_hash ON entries(username_hash);
CREATE INDEX IF NOT EXISTS idx_entries_site_hash ON entries(site_name_hash);

-- Audit log (tamper-evident chain with full binding)
CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    action TEXT NOT NULL,
    payload BLOB,
    prev_mac BLOB,
    mac BLOB NOT NULL
);
"""

# SQLite PRAGMAs for crash safety and integrity (per docs/data-model.md)
PRAGMAS = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
PRAGMA secure_delete=ON;
"""


# =============================================================================
# VAULT CLASS
# =============================================================================

class Vault:
    """
    Main vault class - handles all password management operations.

    Usage:
        # Create new vault
        vault = Vault("my_vault.db")
        vault.initialize("master_password")

        # Later: unlock vault
        vault = Vault("my_vault.db")
        vault.unlock("master_password")

        # Add entry
        entry_id = vault.add_entry(b"my_secret_password")

        # Retrieve entry
        secret = vault.get_entry(entry_id)

        # Lock when done
        vault.lock()
    """

    def __init__(self, db_path: str):
        """
        Initialize vault (doesn't unlock it yet).

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self.vault_id: Optional[str] = None
        self.salt: Optional[bytes] = None
        self.schema_version: int = 1
        self.kdf_params: Optional[dict] = None
        self.aead_algo: str = "aes256gcm"

        # Keys (only present when unlocked)
        self.vault_key: Optional[bytes] = None
        self.content_key: Optional[bytes] = None
        self.audit_key: Optional[bytes] = None
        self.recovery_key: Optional[bytes] = None
        self.label_key: Optional[bytes] = None

    def initialize(self, master_password: str) -> str:
        """
        Create a new vault with master password.

        This:
        1. Creates database with crash-safety PRAGMAs
        2. Generates random salt
        3. Stores KDF and AEAD parameters
        4. Derives keys from master password
        5. Records initialization in audit log

        Args:
            master_password: User's master password

        Returns:
            Vault ID (UUID)
        """
        # Connect to database
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # Access columns by name

        # Apply PRAGMAs for crash safety and integrity
        self.conn.executescript(PRAGMAS)

        # Create tables
        self.conn.executescript(SCHEMA)

        # Generate salt and vault ID
        self.salt = os.urandom(16)
        self.vault_id = str(uuid.uuid4())
        self.schema_version = 1
        self.aead_algo = "aes256gcm"

        # Store KDF parameters (from crypto module defaults)
        self.kdf_params = {
            "N": crypto.SCRYPT_N,
            "r": crypto.SCRYPT_R,
            "p": crypto.SCRYPT_P,
            "dkLen": 32
        }

        # Save vault state with crypto parameters
        self.conn.execute(
            """INSERT INTO vault_state
               (id, vault_id, schema_version, kdf, kdf_params, kdf_salt, aead_algo, created_at)
               VALUES (1, ?, ?, ?, ?, ?, ?, ?)""",
            (self.vault_id, self.schema_version, "scrypt",
             json.dumps(self.kdf_params), self.salt, self.aead_algo, int(time.time()))
        )
        self.conn.commit()

        # Derive keys
        self._derive_keys(master_password)

        # Log initialization
        self._audit("VAULT_INIT")

        return self.vault_id

    def unlock(self, master_password: str) -> None:
        """
        Unlock existing vault with master password.

        Loads vault state including crypto parameters and uses them
        to derive keys. Updates last_unlock_at timestamp.

        Args:
            master_password: User's master password

        Raises:
            Exception: If password is wrong (decryption will fail later)
        """
        # Connect to database
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row

        # Apply PRAGMAs
        self.conn.executescript(PRAGMAS)

        # Load vault state (includes crypto parameters)
        row = self.conn.execute("SELECT * FROM vault_state WHERE id = 1").fetchone()
        if not row:
            raise Exception("Vault not initialized")

        self.vault_id = row['vault_id']
        self.salt = row['kdf_salt']
        self.schema_version = row['schema_version']
        self.aead_algo = row['aead_algo']
        self.kdf_params = json.loads(row['kdf_params'])

        # Derive keys using stored parameters
        self._derive_keys(master_password)

        # Update last unlock timestamp
        self.conn.execute(
            "UPDATE vault_state SET last_unlock_at = ? WHERE id = 1",
            (int(time.time()),)
        )
        self.conn.commit()

        # Log unlock
        self._audit("VAULT_UNLOCK")

    def lock(self) -> None:
        """Lock vault and clear keys from memory."""
        self.vault_key = None
        self.content_key = None
        self.audit_key = None
        self.recovery_key = None
        self.label_key = None
        if self.conn:
            self.conn.close()
            self.conn = None

    def add_entry(
        self,
        secret: bytes,
        username: str,
        site_name: Optional[str] = None,
        url: Optional[str] = None,
        category: Optional[str] = None
    ) -> str:
        """
        Add password entry (hybrid: plaintext + hashes + AD binding).

        SECURITY:
        - Plaintext metadata stored for fuzzy search
        - HMAC hashes for constant-time exact search
        - Metadata bound in AD to prevent tampering

        Args:
            secret: Password/secret to store
            username: Account username/email (REQUIRED)
            site_name: Service name (optional, e.g. "GitHub")
            url: Full URL (optional)
            category: Category tag (optional, e.g. "Work")

        Returns:
            Entry ID (UUID)
        """
        self._require_unlocked()
        if not username or not username.strip():
            raise ValueError("Username is required")

        entry_id = str(uuid.uuid4())
        entry_key = crypto.create_entry_key()
        entry_version = 1
        now = int(time.time())

        # Compute HMAC hashes for exact search
        username_hash = crypto.hash_label(self.label_key, username)
        site_name_hash = crypto.hash_label(self.label_key, site_name) if site_name else None

        # Build metadata dict for AD binding (tamper protection)
        metadata = {"username": username}
        if site_name:
            metadata["site_name"] = site_name
        if url:
            metadata["url"] = url
        if category:
            metadata["category"] = category

        # Encrypt with metadata in AD (prevents metadata tampering)
        content_nonce, content_ct = crypto.encrypt_entry_content(
            entry_key, secret, self.vault_id, entry_id,
            now, now, self.schema_version, entry_version, metadata
        )

        key_nonce, key_wrapped = crypto.wrap_entry_key(
            self.content_key, entry_key, self.vault_id, entry_id,
            self.schema_version, entry_version
        )

        # Store: plaintext (fuzzy search) + hashes (exact search) + AD-bound ciphertext
        self.conn.execute(
            """INSERT INTO entries (id, version, username, site_name, url, category,
                                   username_hash, site_name_hash,
                                   key_nonce, key_wrapped, content_nonce, content_ciphertext,
                                   created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (entry_id, entry_version, username, site_name, url, category,
             username_hash, site_name_hash,
             key_nonce, key_wrapped, content_nonce, content_ct, now, now)
        )
        self.conn.commit()
        self._audit("ENTRY_ADD")
        return entry_id

    def get_entry(self, entry_id: str) -> Dict:
        """
        Get entry with AD-verified decryption (hybrid security).

        SECURITY: Metadata in AD binding - if tampered, decryption fails.

        Returns:
            Dict with id, secret, username, site_name, url, category, timestamps
        """
        self._require_unlocked()
        row = self.conn.execute(
            "SELECT * FROM entries WHERE id = ? AND deleted = 0", (entry_id,)
        ).fetchone()
        if not row:
            raise Exception(f"Entry {entry_id} not found")

        entry_key = crypto.unwrap_entry_key(
            self.content_key, row['key_nonce'], row['key_wrapped'],
            self.vault_id, entry_id, self.schema_version, row['version']
        )

        # Build metadata for AD verification (SECURITY: prevents tampering)
        metadata = {"username": row['username']}
        if row['site_name']:
            metadata["site_name"] = row['site_name']
        if row['url']:
            metadata["url"] = row['url']
        if row['category']:
            metadata["category"] = row['category']

        # Decrypt with AD binding - fails if metadata tampered
        secret = crypto.decrypt_entry_content(
            entry_key, row['content_nonce'], row['content_ciphertext'],
            self.vault_id, entry_id, row['created_at'], row['updated_at'],
            self.schema_version, row['version'], metadata
        )

        self._audit("ENTRY_GET")
        return {
            'id': entry_id,
            'secret': secret,
            'username': row['username'],
            'site_name': row['site_name'],
            'url': row['url'],
            'category': row['category'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at']
        }

    def list_entries(self) -> List[Dict]:
        """List entries (metadata only)."""
        self._require_unlocked()
        rows = self.conn.execute(
            """SELECT id, username, site_name, url, category, created_at, updated_at
               FROM entries WHERE deleted = 0
               ORDER BY username, site_name"""
        ).fetchall()
        return [dict(row) for row in rows]

    def search(self, query: str) -> List[Dict]:
        """
        Fuzzy search across username, site_name, url, category (4 fields).

        Uses SQL LIKE for partial matching (case-insensitive).
        """
        self._require_unlocked()
        if not query or not query.strip():
            return self.list_entries()

        pattern = f"%{query}%"
        rows = self.conn.execute(
            """SELECT id, username, site_name, url, category, created_at, updated_at
               FROM entries
               WHERE deleted = 0 AND (
                   LOWER(username) LIKE ? OR
                   LOWER(COALESCE(site_name, '')) LIKE ? OR
                   LOWER(COALESCE(url, '')) LIKE ? OR
                   LOWER(COALESCE(category, '')) LIKE ?)
               ORDER BY username, site_name""",
            (pattern.lower(), pattern.lower(), pattern.lower(), pattern.lower())
        ).fetchall()
        return [dict(row) for row in rows]

    def search_exact(self, username: str = None, site_name: str = None) -> List[Dict]:
        """Exact search using HMAC hashes (constant-time, no fuzzy)."""
        self._require_unlocked()
        if username:
            h = crypto.hash_label(self.label_key, username)
            rows = self.conn.execute(
                """SELECT id, username, site_name, url, category, created_at, updated_at
                   FROM entries WHERE username_hash = ? AND deleted = 0""",
                (h,)
            ).fetchall()
        elif site_name:
            h = crypto.hash_label(self.label_key, site_name)
            rows = self.conn.execute(
                """SELECT id, username, site_name, url, category, created_at, updated_at
                   FROM entries WHERE site_name_hash = ? AND deleted = 0""",
                (h,)
            ).fetchall()
        else:
            return []
        return [dict(row) for row in rows]

    def delete_entry(self, entry_id: str, hard: bool = False) -> None:
        """
        Delete an entry.

        Args:
            entry_id: UUID of entry to delete
            hard: If True, permanently delete. If False, mark as deleted.
        """
        self._require_unlocked()

        if hard:
            self.conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
            self._audit("ENTRY_HARD_DELETE")
        else:
            self.conn.execute(
                "UPDATE entries SET deleted = 1 WHERE id = ?",
                (entry_id,)
            )
            self._audit("ENTRY_DELETE")

        self.conn.commit()

    def verify_audit_log(self) -> bool:
        """
        Verify audit log hasn't been tampered with.

        Returns:
            True if log is valid, False if tampered
        """
        self._require_unlocked()

        # Load all audit entries (including ts and payload for new MAC verification)
        rows = self.conn.execute(
            "SELECT seq, ts, action, payload, prev_mac, mac FROM audit_log ORDER BY seq"
        ).fetchall()

        entries = [dict(row) for row in rows]

        return crypto.verify_audit_chain(self.audit_key, entries)

    # =========================================================================
    # INTERNAL HELPERS
    # =========================================================================

    def _derive_keys(self, master_password: str) -> None:
        """Derive all keys from master password."""
        self.vault_key = crypto.derive_vault_key(master_password, self.salt)
        subkeys = crypto.derive_subkeys(self.vault_key)
        self.content_key = subkeys['content_key']
        self.audit_key = subkeys['audit_key']
        self.recovery_key = subkeys['recovery_key']
        self.label_key = subkeys['label_key']

    def _audit(self, action: str, payload: Optional[bytes] = None) -> None:
        """
        Add entry to audit log with full binding.

        CRITICAL FIX: Now selects BOTH seq and mac from previous entry.
        Also includes timestamp and payload in MAC computation per spec.

        Args:
            action: Action identifier (e.g., "VAULT_INIT", "ENTRY_ADD")
            payload: Optional payload bytes to authenticate
        """
        # Get previous entry (MUST select both seq and mac!)
        prev_row = self.conn.execute(
            "SELECT seq, mac FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()

        # Compute next sequence number
        if prev_row:
            prev_mac = prev_row['mac']
            seq = prev_row['seq'] + 1
        else:
            prev_mac = None
            seq = 1

        # Current timestamp
        ts = int(time.time())

        # Compute new MAC with full binding (seq, ts, action, payload, prev_mac)
        mac = crypto.compute_audit_mac(self.audit_key, seq, ts, action, prev_mac, payload)

        # Store in audit log (using 'ts' column name per new schema)
        self.conn.execute(
            "INSERT INTO audit_log (ts, action, payload, prev_mac, mac) VALUES (?, ?, ?, ?, ?)",
            (ts, action, payload, prev_mac, mac)
        )
        self.conn.commit()
    
    def recover_vault_with_shares(self, recovery_key: bytes, new_master_password: str):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(PRAGMAS)
        
         # Verify recovery key is correct by checking audit log
        try:
            if not self.verify_audit_log():
                raise Exception("Recovery key invalid: audit log verification failed")
        except Exception as e:
            raise Exception(f"Recovery key invalid or vault corrupted: {e}")
        
        # Recovery key is valid! Now re-key the vault with new master password
        print("\n✓ Recovery key verified. Re-encrypting vault with new master password...")
        
        # 1. Decrypt all entries with old keys
        entries_data = []
        rows = self.conn.execute(
            """SELECT id, version, username, site_name, url, category,
                    key_nonce, key_wrapped, content_nonce, content_ciphertext,
                    created_at, updated_at, deleted
            FROM entries"""
        ).fetchall()
        
        for row in rows:
            try:
                # Unwrap entry key with old content_key
                entry_key = crypto.unwrap_entry_key(
                    self.content_key, row['key_nonce'], row['key_wrapped'],
                    self.vault_id, row['id'], self.schema_version, row['version']
                )
                
                # Build metadata for AD
                metadata = {"username": row['username']}
                if row['site_name']:
                    metadata["site_name"] = row['site_name']
                if row['url']:
                    metadata["url"] = row['url']
                if row['category']:
                    metadata["category"] = row['category']
                
                # Decrypt content with old entry_key
                secret = crypto.decrypt_entry_content(
                    entry_key, row['content_nonce'], row['content_ciphertext'],
                    self.vault_id, row['id'], row['created_at'], row['updated_at'],
                    self.schema_version, row['version'], metadata
                )
                
                # Store decrypted data
                entries_data.append({
                    'id': row['id'],
                    'version': row['version'],
                    'username': row['username'],
                    'site_name': row['site_name'],
                    'url': row['url'],
                    'category': row['category'],
                    'secret': secret,
                    'created_at': row['created_at'],
                    'updated_at': row['updated_at'],
                    'deleted': row['deleted']
                })
            except Exception as e:
                print(f"WARNING: Failed to decrypt entry {row['id']}: {e}")
                continue
        
        print(f"✓ Successfully decrypted {len(entries_data)} entries")
        
        # 2. Generate new salt and derive keys from new master password
        new_salt = os.urandom(16)
        new_vault_key = crypto.derive_vault_key(new_master_password, new_salt)
        new_subkeys = crypto.derive_subkeys(new_vault_key)
        
        # 3. Update vault state with new salt
        self.conn.execute(
            "UPDATE vault_state SET kdf_salt = ? WHERE id = 1",
            (new_salt,)
        )
        
        # 4. Re-encrypt all entries with new keys
        self.vault_key = new_vault_key
        self.content_key = new_subkeys['content_key']
        self.audit_key = new_subkeys['audit_key']
        self.recovery_key = new_subkeys['recovery_key']
        self.label_key = new_subkeys['label_key']
        self.salt = new_salt
        
        for entry_data in entries_data:
            # Generate new entry key
            new_entry_key = crypto.create_entry_key()
            
            # Build metadata
            metadata = {"username": entry_data['username']}
            if entry_data['site_name']:
                metadata["site_name"] = entry_data['site_name']
            if entry_data['url']:
                metadata["url"] = entry_data['url']
            if entry_data['category']:
                metadata["category"] = entry_data['category']
            
            # Re-encrypt content with new entry key
            content_nonce, content_ct = crypto.encrypt_entry_content(
                new_entry_key, entry_data['secret'],
                self.vault_id, entry_data['id'],
                entry_data['created_at'], entry_data['updated_at'],
                self.schema_version, entry_data['version'], metadata
            )
            
            # Wrap new entry key with new content key
            key_nonce, key_wrapped = crypto.wrap_entry_key(
                self.content_key, new_entry_key,
                self.vault_id, entry_data['id'],
                self.schema_version, entry_data['version']
            )
            
            # Update database
            self.conn.execute(
                """UPDATE entries SET 
                key_nonce = ?, key_wrapped = ?,
                content_nonce = ?, content_ciphertext = ?
                WHERE id = ?""",
                (key_nonce, key_wrapped, content_nonce, content_ct, entry_data['id'])
            )
        
        self.conn.commit()
        
        # 5. Log recovery in audit log
        self._audit("VAULT_RECOVERY", payload=b"master_password_reset")
        
        print(f"✓ Vault re-encrypted with new master password")
        print(f"✓ Recovery complete! You can now use your new master password.")
        
    def _require_unlocked(self) -> None:
        """Check that vault is unlocked."""
        if not self.conn or not self.vault_key:
            raise Exception("Vault is locked. Call unlock() first.")


# =============================================================================
# EXAMPLE USAGE
# =============================================================================

if __name__ == "__main__":
    # Create and use a vault
    vault = Vault("test_vault.db")

    # Initialize with master password
    print("Creating new vault...")
    vault_id = vault.initialize("MyMasterPassword123!")
    print(f"Vault created: {vault_id}")

    # Add some entries
    print("\nAdding entries...")
    id1 = vault.add_entry(b"my_github_password")
    id2 = vault.add_entry(b"my_email_password")
    print(f"Added entries: {id1}, {id2}")

    # List entries
    print("\nEntries:")
    for entry in vault.list_entries():
        print(f"  {entry['id']}")

    # Retrieve
    print("\nRetrieving entry...")
    secret = vault.get_entry(id1)
    print(f"Secret: {secret}")

    # Verify audit log
    print("\nVerifying audit log...")
    if vault.verify_audit_log():
        print("✓ Audit log is intact!")
    else:
        print("✗ Audit log has been tampered!")

    # Lock vault
    vault.lock()
    print("\nVault locked.")
