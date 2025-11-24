"""
SecurePWM - Cryptography Module (Simplified Educational Version)

This single file contains ALL cryptographic operations for the password manager.
It's designed to be:
- Easy to understand and explain
- Minimal dependencies (only 'cryptography' library)
- Secure (production-grade algorithms)
- Clear (every function does one thing)

Security Architecture:
    1. Master Password → scrypt → Vault Key (32 bytes)
    2. Vault Key → HKDF → Subkeys (content, audit, recovery)
    3. Each entry gets unique random key → AES-GCM encryption
    4. Entry keys are wrapped (encrypted) with content key

Why this is secure:
    - scrypt is memory-hard (resists GPU attacks)
    - AES-256-GCM provides authenticated encryption (can't be tampered)
    - Each entry has unique key (limits damage if one leaks)
    - HMAC chain prevents audit log tampering
"""

import os
import hmac
import hashlib
import json
from typing import Dict, Tuple, Optional

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =============================================================================
# Configuration
# =============================================================================

VAULT_KEY_SIZE = 32      # 256-bit key
NONCE_SIZE = 12          # 96-bit nonce for AES-GCM
TAG_SIZE = 16            # 128-bit authentication tag

# scrypt parameters (tuned for ~250ms on modern CPU)
# N = CPU/memory cost (power of 2), r = block size, p = parallelization
SCRYPT_N = 2**17         # 131072 - uses ~16 MB RAM
SCRYPT_R = 8
SCRYPT_P = 1


# =============================================================================
# Key Derivation
# =============================================================================

def derive_vault_key(password: str, salt: bytes) -> bytes:
    """
    Derive vault key from master password using scrypt.

    Why scrypt?
    - Memory-hard: Requires lots of RAM, expensive for attackers with GPUs
    - Standard: Well-tested, used by many password managers

    Args:
        password: Master password (user's secret)
        salt: 16-byte random salt (stored in database, NOT secret)

    Returns:
        32-byte vault key
    """
    kdf = Scrypt(
        salt=salt,
        length=VAULT_KEY_SIZE,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode('utf-8'))


def derive_subkeys(vault_key: bytes) -> Dict[str, bytes]:
    """
    Derive multiple subkeys from vault key using HKDF.

    Why HKDF?
    - Creates cryptographically independent keys from one master key
    - 'info' parameter provides domain separation (each key for different purpose)

    Returns:
        Dictionary with:
        - content_key: For encrypting entry keys
        - audit_key: For audit log HMACs
        - recovery_key: For recovery shares
        - label_key: For searchable metadata hashing
    """
    def hkdf(info: str) -> bytes:
        """Helper: derive one subkey with given info string."""
        h = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info.encode('utf-8')
        )
        return h.derive(vault_key)

    return {
        'content_key': hkdf('spwm-content-v1'),
        'audit_key': hkdf('spwm-audit-v1'),
        'recovery_key': hkdf('spwm-recovery-v1'),
        'label_key': hkdf('spwm-label-v1'),
    }


# =============================================================================
# Canonical Associated Data
# =============================================================================

def canonical_ad(ad: dict) -> bytes:
    """
    Convert associated data to canonical JSON bytes (RFC 8785 style).

    Why canonical?
    - Same AD dict ALWAYS produces same bytes
    - Deterministic across platforms
    - Required for decryption to work

    Format:
    - Keys sorted lexicographically
    - No whitespace (compact)
    - UTF-8 encoding without escaping non-ASCII
    - separators=(",", ":") for compact JSON

    Args:
        ad: Dictionary with required fields (depends on context)

    Returns:
        UTF-8 encoded canonical JSON bytes
    """
    # Canonical JSON: sorted keys, compact, UTF-8
    json_str = json.dumps(ad, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return json_str.encode('utf-8')


# =============================================================================
# Encryption (AES-256-GCM)
# =============================================================================

def encrypt(key: bytes, plaintext: bytes, associated_data: dict) -> Tuple[bytes, bytes]:
    """
    Encrypt data with AES-256-GCM (Authenticated Encryption).

    AES-GCM provides:
    - Confidentiality: Plaintext is hidden
    - Authenticity: Any tampering is detected
    - Associated Data: Context is authenticated (prevents misuse)

    Args:
        key: 32-byte encryption key
        plaintext: Data to encrypt
        associated_data: Context dict (MUST include required fields per spec)

    Returns:
        (nonce, ciphertext) tuple
        - nonce: 12 random bytes (must be stored with ciphertext)
        - ciphertext: encrypted data + 16-byte tag
    """
    # Generate random nonce (NEVER reuse with same key!)
    nonce = os.urandom(NONCE_SIZE)

    # Convert associated data to canonical bytes
    ad_bytes = canonical_ad(associated_data)

    # Encrypt with AES-256-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, ad_bytes)

    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: dict) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.

    Args:
        key: Same 32-byte key used for encryption
        nonce: Same nonce used for encryption
        ciphertext: Encrypted data (includes tag)
        associated_data: MUST match encryption exactly, or decryption fails

    Returns:
        Plaintext bytes

    Raises:
        Exception: If tampered, wrong key, or wrong associated data
    """
    ad_bytes = canonical_ad(associated_data)

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, ad_bytes)

    return plaintext


# =============================================================================
# Vault Operations
# =============================================================================

def create_entry_key() -> bytes:
    """
    Generate a random key for one password entry.

    Why unique keys per entry?
    - If one key leaks, other entries are still safe
    - Can delete entries securely (destroy key)

    Returns:
        32-byte random key
    """
    return os.urandom(VAULT_KEY_SIZE)


def wrap_entry_key(
    content_key: bytes,
    entry_key: bytes,
    vault_id: str,
    entry_id: str,
    schema_version: int = 1,
    entry_version: int = 1
) -> Tuple[bytes, bytes]:
    """
    Encrypt (wrap) an entry key using the content key.

    This is "envelope encryption":
    - Entry key encrypts the actual password
    - Content key encrypts the entry key

    Associated Data (prevents context confusion):
    - ctx: "ke_wrap" (identifies this as key wrapping)
    - vault_id: Which vault this belongs to
    - entry_id: Which entry this key is for
    - aead: "aes256gcm" (algorithm used)
    - schema_version: Database schema version
    - entry_version: Entry version (for updates)

    Why full AD binding?
    - Prevents using wrapped key in wrong context
    - Detects if metadata changes
    - Binds to specific vault and entry

    Args:
        content_key: From derive_subkeys()
        entry_key: Random key for this entry
        vault_id: UUID of vault
        entry_id: UUID of entry
        schema_version: Current schema version
        entry_version: Entry version number

    Returns:
        (nonce, wrapped_key) - both must be stored in database
    """
    ad = {
        "ctx": "ke_wrap",
        "vault_id": vault_id,
        "entry_id": entry_id,
        "aead": "aes256gcm",
        "schema_version": schema_version,
        "entry_version": entry_version
    }
    return encrypt(content_key, entry_key, ad)


def unwrap_entry_key(
    content_key: bytes,
    nonce: bytes,
    wrapped_key: bytes,
    vault_id: str,
    entry_id: str,
    schema_version: int = 1,
    entry_version: int = 1
) -> bytes:
    """
    Decrypt (unwrap) an entry key.

    AD MUST match wrap exactly or decryption fails.

    Returns:
        32-byte entry key
    """
    ad = {
        "ctx": "ke_wrap",
        "vault_id": vault_id,
        "entry_id": entry_id,
        "aead": "aes256gcm",
        "schema_version": schema_version,
        "entry_version": entry_version
    }
    return decrypt(content_key, nonce, wrapped_key, ad)


def encrypt_entry_content(
    entry_key: bytes,
    content: bytes,
    vault_id: str,
    entry_id: str,
    created_at: int,
    updated_at: int,
    schema_version: int = 1,
    entry_version: int = 1,
    metadata: Optional[Dict[str, Optional[str]]] = None
) -> Tuple[bytes, bytes]:
    """
    Encrypt password/secret content for an entry.

    Associated Data (prevents rollback/tampering):
    - ctx: "entry_content"
    - vault_id, entry_id: Identity binding
    - aead: Algorithm identifier
    - schema_version, entry_version: Version binding
    - created_at, updated_at: Timestamp binding
    - metadata: Site name, username, URL, category (NEW - optional)

    Why include timestamps in AD?
    - Prevents rollback attacks (can't use old ciphertext)
    - Binds ciphertext to its metadata
    - Detects tampering with timestamps

    Why include metadata in AD? (SECURITY CRITICAL)
    - Metadata stored in plaintext DB (for search/list)
    - BUT metadata is authenticated via AD binding
    - If attacker changes "site_name" in DB, decryption fails
    - Prevents UI spoofing attack (showing wrong site for password)
    - User cannot be tricked into using password on wrong site

    Args:
        entry_key: Unwrapped entry key
        content: The actual secret (password, note, etc.)
        vault_id: UUID of vault
        entry_id: UUID of entry
        created_at: Creation timestamp (Unix seconds)
        updated_at: Last update timestamp (Unix seconds)
        schema_version: Current schema version
        entry_version: Entry version number
        metadata: Optional dict with site_name, username, url, category

    Returns:
        (nonce, ciphertext) to store in database
    """
    ad = {
        "ctx": "entry_content",
        "vault_id": vault_id,
        "entry_id": entry_id,
        "aead": "aes256gcm",
        "schema_version": schema_version,
        "entry_version": entry_version,
        "created_at": created_at,
        "updated_at": updated_at
    }

    # Include metadata in AD for tamper-proof authentication
    # Even though metadata is stored plaintext, it's cryptographically bound
    if metadata:
        ad["metadata"] = metadata

    return encrypt(entry_key, content, ad)


def decrypt_entry_content(
    entry_key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    vault_id: str,
    entry_id: str,
    created_at: int,
    updated_at: int,
    schema_version: int = 1,
    entry_version: int = 1,
    metadata: Optional[Dict[str, Optional[str]]] = None
) -> bytes:
    """
    Decrypt password/secret content.

    AD MUST match encrypt exactly (including metadata if present).

    SECURITY: If metadata was included during encryption, it MUST be
    provided here with exact same values, or decryption will fail.
    This prevents tampering with metadata in the database.

    Args:
        entry_key: Unwrapped entry key
        nonce: Nonce from encryption
        ciphertext: Encrypted content
        vault_id: UUID of vault
        entry_id: UUID of entry
        created_at: Creation timestamp (must match encryption)
        updated_at: Last update timestamp (must match encryption)
        schema_version: Schema version (must match encryption)
        entry_version: Entry version (must match encryption)
        metadata: Optional dict with site_name, username, url, category (must match encryption)

    Returns:
        Plaintext secret

    Raises:
        Exception: If AD doesn't match (includes metadata tampering)
    """
    ad = {
        "ctx": "entry_content",
        "vault_id": vault_id,
        "entry_id": entry_id,
        "aead": "aes256gcm",
        "schema_version": schema_version,
        "entry_version": entry_version,
        "created_at": created_at,
        "updated_at": updated_at
    }

    # Include metadata in AD (must match encryption exactly)
    if metadata:
        ad["metadata"] = metadata

    return decrypt(entry_key, nonce, ciphertext, ad)


# =============================================================================
# Audit Log
# =============================================================================

def compute_audit_mac(
    audit_key: bytes,
    seq: int,
    ts: int,
    action: str,
    prev_mac: Optional[bytes],
    payload: Optional[bytes] = None
) -> bytes:
    """
    Compute HMAC for an audit log entry with full binding.

    How it works:
    - Each entry's MAC includes the previous entry's MAC
    - Creates a chain: MAC1 → MAC2 → MAC3 → ...
    - Any tampering breaks the chain

    What's authenticated (prevents tampering):
    - seq: Sequence number (prevents reordering)
    - ts: Timestamp (prevents backdating)
    - action: What happened (prevents action changes)
    - payload_hash: Hash of encrypted payload if present
    - prev_mac: Previous MAC (creates chain)

    Why include timestamp and payload?
    - Timestamp: Prevents backdating/forward-dating attacks
    - Payload hash: Authenticates any associated data
    - Together: Full audit trail integrity

    Args:
        audit_key: From derive_subkeys()
        seq: Sequence number (1, 2, 3, ...)
        ts: Timestamp (Unix seconds)
        action: What happened (e.g., "ENTRY_ADD", "VAULT_UNLOCK")
        prev_mac: Previous entry's MAC (None for first entry)
        payload: Optional payload bytes to authenticate

    Returns:
        32-byte HMAC
    """
    # Compute payload hash if payload provided
    if payload:
        payload_hash = hashlib.sha256(payload).hexdigest()
    else:
        payload_hash = ""

    # Build message to authenticate (canonical JSON)
    message = {
        "seq": seq,
        "ts": ts,
        "action": action,
        "payload_hash": payload_hash,
        "prev_mac": prev_mac.hex() if prev_mac else ""
    }

    # Use canonical AD (same as AEAD operations)
    message_bytes = canonical_ad(message)

    # Compute HMAC-SHA256
    return hmac.new(audit_key, message_bytes, hashlib.sha256).digest()


def verify_audit_chain(audit_key: bytes, entries: list) -> bool:
    """
    Verify audit log hasn't been tampered with.

    Args:
        audit_key: From derive_subkeys()
        entries: List of dicts with keys: seq, ts, action, payload, mac, prev_mac

    Returns:
        True if chain is valid, False if tampered
    """
    prev_mac = None

    for entry in entries:
        # Recompute MAC
        expected_mac = compute_audit_mac(
            audit_key,
            entry["seq"],
            entry["ts"],
            entry["action"],
            prev_mac,
            entry.get("payload")
        )

        # Check if it matches stored MAC (constant-time comparison)
        if not hmac.compare_digest(expected_mac, entry["mac"]):
            return False  # Tampered!

        prev_mac = entry["mac"]

    return True


# =============================================================================
# Password Generation
# =============================================================================

def generate_password(length: int = 20, use_symbols: bool = True) -> str:
    """
    Generate a strong random password.

    Character sets:
    - Uppercase: A-Z (26)
    - Lowercase: a-z (26)
    - Digits: 0-9 (10)
    - Symbols: !@#$%^&*()_+-= (optional, 14)

    Args:
        length: Password length (default 20)
        use_symbols: Include symbols?

    Returns:
        Random password string
    """
    import string

    chars = string.ascii_letters + string.digits
    if use_symbols:
        chars += "!@#$%^&*()_+-="

    # Use cryptographically secure random
    # secrets.choice() uses os.urandom()
    import secrets
    return ''.join(secrets.choice(chars) for _ in range(length))


# =============================================================================
# Label Hashing
# =============================================================================

def hash_label(label_key: bytes, label: str) -> bytes:
    """
    Create HMAC hash of metadata label for exact-match searching.

    Allows constant-time exact search without exposing plaintext.
    Used alongside plaintext storage for fuzzy search capability.

    Args:
        label_key: Derived from vault key (label_key subkey)
        label: Username, site name, or other searchable field

    Returns:
        32-byte HMAC-SHA256 hash
    """
    return hmac.new(label_key, label.lower().encode('utf-8'), hashlib.sha256).digest()


# =============================================================================
# Helpers
# =============================================================================

def constant_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time.

    Why?
    - Normal comparison (a == b) returns False immediately on first mismatch
    - Attacker can measure time to learn how many bytes matched
    - This always takes same time regardless of where mismatch is

    Uses built-in hmac.compare_digest (constant-time).
    """
    return hmac.compare_digest(a, b)
