"""
SecurePWM - Zero-Knowledge Password Manager (Simplified Educational Version)

A minimal, understandable, and secure password manager for learning purposes.

Key Features:
- Zero-knowledge: All encryption happens locally
- Strong crypto: AES-256-GCM + scrypt + HKDF
- Tamper detection: HMAC-chained audit log
- Recovery: k-of-n Shamir Secret Sharing
- Simple: ~1000 lines total, easy to understand

Components:
- crypto.py: All cryptographic operations (one file!)
- vault.py: SQLite database and vault operations
- recovery.py: Shamir Secret Sharing for disaster recovery
- cli.py: Command-line interface (uses built-in argparse)

Usage:
    python -m securepwm.cli init                    # Create vault
    python -m securepwm.cli add --generate          # Add password
    python -m securepwm.cli list                    # List entries
    python -m securepwm.cli get <id>                # Get password
    python -m securepwm.cli verify                  # Check integrity
    python -m securepwm.cli recovery-create         # Create recovery kit
"""

__version__ = "0.2.0-simplified"
__author__ = "SecurePWM Team"
