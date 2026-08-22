#!/usr/bin/env python3
"""
crypto.py

Envelope encryption for everything the portal must be able to read back:
client secrets and private keys of the monitored customers.

AES-256-GCM with a random 12 byte nonce per value. The master key never
leaves the environment, the ciphertext lives in the database. Nothing here
is used for user passwords, those are hashed and never decrypted.
"""

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "v1"
NONCE_BYTES = 12
DOMAIN = b"entra-secret-portal"


def aad_for(kind, identity, column):
    """
    Build the associated data for one stored value.

    Binding table, record and column into the AAD means a ciphertext cannot be
    moved between customers or between columns by anyone with write access to
    the database: the authentication tag stops verifying.
    """
    return b"|".join([DOMAIN, str(kind).encode(), str(identity).encode(),
                      str(column).encode()])


class CryptoError(RuntimeError):
    """Raised when a stored value cannot be decrypted with the current key."""


def generate_master_key():
    """Return a fresh base64 encoded 32 byte master key for PORTAL_ENCRYPTION_KEY."""
    return base64.b64encode(os.urandom(32)).decode()


def encrypt(plaintext, key, aad=DOMAIN):
    """
    Encrypt a string and return 'v1:<nonce>:<ciphertext>' in base64url.

    The associated data binds the ciphertext to this application so a value
    copied into another AES-GCM context fails to authenticate.
    """
    if plaintext is None or plaintext == "":
        return ""
    nonce = os.urandom(NONCE_BYTES)
    raw = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return "%s:%s:%s" % (PREFIX,
                         base64.urlsafe_b64encode(nonce).decode().rstrip("="),
                         base64.urlsafe_b64encode(raw).decode().rstrip("="))


def _b64decode(value):
    """Decode base64url without padding."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def decrypt(stored, key, aad=DOMAIN):
    """Reverse encrypt(); raises CryptoError on a wrong key or tampered value."""
    if not stored:
        return ""
    try:
        prefix, nonce_b64, cipher_b64 = stored.split(":", 2)
    except ValueError as exc:
        raise CryptoError("Gespeicherter Wert hat kein gültiges Format") from exc
    if prefix != PREFIX:
        raise CryptoError("Unbekannte Verschlüsselungsversion '%s'" % prefix)
    try:
        plain = AESGCM(key).decrypt(_b64decode(nonce_b64), _b64decode(cipher_b64), aad)
    except InvalidTag as exc:
        raise CryptoError("Entschlüsselung fehlgeschlagen: falscher PORTAL_ENCRYPTION_KEY "
                          "oder veränderter Datensatz") from exc
    except Exception as exc:                              # noqa: BLE001
        raise CryptoError("Entschlüsselung fehlgeschlagen: %s" % exc) from exc
    return plain.decode("utf-8")


def mask(value, keep=4):
    """Return a display safe fingerprint of a secret, never the secret itself."""
    if not value:
        return ""
    if len(value) <= keep:
        return "*" * len(value)
    return "*" * (len(value) - keep) + value[-keep:]
