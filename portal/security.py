#!/usr/bin/env python3
"""
security.py

Password policy, password hashing, TOTP handling and recovery codes.

Passwords are hashed with Argon2id and never stored or logged in clear.
The TOTP shared secret is treated like a customer credential and kept
encrypted at rest, because a stolen database would otherwise hand over the
second factor together with the first.
"""

import hmac
import re
import secrets
import string
import unicodedata
from datetime import datetime

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from portal import crypto

# Argon2id with parameters that stay well under a second on a small VM.
_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2,
                         hash_len=32, salt_len=16)

SPECIALS = "!@#$%^&*()-_=+[]{};:,.<>/?|~"

# Passwords that pass the character classes but are still worthless.
FORBIDDEN_PATTERNS = (
    "password", "passwort", "kennwort", "welcome", "willkommen", "qwertz",
    "qwerty", "azerty", "123456", "abcdef", "admin", "administrator",
    "entra", "azure", "microsoft", "bebamu", "monitor", "sommer", "winter",
)


class PolicyError(ValueError):
    """Raised when a proposed password violates the policy."""


def normalize(value):
    """Normalise unicode so visually identical inputs compare equal."""
    return unicodedata.normalize("NFKC", value or "")


def check_password_policy(password, min_length=12, username="", display_name=""):
    """
    Validate a password and return the list of violations, empty when fine.

    Rules: length, all four character classes, no whitespace at the edges,
    no repetition of the account name, no obvious dictionary stem, and no
    single character repeated more than three times in a row.
    """
    password = normalize(password)
    problems = []

    if len(password) < min_length:
        problems.append("mindestens %d Zeichen" % min_length)
    if len(password) > 128:
        problems.append("höchstens 128 Zeichen")
    if not re.search(r"[A-Z\u00c4\u00d6\u00dc]", password):
        problems.append("mindestens ein Grossbuchstabe")
    if not re.search(r"[a-z\u00e4\u00f6\u00fc\u00df]", password):
        problems.append("mindestens ein Kleinbuchstabe")
    if not re.search(r"[0-9]", password):
        problems.append("mindestens eine Ziffer")
    if not any(ch in SPECIALS for ch in password):
        problems.append("mindestens ein Sonderzeichen aus %s" % SPECIALS)
    if password != password.strip():
        problems.append("keine Leerzeichen am Anfang oder Ende")
    if re.search(r"(.)\1{3,}", password):
        problems.append("kein Zeichen mehr als dreimal hintereinander")

    lowered = password.lower()
    for name in (username, display_name):
        if name and len(name) >= 3 and name.lower() in lowered:
            problems.append("darf den Benutzernamen nicht enthalten")
            break
    for stem in FORBIDDEN_PATTERNS:
        if stem in lowered:
            problems.append("darf kein leicht erratbares Wort enthalten (%s)" % stem)
            break
    return problems


def assert_password_policy(password, min_length=12, username="", display_name=""):
    """Raise PolicyError with a readable message when the password is too weak."""
    problems = check_password_policy(password, min_length, username, display_name)
    if problems:
        raise PolicyError("Passwort erfüllt die Vorgaben nicht: " + ", ".join(problems))


def hash_password(password):
    """Return the Argon2id hash of a password."""
    return _hasher.hash(normalize(password))


def verify_password(stored_hash, password):
    """Constant time password check; False on any mismatch or broken hash."""
    if not stored_hash:
        return False
    try:
        return _hasher.verify(stored_hash, normalize(password))
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


# Einmalig beim Import, damit dummy_verify nur noch prueft und nicht hasht.
_DUMMY_HASH = _hasher.hash("dummy password for timing equalisation")


def dummy_verify(password):
    """
    Burn the same time a real password check costs, for a missing account.

    The login must not answer faster for an unknown user than for a known one
    with a wrong password, otherwise the response time reveals which usernames
    exist. Hashing a throwaway value per attempt would overshoot: it costs a
    hash on top of the verify, so the unknown user became measurably slower
    instead, and every sprayed random name cost double the CPU. The reference
    hash is therefore computed once at import, with the parameters in use.
    """
    return verify_password(_DUMMY_HASH, password)


def needs_rehash(stored_hash):
    """True when the hash was produced with weaker parameters than the current ones."""
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except (InvalidHashError, ValueError):
        return True


def suggest_password(length=20):
    """Generate a policy compliant password for handing out a new account."""
    alphabet = string.ascii_letters + string.digits + SPECIALS
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if not check_password_policy(candidate, min_length=12):
            return candidate


# --------------------------------------------------------------------------
# Second factor
# --------------------------------------------------------------------------

def new_totp_secret():
    """Return a fresh base32 TOTP secret."""
    return pyotp.random_base32()


def totp_uri(secret, username, issuer):
    """Build the otpauth:// URI an authenticator app scans."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret, code, last_counter=0):
    """
    Validate a six digit code with one step of clock tolerance.

    Returns (ok, counter). The counter is stored on the user so the same
    code cannot be replayed within its validity window.
    """
    code = re.sub(r"\D", "", code or "")
    if len(code) != 6 or not secret:
        return False, last_counter
    totp = pyotp.TOTP(secret)
    now = totp.timecode(datetime.now())
    for offset in (0, -1, 1):
        counter = now + offset
        if hmac.compare_digest(totp.generate_otp(counter), code):
            if counter <= (last_counter or 0):
                return False, last_counter
            return True, counter
    return False, last_counter


def new_recovery_codes(count=8):
    """Generate readable single use recovery codes."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(alphabet) for _ in range(12))
        codes.append("%s-%s-%s" % (raw[:4], raw[4:8], raw[8:]))
    return codes


def hash_recovery_code(code):
    """Hash a recovery code with the same Argon2 parameters as a password."""
    return _hasher.hash(normalize(code).upper().replace(" ", ""))


def verify_recovery_code(stored_hash, code):
    """Check one recovery code against its stored hash."""
    try:
        return _hasher.verify(stored_hash, normalize(code).upper().replace(" ", ""))
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def encrypt_totp_secret(secret, key, username):
    """Encrypt the TOTP secret, bound to the account it belongs to."""
    return crypto.encrypt(secret, key, crypto.aad_for("user", username, "totp_secret_enc"))


def decrypt_totp_secret(stored, key, username):
    """Decrypt the stored TOTP secret of one account."""
    return crypto.decrypt(stored, key, crypto.aad_for("user", username, "totp_secret_enc"))
