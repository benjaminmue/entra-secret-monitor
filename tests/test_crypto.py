"""
Tests for portal/crypto.py: envelope encryption of customer credentials.

This module protects the only values the portal must be able to read back,
client secrets and private keys. Its promises are that a wrong key fails loudly,
a tampered record fails loudly, and a ciphertext cannot be moved between
customers or columns by anyone with write access to the database.
"""
import base64
import unittest

from .support import needs_portal

try:
    from portal import crypto
except ImportError:                     # ohne die Extras uebernimmt needs_portal
    crypto = None


@needs_portal
class MasterKeyTest(unittest.TestCase):
    def test_key_is_32_bytes_of_base64(self):
        raw = base64.b64decode(crypto.generate_master_key())
        self.assertEqual(32, len(raw))

    def test_two_keys_differ(self):
        self.assertNotEqual(crypto.generate_master_key(), crypto.generate_master_key())


@needs_portal
class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = base64.b64decode(crypto.generate_master_key())

    def test_value_survives_encryption_and_decryption(self):
        secret = "ein Client Secret mit Umlauten: äöü"
        self.assertEqual(secret,
                         crypto.decrypt(crypto.encrypt(secret, self.key), self.key))

    def test_ciphertext_does_not_contain_the_plaintext(self):
        stored = crypto.encrypt("streng-geheim", self.key)
        self.assertNotIn("streng-geheim", stored)

    def test_stored_format_is_versioned(self):
        stored = crypto.encrypt("wert", self.key)
        self.assertTrue(stored.startswith(crypto.PREFIX + ":"))
        self.assertEqual(3, len(stored.split(":")))

    def test_empty_values_stay_empty_in_both_directions(self):
        self.assertEqual("", crypto.encrypt("", self.key))
        self.assertEqual("", crypto.encrypt(None, self.key))
        self.assertEqual("", crypto.decrypt("", self.key))
        self.assertEqual("", crypto.decrypt(None, self.key))

    def test_each_encryption_uses_a_fresh_nonce(self):
        # Reusing a nonce under AES-GCM breaks confidentiality outright, so
        # encrypting the same value twice must not produce the same record.
        first = crypto.encrypt("derselbe Wert", self.key)
        second = crypto.encrypt("derselbe Wert", self.key)
        self.assertNotEqual(first, second)
        self.assertNotEqual(first.split(":")[1], second.split(":")[1])
        self.assertEqual("derselbe Wert", crypto.decrypt(second, self.key))


@needs_portal
class FailureTest(unittest.TestCase):
    """Every failure must raise rather than return something usable."""

    def setUp(self):
        self.key = base64.b64decode(crypto.generate_master_key())
        self.other_key = base64.b64decode(crypto.generate_master_key())
        self.stored = crypto.encrypt("geheim", self.key)

    def test_wrong_key_is_refused(self):
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt(self.stored, self.other_key)

    def test_tampered_ciphertext_is_refused(self):
        prefix, nonce, cipher = self.stored.split(":", 2)
        broken = "%s:%s:%s" % (prefix, nonce, cipher[:-4] + "AAAA")
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt(broken, self.key)

    def test_tampered_nonce_is_refused(self):
        prefix, nonce, cipher = self.stored.split(":", 2)
        broken = "%s:%s:%s" % (prefix, "A" * len(nonce), cipher)
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt(broken, self.key)

    def test_malformed_record_is_refused(self):
        for value in ("kein-doppelpunkt", "v1:nur-zwei-teile"):
            with self.assertRaises(crypto.CryptoError, msg=value):
                crypto.decrypt(value, self.key)

    def test_unknown_version_is_refused(self):
        _, nonce, cipher = self.stored.split(":", 2)
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt("v99:%s:%s" % (nonce, cipher), self.key)

    def test_the_error_never_carries_the_plaintext(self):
        try:
            crypto.decrypt(self.stored, self.other_key)
        except crypto.CryptoError as exc:
            self.assertNotIn("geheim", str(exc))


@needs_portal
class AssociatedDataTest(unittest.TestCase):
    """
    The AAD binds a record to its table, row and column.

    Without it, anyone able to write to the database could copy a customer's
    encrypted secret into another customer's row and have the portal
    authenticate against the wrong tenant with it.
    """

    def setUp(self):
        self.key = base64.b64decode(crypto.generate_master_key())

    def test_aad_is_deterministic(self):
        self.assertEqual(crypto.aad_for("customer", 1, "client_secret"),
                         crypto.aad_for("customer", 1, "client_secret"))

    def test_aad_differs_per_record_and_column(self):
        base = crypto.aad_for("customer", 1, "client_secret")
        self.assertNotEqual(base, crypto.aad_for("customer", 2, "client_secret"))
        self.assertNotEqual(base, crypto.aad_for("customer", 1, "key_pem"))
        self.assertNotEqual(base, crypto.aad_for("user", 1, "client_secret"))

    def test_a_record_cannot_be_moved_to_another_customer(self):
        stored = crypto.encrypt("secret von Kunde 1", self.key,
                                crypto.aad_for("customer", 1, "client_secret"))
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt(stored, self.key,
                           crypto.aad_for("customer", 2, "client_secret"))

    def test_a_record_cannot_be_moved_to_another_column(self):
        stored = crypto.encrypt("secret", self.key,
                                crypto.aad_for("customer", 1, "client_secret"))
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt(stored, self.key, crypto.aad_for("customer", 1, "key_pem"))

    def test_matching_associated_data_still_decrypts(self):
        aad = crypto.aad_for("customer", 7, "client_secret")
        self.assertEqual("secret",
                         crypto.decrypt(crypto.encrypt("secret", self.key, aad),
                                        self.key, aad))


@needs_portal
class MaskTest(unittest.TestCase):
    def test_only_the_last_characters_remain(self):
        self.assertEqual("*" * 12 + "cdef", crypto.mask("0123456789abcdef", keep=4))

    def test_short_values_are_masked_entirely(self):
        # Keeping a tail of a value no longer than the tail would show all of it.
        self.assertEqual("***", crypto.mask("abc", keep=4))
        self.assertNotIn("abc", crypto.mask("abc", keep=4))

    def test_empty_value_stays_empty(self):
        self.assertEqual("", crypto.mask(""))
        self.assertEqual("", crypto.mask(None))

    def test_the_secret_itself_never_appears(self):
        secret = "sehr-langes-client-secret-1234"
        self.assertNotIn(secret, crypto.mask(secret))


if __name__ == "__main__":
    unittest.main()
