import os
import stat
import tempfile
import unittest
from pathlib import Path

from privacy import identity as ident
from privacy.tests.fixtures import CANARY, TEST_PASSPHRASE, TRICKY

FAST = ident.KdfParams(log2_n=10)


class RoundTrip(unittest.TestCase):
    def test_round_trip_canary(self):
        blob = ident.encrypt(CANARY, TEST_PASSPHRASE, FAST)
        out = ident.decrypt(blob, TEST_PASSPHRASE)
        self.assertEqual(out["email"], CANARY["email"])
        self.assertEqual(out["full_name"], "Qvistrup Ørnbjerg-Ældremøller")

    def test_round_trip_tricky(self):
        blob = ident.encrypt(TRICKY, TEST_PASSPHRASE, FAST)
        self.assertEqual(ident.decrypt(blob, TEST_PASSPHRASE)["last_name"],
                         TRICKY["last_name"])

    def test_default_cost_is_strong(self):
        self.assertGreaterEqual(ident.DEFAULT_LOG2_N, 17)
        blob = ident.encrypt(CANARY, TEST_PASSPHRASE)
        self.assertEqual(blob[5], ident.DEFAULT_LOG2_N)

    def test_fresh_salt_and_nonce(self):
        a = ident.encrypt(CANARY, TEST_PASSPHRASE, FAST)
        b = ident.encrypt(CANARY, TEST_PASSPHRASE, FAST)
        self.assertNotEqual(a[8:36], b[8:36])
        self.assertNotEqual(a, b)


class NoPlaintext(unittest.TestCase):
    def test_no_identity_value_in_ciphertext(self):
        blob = ident.encrypt(CANARY, TEST_PASSPHRASE, FAST)
        for value in CANARY.values():
            self.assertNotIn(value.encode(), blob)
            self.assertNotIn(value.lower().encode(), blob.lower())


class Rejections(unittest.TestCase):
    def setUp(self):
        self.blob = ident.encrypt(CANARY, TEST_PASSPHRASE, FAST)

    def test_wrong_passphrase(self):
        with self.assertRaises(ident.WrongPassphrase):
            ident.decrypt(self.blob, TEST_PASSPHRASE + "x")

    def test_tampered_ciphertext(self):
        bad = bytearray(self.blob)
        bad[-1] ^= 1
        with self.assertRaises(ident.WrongPassphrase):
            ident.decrypt(bytes(bad), TEST_PASSPHRASE)

    def test_tampered_header_is_authenticated(self):
        bad = bytearray(self.blob)
        bad[10] ^= 1          # inside the salt
        with self.assertRaises(ident.WrongPassphrase):
            ident.decrypt(bytes(bad), TEST_PASSPHRASE)

    def test_weakened_cost_rejected(self):
        bad = bytearray(self.blob)
        bad[5] = 4
        with self.assertRaises(ident.IdentityError):
            ident.decrypt(bytes(bad), TEST_PASSPHRASE)

    def test_not_an_identity_file(self):
        with self.assertRaises(ident.IdentityError):
            ident.decrypt(b"%PDF-1.7 hello", TEST_PASSPHRASE)

    def test_empty_passphrase(self):
        with self.assertRaises(ident.IdentityError):
            ident.encrypt(CANARY, "", FAST)


class Validation(unittest.TestCase):
    def test_required_fields(self):
        problems = ident.validate(ident.normalise({"first_name": "A"}))
        self.assertIn("email: required", problems)
        self.assertIn("phone: required", problems)

    def test_messages_never_echo_values(self):
        bad = dict(CANARY, email="not an email Qvistrup", phone="call me",
                   linkedin="http://x.invalid/?q=Qvistrup",
                   address="line\nbreak {Qvistrup}")
        problems = " ".join(ident.validate(ident.normalise(bad)))
        self.assertTrue(problems)
        for value in bad.values():
            self.assertNotIn(value, problems)
        self.assertNotIn("Qvistrup", problems)

    def test_token_as_value_rejected(self):
        problems = ident.validate(ident.normalise(dict(CANARY, first_name="ZZNAMEZZ")))
        self.assertTrue(any("token" in p for p in problems))

    def test_unknown_field_rejected(self):
        with self.assertRaises(ident.IdentityError):
            ident.normalise(dict(CANARY, password="x"))

    def test_fixtures_are_valid(self):
        for fx in (CANARY, TRICKY):
            self.assertEqual(ident.validate(ident.normalise(fx)), [])


class FileIO(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        for p in self.dir.iterdir():
            p.unlink()
        self.dir.rmdir()

    def test_written_mode_0600(self):
        p = self.dir / "identity.enc"
        ident.write_file(p, b"x")
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        self.assertEqual(ident.read_file(p), b"x")

    def test_refuses_symlink_on_write(self):
        target = self.dir / "elsewhere"
        target.write_bytes(b"old")
        link = self.dir / "identity.enc"
        link.symlink_to(target)
        with self.assertRaises(ident.IdentityError):
            ident.write_file(link, b"new")
        self.assertEqual(target.read_bytes(), b"old")

    def test_refuses_symlink_on_read(self):
        target = self.dir / "elsewhere"
        target.write_bytes(b"x")
        (self.dir / "identity.enc").symlink_to(target)
        with self.assertRaises(OSError):
            ident.read_file(self.dir / "identity.enc")


if __name__ == "__main__":
    unittest.main()
