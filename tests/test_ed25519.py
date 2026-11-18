"""Ed25519 tests against the RFC 8032 section 7.1 test vectors.

Vectors copied from https://www.rfc-editor.org/rfc/rfc8032.txt (TEST 1,
TEST 2, TEST 3). The RFC's "SECRET KEY" is the 32-byte seed.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from approvalguard import ed25519

# RFC 8032 TEST 1: empty message
T1_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
T1_PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
T1_MSG = b""
T1_SIG = (
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)

# RFC 8032 TEST 2: 1-byte message 0x72
T2_SEED = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
T2_PUB = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
T2_MSG = bytes.fromhex("72")
T2_SIG = (
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
)

# RFC 8032 TEST 3: 2-byte message 0xaf82
T3_SEED = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
T3_PUB = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
T3_MSG = bytes.fromhex("af82")
T3_SIG = (
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
    "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
)

VECTORS = [
    (T1_SEED, T1_PUB, T1_MSG, T1_SIG),
    (T2_SEED, T2_PUB, T2_MSG, T2_SIG),
    (T3_SEED, T3_PUB, T3_MSG, T3_SIG),
]


class TestEd25519Rfc8032(unittest.TestCase):
    def test_public_key_derivation(self):
        for seed_hex, pub_hex, _, _ in VECTORS:
            got = ed25519.public_key_from_seed(bytes.fromhex(seed_hex)).hex()
            self.assertEqual(got, pub_hex, "pubkey mismatch for seed %s" % seed_hex[:16])

    def test_signing_matches_vectors(self):
        for seed_hex, _, msg, sig_hex in VECTORS:
            got = ed25519.sign(bytes.fromhex(seed_hex), msg).hex()
            self.assertEqual(got, sig_hex, "signature mismatch for seed %s" % seed_hex[:16])

    def test_verification_accepts_vectors(self):
        for _, pub_hex, msg, sig_hex in VECTORS:
            self.assertTrue(
                ed25519.verify(bytes.fromhex(pub_hex), msg, bytes.fromhex(sig_hex))
            )

    def test_roundtrip_random_messages(self):
        seed = os.urandom(32)
        pub = ed25519.public_key_from_seed(seed)
        for msg in (b"", b"hello", os.urandom(1024)):
            sig = ed25519.sign(seed, msg)
            self.assertTrue(ed25519.verify(pub, msg, sig))

    def test_tampering_rejected(self):
        seed = bytes.fromhex(T1_SEED)
        pub = bytes.fromhex(T1_PUB)
        sig = bytes.fromhex(T1_SIG)
        self.assertFalse(ed25519.verify(pub, b"x", sig))
        tampered = bytearray(sig)
        tampered[10] ^= 1
        self.assertFalse(ed25519.verify(pub, T1_MSG, bytes(tampered)))
        other_pub = bytes.fromhex(T2_PUB)
        self.assertFalse(ed25519.verify(other_pub, T1_MSG, sig))

    def test_malformed_inputs_rejected(self):
        pub = bytes.fromhex(T1_PUB)
        self.assertFalse(ed25519.verify(pub, b"m", b"short"))
        self.assertFalse(ed25519.verify(b"short", b"m", bytes.fromhex(T1_SIG)))
        self.assertFalse(ed25519.verify(b"\x00" * 32, b"m", bytes.fromhex(T1_SIG)))
        with self.assertRaises(ValueError):
            ed25519.public_key_from_seed(b"too short")


if __name__ == "__main__":
    unittest.main()
