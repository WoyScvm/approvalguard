"""Unit tests for scanner parsing, risk flags, and canonical signing."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from approvalguard import ed25519
from approvalguard.scanner import (
    MAX_UINT256,
    canonical_json,
    decode_abi_string,
    decode_abi_uint,
    is_valid_address,
    normalize_address,
    parse_approval_input,
    parse_decoded_input,
    Scanner,
)

SPENDER = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"
TOKEN = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"


def approval_calldata(spender, amount):
    return (
        "0x095ea7b3"
        + spender[2:].rjust(64, "0")
        + ("%064x" % amount)
    )


class TestParsing(unittest.TestCase):
    def test_approve_calldata(self):
        parsed = parse_approval_input(approval_calldata(SPENDER, 12345), TOKEN)
        self.assertEqual(parsed, (SPENDER, 12345, "approve"))

    def test_unlimited_calldata(self):
        parsed = parse_approval_input(approval_calldata(SPENDER, MAX_UINT256), TOKEN)
        self.assertEqual(parsed[1], MAX_UINT256)

    def test_non_approve_ignored(self):
        self.assertIsNone(parse_approval_input("0xa9059cbb" + "00" * 64, TOKEN))
        self.assertIsNone(parse_approval_input("0x", TOKEN))
        self.assertIsNone(parse_approval_input(None, TOKEN))
        self.assertIsNone(parse_approval_input("0x095ea7b3" + "00" * 10, TOKEN))

    def test_increase_allowance(self):
        data = "0x39509351" + SPENDER[2:].rjust(64, "0") + ("%064x" % 7)
        self.assertEqual(parse_approval_input(data, TOKEN), (SPENDER, 7, "increaseAllowance"))

    def test_decoded_input_fallback(self):
        decoded = {
            "method": "approve",
            "parameters": [
                {"name": "spender", "type": "address", "value": SPENDER},
                {"name": "amount", "type": "uint256", "value": "999"},
            ],
        }
        self.assertEqual(
            parse_decoded_input(decoded), (SPENDER, 999, "approve")
        )
        self.assertIsNone(parse_decoded_input({"method": "transfer", "parameters": []}))

    def test_address_validation(self):
        self.assertTrue(is_valid_address("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))
        self.assertTrue(is_valid_address("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))
        self.assertFalse(is_valid_address("0x123"))
        self.assertFalse(is_valid_address("not an address"))
        self.assertFalse(is_valid_address(None))
        self.assertEqual(
            normalize_address("0xD8DA6BF26964AF9D7EED9E03E53415D37AA96045"),
            "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
        )

    def test_abi_string_decode(self):
        # "USDC" as ABI string: offset 32, length 4, data
        encoded = "0x" + (32).to_bytes(32, "big").hex() + (4).to_bytes(32, "big").hex() + b"USDC".ljust(32, b"\x00").hex()
        self.assertEqual(decode_abi_string(encoded), "USDC")
        # bytes32-style symbol (e.g. MKR)
        self.assertEqual(decode_abi_string("0x" + b"MKR".ljust(32, b"\x00").hex()), "MKR")
        self.assertIsNone(decode_abi_string("0x"))
        self.assertEqual(decode_abi_uint("0x12"), 18)


class TestRiskFlags(unittest.TestCase):
    def _flags(self, **kw):
        base = dict(
            allowance=100,
            balance=1000,
            decimals=6,
            is_contract=True,
            label="Some Protocol",
            token_scam=False,
            first_block=26_000_000,
            head_block=26_400_000,
            meta_ok=True,
        )
        base.update(kw)
        return Scanner._risk_flags(**base)

    def test_revoked_is_zero(self):
        flags, score = self._flags(allowance=0)
        self.assertEqual(score, 0)
        self.assertEqual(flags[0]["code"], "REVOKED")

    def test_unlimited_flagged(self):
        flags, score = self._flags(allowance=MAX_UINT256, label=None)
        self.assertIn("UNLIMITED", [f["code"] for f in flags])
        self.assertGreaterEqual(score, 40)
        # A known-protocol label reduces (but does not remove) the score.
        _, known_score = self._flags(allowance=MAX_UINT256, label="Some Protocol")
        self.assertLess(known_score, score)
        self.assertGreater(known_score, 0)

    def test_eoa_flagged(self):
        flags, score = self._flags(is_contract=False, label=None)
        codes = [f["code"] for f in flags]
        self.assertIn("EOA_SPENDER", codes)
        self.assertIn("UNKNOWN_SPENDER", codes)

    def test_exceeds_balance_flagged(self):
        flags, _ = self._flags(allowance=5000, balance=100)
        self.assertIn("EXCEEDS_BALANCE", [f["code"] for f in flags])

    def test_known_contract_low_risk(self):
        _, score = self._flags()
        self.assertLessEqual(score, 20)

    def test_stale_flagged(self):
        flags, _ = self._flags(first_block=10_000_000, head_block=26_400_000)
        self.assertIn("STALE", [f["code"] for f in flags])


class TestCanonicalSigning(unittest.TestCase):
    def test_canonical_deterministic_and_verifiable(self):
        report = {"b": 1, "a": {"z": [3, 2], "y": "x"}}
        first = canonical_json(report)
        second = canonical_json({"a": {"y": "x", "z": [3, 2]}, "b": 1})
        self.assertEqual(first, second)
        seed = os.urandom(32)
        pub = ed25519.public_key_from_seed(seed)
        sig = ed25519.sign(seed, first)
        self.assertTrue(ed25519.verify(pub, first, sig))
        self.assertFalse(ed25519.verify(pub, first + b" ", sig))


if __name__ == "__main__":
    unittest.main()
