"""End-to-end scan logic with stubbed RPC + explorer layers (no network).

Proves the verification/scoring behavior that live RPC flakiness hides
from this environment: contract vs EOA vs unknown code, active vs
revoked vs unknown status, and honest summary counts.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from approvalguard.scanner import MAX_UINT256, Scanner, normalize_address

OWNER = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
ROUTER = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"  # contract, labeled
EOA = "0x000000000000000000000000000000000000dead"  # positively empty code
GHOST = "0x000000000000000000000000000000000000beef"  # code lookup fails
DELEGATED = "0x000000000000000000000000000000000000cafe"  # EIP-7702 delegated EOA
TOKEN_A = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
TOKEN_B = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
TOKEN_C = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
TOKEN_D = "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599"
TOKEN_E = "0x514910771AF9Ca656af840dff83E8264EcF986CA"
TOKEN_F = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"

HEAD = 0x1000000
RECENT = 0xFF0000  # ~9 days before HEAD: not stale


def approve_input(spender, amount):
    return "0x095ea7b3" + spender[2:].rjust(64, "0") + ("%064x" % amount)


class FakeRpc:
    def call(self, method, params):
        return self.batch([(method, params)])[0]

    def batch(self, calls):
        out = []
        for method, params in calls:
            if method == "eth_blockNumber":
                out.append("0x%x" % HEAD)
            elif method == "eth_getCode":
                spender = normalize_address(params[0])
                if spender == normalize_address(ROUTER):
                    out.append("0x60006000")
                elif spender == normalize_address(EOA):
                    out.append("0x")
                elif spender == normalize_address(DELEGATED):
                    out.append("0xef01005a7fc11397e9a8ad41bf10bf13f22b0a63f96f6d")
                else:
                    out.append(None)  # lookup failure
            elif method == "eth_call":
                data = params[0]["data"]
                to = normalize_address(params[0]["to"])
                if data.startswith("0xdd62ed3e"):  # allowance
                    by_token = {
                        normalize_address(TOKEN_A): MAX_UINT256,
                        normalize_address(TOKEN_B): 0,
                        normalize_address(TOKEN_C): None,
                        normalize_address(TOKEN_D): 100,
                        normalize_address(TOKEN_E): 100,
                        normalize_address(TOKEN_F): 100,
                    }
                    value = by_token[to]
                    out.append(None if value is None else "0x" + "%064x" % value)
                elif data.startswith("0x70a08231"):  # balanceOf
                    out.append("0x" + "%064x" % 1000)
                elif data.startswith("0x313ce567"):  # decimals
                    out.append("0x" + "%064x" % 18)
                else:  # name/symbol: unreadable
                    out.append(None)
            else:
                out.append(None)
        return out


class FakeExplorer:
    def outgoing_transactions(self, address, max_pages):
        pairs = [
            (TOKEN_A, ROUTER, MAX_UINT256),
            (TOKEN_B, EOA, 500),
            (TOKEN_C, GHOST, 500),
            (TOKEN_D, EOA, 100),
            (TOKEN_E, GHOST, 100),
            (TOKEN_F, DELEGATED, 100),
        ]
        txs = [
            {
                "to": {"hash": token, "is_scam": False, "name": None},
                "raw_input": approve_input(spender, amount),
                "decoded_input": None,
                "block_number": RECENT,
                "timestamp": "2026-11-10T00:00:00Z",
                "hash": "0x%064x" % (i + 1),
            }
            for i, (token, spender, amount) in enumerate(pairs)
        ]
        summary = {
            "transactions_scanned": len(txs),
            "pages_scanned": 1,
            "earliest_block": RECENT,
            "hit_page_cap": False,
        }
        return txs, summary


def run_scan():
    scanner = Scanner("ethereum")
    scanner.rpc = FakeRpc()
    scanner.logs_rpc = None
    scanner.explorer = FakeExplorer()
    return scanner.scan(OWNER, depth="quick")


class TestScanWithStubs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_scan()
        cls.by_pair = {
            (a["token"], a["spender"]): a for a in cls.report["approvals"]
        }

    def test_contract_spender_is_contract(self):
        a = self.by_pair[(normalize_address(TOKEN_A), normalize_address(ROUTER))]
        self.assertIs(a["spender_is_contract"], True)
        self.assertEqual(a["status"], "active")
        codes = [f["code"] for f in a["risk_flags"]]
        self.assertIn("UNLIMITED", codes)
        self.assertNotIn("EOA_SPENDER", codes)
        self.assertNotIn("SPENDER_CODE_UNKNOWN", codes)

    def test_eoa_spender_flagged_only_when_active(self):
        a = self.by_pair[(normalize_address(TOKEN_D), normalize_address(EOA))]
        self.assertIs(a["spender_is_contract"], False)
        self.assertEqual(a["status"], "active")
        codes = [f["code"] for f in a["risk_flags"]]
        self.assertIn("EOA_SPENDER", codes)
        self.assertNotIn("SPENDER_CODE_UNKNOWN", codes)
        # EIP-7702 delegated EOA: has code, still an EOA.
        f = self.by_pair[(normalize_address(TOKEN_F), normalize_address(DELEGATED))]
        self.assertIs(f["spender_is_contract"], False)
        self.assertEqual(f["status"], "active")
        self.assertIn("EOA_SPENDER", [fl["code"] for fl in f["risk_flags"]])

    def test_unknown_code_is_not_eoa(self):
        a = self.by_pair[(normalize_address(TOKEN_E), normalize_address(GHOST))]
        self.assertIs(a["spender_is_contract"], None)
        self.assertEqual(a["status"], "active")
        codes = [f["code"] for f in a["risk_flags"]]
        self.assertIn("SPENDER_CODE_UNKNOWN", codes)
        self.assertNotIn("EOA_SPENDER", codes)

    def test_revoked_and_unknown_statuses(self):
        revoked = self.by_pair[(normalize_address(TOKEN_B), normalize_address(EOA))]
        self.assertEqual(revoked["status"], "revoked")
        self.assertIn("REVOKED", [f["code"] for f in revoked["risk_flags"]])
        unknown = self.by_pair[(normalize_address(TOKEN_C), normalize_address(GHOST))]
        self.assertEqual(unknown["status"], "unknown")
        self.assertIn("ALLOWANCE_UNREADABLE", [f["code"] for f in unknown["risk_flags"]])

    def test_summary_counts(self):
        s = self.report["summary"]
        self.assertEqual(s["total_pairs_found"], 6)
        self.assertEqual(s["active_approvals"], 4)
        self.assertEqual(s["revoked_approvals"], 1)
        self.assertEqual(s["unverified_approvals"], 1)
        self.assertEqual(s["unlimited_approvals"], 1)
        self.assertEqual(s["eoa_spenders"], 2)
        self.assertIn("could not be verified", s["plain_language"])

    def test_limitations_disclose_unknowns(self):
        limitations = self.report["coverage"]["limitations"]
        self.assertTrue(any("code lookups failed" in l for l in limitations))
        self.assertTrue(any("could not be verified" in l for l in limitations))


if __name__ == "__main__":
    unittest.main()
