"""Live end-to-end test: runs a REAL scan against public chain data.

Usage:  python3 tests/test_live.py [address] [depth]

Defaults to vitalik.eth (0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045),
quick depth. Prints the signed report summary and asserts the report
structure, then verifies the signature. No keys, no funds, read-only.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module
from approvalguard.scanner import Scanner


def main():
    address = sys.argv[1] if len(sys.argv) > 1 else "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    depth = sys.argv[2] if len(sys.argv) > 2 else "quick"
    print("Scanning %s (%s)..." % (address, depth), flush=True)
    scanner = Scanner("ethereum")
    report = scanner.scan(address, depth=depth)
    signed = app_module.sign_report(report)
    summary = signed["summary"]
    print("block: %s, seconds: %s" % (signed["block_number"], signed["scan_seconds"]))
    print("coverage: %s" % json.dumps(signed["coverage"], indent=1)[:600])
    print("summary: %s" % json.dumps(summary, indent=1))
    print("approvals found: %d (active %d)" % (len(signed["approvals"]), summary["active_approvals"]))
    for item in signed["approvals"][:10]:
        print(
            "  %s %s spender=%s allowance=%s flags=%s"
            % (
                item.get("token_symbol") or item["token"][:10],
                item["status"],
                item["spender"][:10] + "...",
                item["allowance"],
                ",".join(f["code"] for f in item["risk_flags"]) or "-",
            )
        )
    check = app_module.verify_signed_report(signed)
    print("signature valid: %s" % check["valid"])
    assert check["valid"], "signature verification failed"
    assert signed["address"] == address.lower()
    assert signed["chain"] == "ethereum"
    assert isinstance(signed["approvals"], list)
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "example_report.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(signed, fh, indent=2)
    print("saved example report to %s" % out)
    print("LIVE TEST PASSED")


if __name__ == "__main__":
    main()
