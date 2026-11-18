"""API tests: spins up the real server on an ephemeral port.

Covers /health, /verify, /agent preflight + HMAC behaviour, and /scan
input validation. Live chain scans are covered separately by
tests/test_live.py (run manually; needs network access).
"""

import hashlib
import hmac as hmac_lib
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module


def _request(port, method, path, body=None, headers=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (port, path),
        data=data,
        method=method,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


class ApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app_module.Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_health(self):
        status, body, _ = _request(self.port, "GET", "/health")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["agent"], "ApprovalGuard")
        self.assertEqual(len(data["public_key"]), 64)
        self.assertIn("ethereum", data["verified_chains"])

    def test_demo_page(self):
        status, body, _ = _request(self.port, "GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"ApprovalGuard", body)

    def test_scan_validation(self):
        status, body, _ = _request(self.port, "GET", "/scan?address=not-an-address")
        self.assertEqual(status, 400)
        status, body, _ = _request(self.port, "POST", "/scan", {"address": "0x123"})
        self.assertEqual(status, 400)
        status, body, _ = _request(
            self.port, "POST", "/scan", {"address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "chain": "nope"}
        )
        self.assertEqual(status, 400)

    def test_verify_roundtrip(self):
        report = {"agent": "ApprovalGuard", "address": "0xabc", "value": 42}
        signed = app_module.sign_report(report)
        status, body, _ = _request(self.port, "POST", "/verify", {"report": signed})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["valid"])
        tampered = dict(signed)
        tampered["value"] = 43
        status, body, _ = _request(self.port, "POST", "/verify", {"report": tampered})
        self.assertFalse(json.loads(body)["valid"])

    def test_agent_preflight_no_hmac(self):
        status, body, _ = _request(
            self.port, "POST", "/agent", {"task_id": "preflight_smoke_1", "mode": "preflight"}
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["decision"], "READY")

    def test_agent_missing_address(self):
        status, body, _ = _request(
            self.port, "POST", "/agent", {"task_id": "t-missing", "task": {}}
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["reason_code"], "MISSING_ADDRESS")

    def test_agent_hmac_enforced_when_configured(self):
        secret = "test-secret-123"
        app_module.HMAC_SECRET = secret
        try:
            payload = {"task_id": "preflight_smoke_1", "mode": "preflight"}
            raw = json.dumps(payload).encode("utf-8")
            # No signature -> 401
            status, _, _ = _request(self.port, "POST", "/agent", payload)
            self.assertEqual(status, 401)
            # Wrong signature -> 401
            status, _, _ = _request(
                self.port, "POST", "/agent", payload,
                headers={"x-agent-games-signature": "00" * 32},
            )
            self.assertEqual(status, 401)
            # Correct signature -> 200, and response is signed
            sig = hmac_lib.new(secret.encode(), raw, hashlib.sha256).hexdigest()
            req = urllib.request.Request(
                "http://127.0.0.1:%d/agent" % self.port,
                data=raw,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "x-agent-games-signature": sig,
                },
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                self.assertEqual(resp.status, 200)
                resp_sig = resp.headers.get("x-agent-games-signature")
                resp_body = resp.read()
            self.assertIsNotNone(resp_sig)
            expected = hmac_lib.new(secret.encode(), resp_body, hashlib.sha256).hexdigest()
            self.assertEqual(resp_sig, expected)
        finally:
            app_module.HMAC_SECRET = ""


if __name__ == "__main__":
    unittest.main()
