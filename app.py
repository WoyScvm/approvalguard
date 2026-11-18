"""ApprovalGuard HTTP server (Python stdlib only).

Endpoints:
  GET  /                  Demo page (form + example output)
  GET  /health            Liveness + agent identity (public key, chains)
  GET  /scan?address=0x..&chain=ethereum&depth=full
  POST /scan              {"address": "0x..", "chain": "ethereum", "depth": "full"}
  POST /agent             Agent Games platform envelope (HMAC-aware, see below)
  POST /verify            Verify a signed report
  GET  /example           A real signed example report (checked in)

Platform envelope (POST /agent): accepts the Agent Games task envelope
(task_id / mode / task payload). When the AGENT_GAMES_SECRET environment
variable is set, the x-agent-games-signature HMAC-SHA256 header is
verified against the raw request body before any work (fail closed),
and responses are signed the same way. Preflight tasks
(task_id "preflight_smoke_1" / mode "preflight") get an immediate
response without running a scan. Responses are cached by task_id so
platform retries are idempotent.

Run:  python3 app.py            (listens on 0.0.0.0:8000)
      PORT=8080 python3 app.py  (custom port)
"""

import hashlib
import hmac as hmac_lib
import json
import os
import time
import traceback
import urllib.parse
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from approvalguard import __version__, ed25519, keys
from approvalguard.chains import CHAINS
from approvalguard.scanner import Scanner, canonical_json, is_valid_address

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(HERE, "static")

SEED, PUBLIC_KEY = keys.load_or_generate_keypair()
HMAC_SECRET = os.environ.get("AGENT_GAMES_SECRET", "")

# Bounded idempotency cache: task_id -> response body bytes.
TASK_CACHE = OrderedDict()
TASK_CACHE_MAX = 200


def sign_report(report: dict) -> dict:
    """Return a copy of the report with an Ed25519 signature envelope."""
    payload = canonical_json(report)
    signature = ed25519.sign(SEED, payload)
    signed = dict(report)
    signed["signature"] = {
        "algorithm": "Ed25519",
        "public_key": PUBLIC_KEY.hex(),
        "signature": signature.hex(),
        "signed_encoding": "canonical JSON: sort_keys=True, separators=(',',':'), UTF-8",
        "verify_with": "POST /verify with this full report object",
    }
    return signed


def verify_signed_report(report: dict, public_key_hex: str = None) -> dict:
    """Verify a signed report dict. Returns a result dict."""
    signature_block = report.get("signature") if isinstance(report, dict) else None
    if not isinstance(signature_block, dict):
        return {"valid": False, "reason": "no signature block found"}
    try:
        signature = bytes.fromhex(signature_block["signature"])
        public_key = bytes.fromhex(public_key_hex or signature_block["public_key"])
    except (KeyError, ValueError, TypeError) as exc:
        return {"valid": False, "reason": "malformed signature block: %s" % exc}
    unsigned = {k: v for k, v in report.items() if k != "signature"}
    valid = ed25519.verify(public_key, canonical_json(unsigned), signature)
    return {
        "valid": valid,
        "algorithm": signature_block.get("algorithm"),
        "public_key": public_key.hex(),
        "reason": "signature valid" if valid else "signature does not match payload",
    }


def hmac_hex(secret: str, body: bytes) -> str:
    return hmac_lib.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def extract_scan_params(envelope):
    """Pull address/chain/depth out of various envelope shapes."""
    if not isinstance(envelope, dict):
        return None, "ethereum", "full"
    candidates = [envelope]
    for key in ("task", "payload", "input", "params"):
        if isinstance(envelope.get(key), dict):
            candidates.append(envelope[key])
    address = None
    chain = "ethereum"
    depth = "full"
    for obj in candidates:
        for key in ("address", "wallet", "wallet_address", "owner"):
            if obj.get(key) and is_valid_address(str(obj[key])):
                address = str(obj[key])
        if obj.get("chain"):
            chain = str(obj["chain"])
        if obj.get("depth") in ("quick", "full"):
            depth = str(obj["depth"])
    return address, chain, depth


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ApprovalGuard/" + __version__

    # -- helpers ------------------------------------------------------
    def _send_json(self, status, obj, extra_headers=None):
        body = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status, body, content_type="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self, limit=1_000_000):
        length = int(self.headers.get("Content-Length") or 0)
        if length > limit:
            raise ValueError("request body too large")
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}, raw
        return json.loads(raw.decode("utf-8")), raw

    def log_message(self, fmt, *args):  # keep logs compact
        print("[%s] %s" % (time.strftime("%H:%M:%S"), fmt % args), flush=True)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, x-agent-games-signature")
        self.send_header("Content-Length", "0")
        self.end_headers()

    # -- routes -------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        try:
            if path == "/":
                with open(os.path.join(STATIC_DIR, "index.html"), "rb") as fh:
                    self._send_text(200, fh.read())
            elif path == "/health":
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "agent": "ApprovalGuard",
                        "version": __version__,
                        "platform_version": "1.0",
                        "public_key": PUBLIC_KEY.hex(),
                        "signature_algorithm": "Ed25519",
                        "chains": sorted(CHAINS.keys()),
                        "verified_chains": [
                            k for k, v in CHAINS.items() if v["status"] == "verified"
                        ],
                        "hmac_configured": bool(HMAC_SECRET),
                        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    },
                )
            elif path == "/scan":
                query = urllib.parse.parse_qs(parsed.query)
                address = (query.get("address") or [None])[0]
                chain = (query.get("chain") or ["ethereum"])[0]
                depth = (query.get("depth") or ["full"])[0]
                self._handle_scan(address, chain, depth)
            elif path == "/example":
                with open(os.path.join(HERE, "example_report.json"), "rb") as fh:
                    self._send_text(200, fh.read(), "application/json")
            else:
                self._send_json(404, {"error": "not found: %s" % path})
        except Exception as exc:  # noqa: BLE001 - JSON error surface
            traceback.print_exc()
            self._send_json(500, {"error": "internal error: %s" % exc})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        try:
            if path == "/scan":
                body, _ = self._read_json()
                self._handle_scan(
                    body.get("address"),
                    body.get("chain", "ethereum"),
                    body.get("depth", "full"),
                    max_pages=body.get("max_pages"),
                    logs_window_blocks=body.get("logs_window_blocks"),
                )
            elif path == "/agent":
                self._handle_agent()
            elif path == "/verify":
                body, _ = self._read_json()
                report = body.get("report", body)
                result = verify_signed_report(report, body.get("public_key"))
                self._send_json(200, result)
            else:
                self._send_json(404, {"error": "not found: %s" % path})
        except json.JSONDecodeError:
            self._send_json(400, {"error": "request body is not valid JSON"})
        except Exception as exc:  # noqa: BLE001 - JSON error surface
            traceback.print_exc()
            self._send_json(500, {"error": "internal error: %s" % exc})

    # -- handlers -----------------------------------------------------
    def _handle_scan(self, address, chain, depth, max_pages=None, logs_window_blocks=None):
        if not address or not is_valid_address(str(address)):
            self._send_json(
                400, {"error": "a valid EVM address is required (0x + 40 hex chars)"}
            )
            return
        if depth not in ("quick", "full"):
            self._send_json(400, {"error": "depth must be 'quick' or 'full'"})
            return
        try:
            scanner = Scanner(chain)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        try:
            report = scanner.scan(
                str(address),
                depth=depth,
                max_pages=max_pages,
                logs_window_blocks=logs_window_blocks,
            )
        except Exception as exc:  # noqa: BLE001 - upstream failure surface
            traceback.print_exc()
            self._send_json(
                502, {"error": "scan failed (upstream data source): %s" % exc}
            )
            return
        self._send_json(200, sign_report(report))

    def _handle_agent(self):
        body, raw = self._read_json()
        task_id = body.get("task_id") or "unknown"
        mode = body.get("mode")

        # HMAC verification (fail closed when a secret is configured).
        hmac_status = "not-configured"
        if HMAC_SECRET:
            provided = self.headers.get("x-agent-games-signature", "")
            expected = hmac_hex(HMAC_SECRET, raw)
            if not provided or not hmac_lib.compare_digest(provided, expected):
                self._send_json(401, {"error": "invalid x-agent-games-signature"})
                return
            hmac_status = "verified"

        # Idempotency: platform retries reuse the cached response.
        if task_id in TASK_CACHE:
            cached = TASK_CACHE[task_id]
            headers = {}
            if HMAC_SECRET:
                headers["x-agent-games-signature"] = hmac_hex(HMAC_SECRET, cached)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(cached)))
            self.send_header("Access-Control-Allow-Origin", "*")
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(cached)
            return

        # Preflight: fast acknowledgement, no scan.
        if mode == "preflight" or task_id == "preflight_smoke_1":
            response = {
                "task_id": task_id,
                "status": "ok",
                "decision": "READY",
                "agent": "ApprovalGuard",
                "version": __version__,
                "public_key": PUBLIC_KEY.hex(),
                "hmac": hmac_status,
            }
            self._send_agent_response(task_id, response)
            return

        address, chain, depth = extract_scan_params(body)
        if not address:
            response = {
                "task_id": task_id,
                "status": "error",
                "decision": "REJECT",
                "reason_code": "MISSING_ADDRESS",
                "detail": "no valid EVM address found in the task payload",
            }
            self._send_agent_response(task_id, response, status=400)
            return
        try:
            scanner = Scanner(chain)
            report = scanner.scan(address, depth=depth)
        except ValueError as exc:
            response = {
                "task_id": task_id,
                "status": "error",
                "decision": "REJECT",
                "reason_code": "BAD_REQUEST",
                "detail": str(exc),
            }
            self._send_agent_response(task_id, response, status=400)
            return
        except Exception as exc:  # noqa: BLE001 - upstream failure surface
            traceback.print_exc()
            response = {
                "task_id": task_id,
                "status": "error",
                "decision": "REJECT",
                "reason_code": "SCAN_FAILED",
                "detail": "scan failed (upstream data source): %s" % exc,
            }
            self._send_agent_response(task_id, response, status=502)
            return
        response = {
            "task_id": task_id,
            "status": "ok",
            "decision": "COMPLETE",
            "agent": "ApprovalGuard",
            "version": __version__,
            "hmac": hmac_status,
            "result": sign_report(report),
        }
        self._send_agent_response(task_id, response)

    def _send_agent_response(self, task_id, response, status=200):
        body = json.dumps(response, indent=2).encode("utf-8")
        TASK_CACHE[task_id] = body
        while len(TASK_CACHE) > TASK_CACHE_MAX:
            TASK_CACHE.popitem(last=False)
        headers = {}
        if HMAC_SECRET:
            headers["x-agent-games-signature"] = hmac_hex(HMAC_SECRET, body)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


def main():
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")
    server = ThreadingHTTPServer((host, port), Handler)
    print(
        "ApprovalGuard %s listening on http://%s:%d (public key %s)"
        % (__version__, host, port, PUBLIC_KEY.hex()),
        flush=True,
    )
    print("HMAC secret configured: %s" % bool(HMAC_SECRET), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.", flush=True)


if __name__ == "__main__":
    main()
