"""Minimal JSON-RPC client over urllib (stdlib only).

Supports single calls, batch calls, multiple endpoint fallback, and
retries with backoff. Used for eth_call (allowance, token metadata),
eth_getCode, eth_blockNumber, and eth_getLogs.
"""

import json
import time
import urllib.error
import urllib.request

USER_AGENT = "ApprovalGuard/1.0 (+https://agentgames.zkverify.io/)"


class RpcError(Exception):
    pass


def _post(url, payload, timeout=30):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class RpcClient:
    def __init__(self, urls, timeout=30, retries=2):
        self.urls = list(urls)
        self.timeout = timeout
        self.retries = retries
        self.last_errors = []

    def call(self, method, params):
        """Single JSON-RPC call with endpoint fallback. Returns result.

        Raises RpcError if every endpoint fails or the call yields no
        result (an error response is never silently returned as None).
        """
        result = self.batch([(method, params)])[0]
        if result is None:
            raise RpcError(
                "RPC call %s returned no result (errors: %s)" % (method, self.last_errors)
            )
        return result

    def batch(self, calls):
        """Batch JSON-RPC call. `calls` is a list of (method, params).

        Returns a list of results in request order. A failed call yields
        None in its slot and records the error on self.last_errors.
        """
        payload = [
            {"jsonrpc": "2.0", "id": i + 1, "method": m, "params": p}
            for i, (m, p) in enumerate(calls)
        ]
        last_error = None
        for url in self.urls:
            for attempt in range(self.retries + 1):
                try:
                    resp = _post(url, payload, timeout=self.timeout)
                    results = self._unpack(resp, len(calls))
                except Exception as exc:  # noqa: BLE001 - fallback chain
                    last_error = exc
                    time.sleep(0.5 * (attempt + 1))
                    continue
                if all(r is None for r in results) and any(self.last_errors):
                    # The endpoint answered, but only with error payloads:
                    # treat it as failed and try the next endpoint instead
                    # of returning a batch of silent Nones.
                    last_error = RpcError(
                        "endpoint returned only error responses: %s" % (self.last_errors,)
                    )
                    time.sleep(0.5 * (attempt + 1))
                    continue
                return results
        raise RpcError("all RPC endpoints failed: %s" % (last_error,))

    def _unpack(self, resp, count):
        """Split a JSON-RPC response into per-call results.

        A call whose item carries "error" (or is missing) yields None in
        its slot, and the error is recorded in self.last_errors so a
        caller can tell an error response apart from a real result.
        """
        results = [None] * count
        errors = [None] * count
        items = resp if isinstance(resp, list) else [resp]
        for item in items:
            if not isinstance(item, dict):
                continue
            raw_id = item.get("id", 1)
            if not isinstance(raw_id, int):
                continue
            idx = raw_id - 1
            if 0 <= idx < count:
                if "result" in item:
                    results[idx] = item["result"]
                elif "error" in item:
                    errors[idx] = item["error"]
        self.last_errors = errors
        return results


def hex_to_int(value):
    if value is None:
        return None
    if isinstance(value, int):
        return value
    return int(value, 16)


def encode_address(address: str) -> str:
    """Left-pad an address to a 32-byte ABI word (no 0x prefix)."""
    return address.lower().replace("0x", "").rjust(64, "0")


def encode_allowance_call(owner: str, spender: str) -> str:
    # allowance(address,address) -> 0xdd62ed3e
    return "0xdd62ed3e" + encode_address(owner) + encode_address(spender)


def encode_balance_call(owner: str) -> str:
    # balanceOf(address) -> 0x70a08231
    return "0x70a08231" + encode_address(owner)
