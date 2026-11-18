"""Blockscout v2 API client (no API key needed).

Used for approval discovery: paginating an address's outgoing
transactions and parsing ERC20 approve() calls from their input data.
Every direct ERC20 approval is a transaction FROM the owner, so a full
outgoing-transaction scan is complete for direct approvals. Approvals
granted via EIP-2612 permit() are submitted by third parties and are
covered instead by the recent-logs layer (see scanner.py).
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "ApprovalGuard/1.0 (+https://agentgames.zkverify.io/)"
PAGE_SIZE = 50


class BlockscoutError(Exception):
    pass


class BlockscoutClient:
    def __init__(self, base_url, timeout=45, retries=2):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retries = retries

    def _get(self, path, params=None):
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        last_error = None
        for attempt in range(self.retries + 1):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except Exception as exc:  # noqa: BLE001 - retry then raise
                last_error = exc
                time.sleep(1.0 * (attempt + 1))
        raise BlockscoutError("GET %s failed: %s" % (path, last_error))

    def outgoing_transactions(self, address, max_pages=120, on_page=None):
        """Yield transaction dicts (newest first) for outgoing txs.

        Stops at `max_pages` pages or when pagination ends. Returns a
        dict summary as the final value via the `summary` attribute on
        the generator's return is awkward, so instead this returns
        (transactions, summary) after consuming all pages.
        """
        transactions = []
        params = {"filter": "from"}
        pages = 0
        more_pages_available = False
        while pages < max_pages:
            data = self._get(
                "/api/v2/addresses/%s/transactions" % address, params
            )
            items = data.get("items", [])
            if not items:
                break
            transactions.extend(items)
            pages += 1
            if on_page:
                on_page(pages, len(transactions))
            nxt = data.get("next_page_params")
            if not nxt:
                more_pages_available = False
                break
            more_pages_available = True
            params = {k: v for k, v in nxt.items() if v is not None}
        summary = {
            "pages_scanned": pages,
            "transactions_scanned": len(transactions),
            "hit_page_cap": pages >= max_pages and more_pages_available,
            "earliest_block": (
                min(
                    (int(t["block_number"]) for t in transactions if t.get("block_number")),
                    default=None,
                )
            ),
            "latest_block": (
                max(
                    (int(t["block_number"]) for t in transactions if t.get("block_number")),
                    default=None,
                )
            ),
        }
        return transactions, summary

    def token_info(self, token_address):
        """Best-effort token metadata from Blockscout (may be None)."""
        try:
            data = self._get("/api/v2/tokens/%s" % token_address)
        except BlockscoutError:
            return None
        if not isinstance(data, dict):
            return None
        return {
            "name": data.get("name"),
            "symbol": data.get("symbol"),
            "decimals": data.get("decimals"),
            "total_supply": data.get("total_supply"),
            "holders_count": data.get("holders_count"),
            "exchange_rate": data.get("exchange_rate"),
            "reputation": data.get("reputation"),
            "is_verified": None,
        }
