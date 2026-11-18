"""Approval discovery, verification, and risk analysis.

Discovery layers (both keyless, both read-only):
  L1  Outgoing-transaction scan via Blockscout v2: every direct ERC20
      approve()/increaseAllowance() call is a transaction FROM the owner,
      so parsing those calls gives full-history coverage of direct
      approvals.
  L2  Recent-logs scan via public JSON-RPC eth_getLogs: catches
      approvals granted via EIP-2612 permit() (submitted by third
      parties) and anything the transaction scan missed, within a
      bounded recent window.

Verification layer: for every discovered (token, spender) pair, the
CURRENT allowance is read on-chain via eth_call, the spender's code is
checked via eth_getCode, and token metadata is read via eth_call. The
on-chain state is the ground truth; historical events only explain how
an approval came to be.

Risk flags are deliberately conservative: unknown spenders are flagged
as unknown, and only a small curated list of well-known protocol
contracts is labelled. See known.py.
"""

import json
import time
from concurrent.futures import ThreadPoolExecutor

from . import known
from .blockscout import BlockscoutClient
from .chains import get_chain
from .rpc import RpcClient, encode_allowance_call, encode_balance_call, hex_to_int

APPROVAL_TOPIC = (
    "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
)
APPROVE_SELECTOR = "0x095ea7b3"
INCREASE_SELECTOR = "0x39509351"
DECREASE_SELECTOR = "0xa457c2d7"
MAX_UINT256 = (1 << 256) - 1
STALE_AGE_SECONDS = 180 * 24 * 3600

NAME_SELECTOR = "0x06fdde03"  # name()
SYMBOL_SELECTOR = "0x95d89b41"  # symbol()
DECIMALS_SELECTOR = "0x313ce567"  # decimals()


def is_valid_address(address) -> bool:
    if not isinstance(address, str):
        return False
    body = address[2:] if address.startswith(("0x", "0X")) else address
    return len(body) == 40 and all(c in "0123456789abcdefABCDEF" for c in body)


def normalize_address(address: str) -> str:
    body = address[2:] if address.startswith(("0x", "0X")) else address
    return "0x" + body.lower()


def parse_approval_input(raw_input, token_address):
    """Parse an approve/increaseAllowance/decreaseAllowance call.

    Returns (spender, amount, kind) or None.
    """
    if not raw_input or not isinstance(raw_input, str):
        return None
    data = raw_input.lower()
    kind = None
    if data.startswith(APPROVE_SELECTOR):
        kind = "approve"
    elif data.startswith(INCREASE_SELECTOR):
        kind = "increaseAllowance"
    elif data.startswith(DECREASE_SELECTOR):
        kind = "decreaseAllowance"
    else:
        return None
    body = data[10:]
    if len(body) < 128:
        return None
    try:
        spender = "0x" + body[24:64]
        amount = int(body[64:128], 16)
    except ValueError:
        return None
    if not is_valid_address(spender):
        return None
    return spender, amount, kind


def parse_decoded_input(decoded):
    """Fallback parser using Blockscout's decoded input, if present."""
    if not isinstance(decoded, dict):
        return None
    method = (decoded.get("method") or "").lower()
    if method not in ("approve", "increaseallowance", "decreaseallowance"):
        return None
    spender = None
    amount = None
    for param in decoded.get("parameters") or []:
        if param.get("name") in ("spender", "guy", "usr"):
            spender = param.get("value")
        if param.get("name") in ("amount", "value", "wad", "amt"):
            try:
                amount = int(param.get("value"))
            except (TypeError, ValueError):
                pass
    if spender and is_valid_address(str(spender)) and amount is not None:
        return normalize_address(str(spender)), amount, method
    return None


def decode_abi_string(hexdata):
    """Decode an ABI-encoded string return value; fall back to bytes32."""
    if not hexdata or hexdata == "0x":
        return None
    raw = bytes.fromhex(hexdata[2:])
    try:
        if len(raw) >= 96:
            offset = int.from_bytes(raw[0:32], "big")
            length = int.from_bytes(raw[offset : offset + 32], "big")
            text = raw[offset + 32 : offset + 32 + length]
            return text.decode("utf-8", errors="replace")
    except Exception:
        pass
    try:
        text = raw[:32].rstrip(b"\x00").decode("utf-8", errors="replace")
        return text or None
    except Exception:
        return None


def decode_abi_uint(hexdata):
    value = hex_to_int(hexdata)
    return value


class Scanner:
    def __init__(self, chain_name="ethereum"):
        self.chain_key, self.chain = get_chain(chain_name)
        if self.chain["status"] != "verified":
            raise ValueError(
                "chain %r is not enabled for scans from this environment "
                "(explorer blocks automated access); verified chains: "
                "ethereum" % (chain_name,)
            )
        self.rpc = RpcClient(self.chain["rpc_urls"])
        self.explorer = BlockscoutClient(self.chain["blockscout"])
        logs_urls = self.chain.get("logs_rpc_urls") or (
            [self.chain["logs_rpc"]] if self.chain.get("logs_rpc") else []
        )
        self.logs_rpc = RpcClient(logs_urls) if logs_urls else None

    # ---- discovery layer 1: outgoing transactions --------------------

    def scan_transactions(self, address, max_pages):
        transactions, summary = self.explorer.outgoing_transactions(
            address, max_pages=max_pages
        )
        events = []
        for tx in transactions:
            to = tx.get("to") or {}
            token = to.get("hash") if isinstance(to, dict) else None
            if not token or not is_valid_address(token):
                continue
            parsed = parse_approval_input(tx.get("raw_input"), token)
            if parsed is None:
                parsed = parse_decoded_input(tx.get("decoded_input"))
            if parsed is None:
                continue
            spender, amount, kind = parsed
            events.append(
                {
                    "token": normalize_address(token),
                    "spender": normalize_address(spender),
                    "amount": amount,
                    "kind": kind,
                    "block_number": int(tx["block_number"])
                    if tx.get("block_number")
                    else None,
                    "timestamp": tx.get("timestamp"),
                    "tx_hash": tx.get("hash"),
                    "source": "tx",
                    "token_scam": bool(to.get("is_scam")) if isinstance(to, dict) else False,
                    "token_name_hint": to.get("name") if isinstance(to, dict) else None,
                }
            )
        summary["approval_events"] = len(events)
        return events, summary

    # ---- discovery layer 2: recent Approval logs ----------------------

    def scan_logs(self, address, head_block, window_blocks, workers=4):
        if not self.logs_rpc or window_blocks <= 0:
            return [], {"enabled": False}
        if head_block is None:
            return [], {"enabled": False, "error": "head block unavailable"}
        chunk = self.chain["logs_max_range"]
        start = max(0, head_block - window_blocks)
        ranges = []
        cur = start
        while cur <= head_block:
            end = min(head_block, cur + chunk - 1)
            ranges.append((cur, end))
            cur = end + 1
        owner_topic = "0x" + "00" * 12 + address[2:]

        def fetch(rng):
            frm, to = rng
            try:
                logs = self.logs_rpc.call(
                    "eth_getLogs",
                    [
                        {
                            "fromBlock": hex(frm),
                            "toBlock": hex(to),
                            "topics": [APPROVAL_TOPIC, owner_topic],
                        }
                    ],
                )
                return logs or [], None
            except Exception as exc:  # noqa: BLE001 - recorded, scan continues
                return [], str(exc)

        events = []
        errors = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for logs, err in pool.map(fetch, ranges):
                if err:
                    errors.append(err)
                    continue
                for log in logs:
                    topics = log.get("topics", [])
                    if len(topics) < 3:
                        continue
                    spender = "0x" + topics[2][-40:]
                    try:
                        amount = int(log.get("data", "0x0"), 16)
                    except ValueError:
                        amount = 0
                    events.append(
                        {
                            "token": normalize_address(log["address"]),
                            "spender": normalize_address(spender),
                            "amount": amount,
                            "kind": "Approval-log",
                            "block_number": int(log["blockNumber"], 16),
                            "timestamp": None,
                            "tx_hash": log.get("transactionHash"),
                            "log_index": log.get("logIndex"),
                            "source": "log",
                            "token_scam": False,
                            "token_name_hint": None,
                        }
                    )
        return events, {
            "enabled": True,
            "window_blocks": window_blocks,
            "from_block": start,
            "to_block": head_block,
            "chunks": len(ranges),
            "log_events": len(events),
            "chunk_errors": errors[:5],
        }

    # ---- verification ---------------------------------------------------

    def verify_pairs(self, pairs, owner):
        """Read current allowances, spender code, token metadata on-chain.

        `pairs` is a list of (token, spender). Returns dicts keyed by
        (token, spender), spender address, and token address.
        """
        calls = []
        index = {}
        for token, spender in pairs:
            calls.append(
                ("eth_call", [{"to": token, "data": encode_allowance_call(owner, spender)}, "latest"])
            )
            index.setdefault(("allowance", token, spender), len(calls) - 1)
        spenders = sorted({s for _, s in pairs})
        for spender in spenders:
            calls.append(("eth_getCode", [spender, "latest"]))
            index.setdefault(("code", spender), len(calls) - 1)
        tokens = sorted({t for t, _ in pairs})
        for token in tokens:
            calls.append(("eth_call", [{"to": token, "data": NAME_SELECTOR}, "latest"]))
            index.setdefault(("name", token), len(calls) - 1)
            calls.append(("eth_call", [{"to": token, "data": SYMBOL_SELECTOR}, "latest"]))
            index.setdefault(("symbol", token), len(calls) - 1)
            calls.append(("eth_call", [{"to": token, "data": DECIMALS_SELECTOR}, "latest"]))
            index.setdefault(("decimals", token), len(calls) - 1)
            calls.append(
                ("eth_call", [{"to": token, "data": encode_balance_call(owner)}, "latest"])
            )
            index.setdefault(("balance", token), len(calls) - 1)

        results = []
        # Small batches: public endpoints close the connection on large
        # batch requests ("remote end closed connection"). 25 works
        # where 100 did not (verified 2026-11-18).
        chunk_size = 25
        for i in range(0, len(calls), chunk_size):
            results.extend(self.rpc.batch(calls[i : i + chunk_size]))
        # One retry round for failed slots: a transient RPC failure must
        # not silently degrade into a false "EOA" or "revoked" reading.
        failed = [i for i, r in enumerate(results) if r is None]
        if failed:
            # Retry in small chunks too: one giant retry batch gets its
            # connection closed like the original 100-call batches did.
            for j in range(0, len(failed), chunk_size):
                group = failed[j : j + chunk_size]
                try:
                    retry = self.rpc.batch([calls[i] for i in group])
                except Exception:  # noqa: BLE001 - keep Nones; scoring marks them unknown
                    continue
                for pos, i in enumerate(group):
                    if retry[pos] is not None:
                        results[i] = retry[pos]

        allowances = {}
        for token, spender in pairs:
            raw = results[index[("allowance", token, spender)]]
            allowances[(token, spender)] = hex_to_int(raw)
        codes = {}
        for spender in spenders:
            # None when the lookup failed: unknown code must never be
            # reported as an EOA (empty code).
            codes[spender] = results[index[("code", spender)]]
        meta = {}
        for token in tokens:
            meta[token] = {
                "name": decode_abi_string(results[index[("name", token)]]),
                "symbol": decode_abi_string(results[index[("symbol", token)]]),
                "decimals": decode_abi_uint(results[index[("decimals", token)]]),
                "balance": hex_to_int(results[index[("balance", token)]]),
            }
        return allowances, codes, meta

    # ---- full scan -------------------------------------------------------

    def scan(self, address, depth="full", max_pages=None, logs_window_blocks=None):
        started = time.time()
        if not is_valid_address(address):
            raise ValueError("invalid EVM address: %r" % (address,))
        owner = normalize_address(address)
        if depth == "quick":
            max_pages = 10 if max_pages is None else max_pages
            logs_window_blocks = 50000 if logs_window_blocks is None else logs_window_blocks
        else:
            max_pages = 120 if max_pages is None else max_pages
            logs_window_blocks = 200000 if logs_window_blocks is None else logs_window_blocks

        head_block = hex_to_int(self.rpc.call("eth_blockNumber", []))

        tx_events, tx_summary = self.scan_transactions(owner, max_pages)
        log_events, log_summary = self.scan_logs(owner, head_block, logs_window_blocks)

        # Aggregate by (token, spender).
        aggregated = {}
        for ev in tx_events + log_events:
            key = (ev["token"], ev["spender"])
            slot = aggregated.setdefault(
                key,
                {
                    "token": ev["token"],
                    "spender": ev["spender"],
                    "events": 0,
                    "sources": set(),
                    "first_block": None,
                    "last_block": None,
                    "first_seen_tx": None,
                    "last_amount": None,
                    "token_scam": False,
                    "token_name_hint": None,
                },
            )
            slot["events"] += 1
            slot["sources"].add(ev["source"])
            slot["token_scam"] = slot["token_scam"] or ev.get("token_scam", False)
            if ev.get("token_name_hint"):
                slot["token_name_hint"] = ev["token_name_hint"]
            blk = ev.get("block_number")
            if blk is not None:
                if slot["first_block"] is None or blk < slot["first_block"]:
                    slot["first_block"] = blk
                    slot["first_seen_tx"] = ev.get("tx_hash")
                if slot["last_block"] is None or blk > slot["last_block"]:
                    slot["last_block"] = blk
                    slot["last_amount"] = ev.get("amount")

        pairs = sorted(aggregated.keys())
        allowances, codes, meta = self.verify_pairs(pairs, owner) if pairs else ({}, {}, {})

        now = time.time()
        approvals = []
        for token, spender in pairs:
            slot = aggregated[(token, spender)]
            allowance = allowances.get((token, spender))
            token_meta = meta.get(token, {})
            decimals = token_meta.get("decimals")
            balance = token_meta.get("balance")
            code = codes.get(spender)
            if code is None:
                is_contract = None
            elif code.startswith("0xef0100"):
                # EIP-7702 delegation: an EOA with delegated code is
                # still an EOA, not a contract.
                is_contract = False
            else:
                is_contract = bool(code != "0x" and len(code) > 2)
            label = known.label_for(spender)
            flags, score = self._risk_flags(
                allowance=allowance,
                balance=balance,
                decimals=decimals,
                is_contract=is_contract,
                label=label,
                token_scam=slot["token_scam"],
                first_block=slot["first_block"],
                head_block=head_block,
                meta_ok=bool(token_meta.get("symbol") or token_meta.get("name")),
            )
            approvals.append(
                {
                    "token": token,
                    "token_name": token_meta.get("name") or slot.get("token_name_hint"),
                    "token_symbol": token_meta.get("symbol"),
                    "token_decimals": decimals,
                    "spender": spender,
                    "spender_label": label,
                    "spender_is_contract": is_contract,
                    "allowance_raw": str(allowance) if allowance is not None else None,
                    "allowance": self._human_amount(allowance, decimals),
                    "unlimited": allowance == MAX_UINT256,
                    "balance_raw": str(balance) if balance is not None else None,
                    "balance": self._human_amount(balance, decimals),
                    "status": (
                        "active"
                        if allowance is not None and allowance > 0
                        else "unknown"
                        if allowance is None
                        else "revoked"
                    ),
                    "risk_flags": flags,
                    "risk_score": score,
                    "first_seen_block": slot["first_block"],
                    "last_seen_block": slot["last_block"],
                    "events_seen": slot["events"],
                    "sources": sorted(slot["sources"]),
                    "first_seen_tx": slot["first_seen_tx"],
                }
            )

        approvals.sort(key=lambda a: (-a["risk_score"], a["token"], a["spender"]))
        active = [a for a in approvals if a["status"] == "active"]
        revoked = [a for a in approvals if a["status"] == "revoked"]
        unverified = [a for a in approvals if a["status"] == "unknown"]
        unlimited = [a for a in active if a["unlimited"]]
        eoa = [a for a in active if a["spender_is_contract"] is False]
        unknown = [a for a in active if not a["spender_label"]]
        unknown_code = [a for a in active if a["spender_is_contract"] is None]
        max_score = max((a["risk_score"] for a in active), default=0)
        level = (
            "CRITICAL"
            if max_score >= 80
            else "HIGH"
            if max_score >= 50
            else "MEDIUM"
            if max_score >= 20
            else "LOW"
        )

        limitations = [
            "ERC721/ERC1155 setApprovalForAll approvals are out of scope; this scan covers ERC20 allowances only.",
            "Approvals granted via EIP-2612 permit() older than the recent-logs window (%d blocks) may be missed if the permit was never submitted as an on-chain approve() call by the owner." % logs_window_blocks,
        ]
        if tx_summary.get("hit_page_cap"):
            limitations.append(
                "Transaction history scan hit the page cap (%d pages); approvals from transactions older than block %s were not scanned."
                % (tx_summary["pages_scanned"], tx_summary.get("earliest_block"))
            )
        if log_summary.get("chunk_errors"):
            limitations.append(
                "Some recent-log chunks failed (%d errors); recent permit-based approvals may be incomplete."
                % len(log_summary["chunk_errors"])
            )
        if unknown_code:
            limitations.append(
                "Spender code lookups failed for %d active approval(s); EOA vs contract is unknown for those (not assumed EOA)."
                % len(unknown_code)
            )
        if unverified:
            limitations.append(
                "%d approval(s) could not be verified (allowance unreadable); they are reported as unknown, not revoked."
                % len(unverified)
            )

        report = {
            "agent": "ApprovalGuard",
            "version": "1.0.0",
            "chain": self.chain_key,
            "chain_id": self.chain["chain_id"],
            "address": owner,
            "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "block_number": head_block,
            "scan_seconds": round(time.time() - started, 1),
            "coverage": {
                "depth": depth,
                "transactions_scanned": tx_summary["transactions_scanned"],
                "transaction_pages": tx_summary["pages_scanned"],
                "earliest_tx_block": tx_summary.get("earliest_block"),
                "logs_window_blocks": log_summary.get("window_blocks", 0),
                "logs_scanned": log_summary.get("log_events", 0),
                "sources": ["blockscout-tx-scan", "rpc-log-scan", "rpc-allowance-verify"],
                "limitations": limitations,
            },
            "summary": {
                "total_pairs_found": len(approvals),
                "active_approvals": len(active),
                "revoked_approvals": len(revoked),
                "unverified_approvals": len(unverified),
                "unlimited_approvals": len(unlimited),
                "eoa_spenders": len(eoa),
                "unknown_spenders": len(unknown),
                "risk_level": level,
                "risk_score": max_score,
                "plain_language": self._plain_language(
                    len(active),
                    len(unlimited),
                    len(eoa),
                    len(unknown),
                    level,
                    len(unverified),
                ),
                "recommendations": self._recommendations(unlimited, eoa, unknown),
            },
            "approvals": approvals,
        }
        return report

    @staticmethod
    def _human_amount(raw, decimals):
        if raw is None:
            return None
        if raw == MAX_UINT256:
            return "unlimited (2^256 - 1)"
        if decimals is None:
            return str(raw) + " (raw units)"
        try:
            scaled = raw / (10 ** decimals)
        except OverflowError:
            return str(raw) + " (raw units)"
        if scaled == int(scaled):
            return str(int(scaled))
        return ("%f" % scaled).rstrip("0").rstrip(".")

    @staticmethod
    def _risk_flags(
        allowance,
        balance,
        decimals,
        is_contract,
        label,
        token_scam,
        first_block,
        head_block,
        meta_ok,
    ):
        flags = []
        score = 0
        if allowance is None:
            flags.append(
                {
                    "code": "ALLOWANCE_UNREADABLE",
                    "detail": "Current allowance could not be read on-chain.",
                }
            )
            return flags, 10
        if allowance == 0:
            flags.append(
                {
                    "code": "REVOKED",
                    "detail": "Allowance is currently zero; this approval is inactive.",
                }
            )
            return flags, 0
        if allowance == MAX_UINT256:
            flags.append(
                {
                    "code": "UNLIMITED",
                    "detail": "Spender may transfer the token's entire balance, now and in the future.",
                }
            )
            score += 40
        elif balance is not None and allowance > balance:
            flags.append(
                {
                    "code": "EXCEEDS_BALANCE",
                    "detail": "Allowance exceeds the current token balance, so future deposits could also be drained.",
                }
            )
            score += 10
        if is_contract is False:
            flags.append(
                {
                    "code": "EOA_SPENDER",
                    "detail": "Spender is an externally owned account, not a contract. Legitimate approvals almost always target contracts.",
                }
            )
            score += 25
        elif is_contract is None:
            flags.append(
                {
                    "code": "SPENDER_CODE_UNKNOWN",
                    "detail": "Spender code could not be read on-chain; EOA vs contract is unknown.",
                }
            )
            score += 5
        if not label:
            flags.append(
                {
                    "code": "UNKNOWN_SPENDER",
                    "detail": "Spender is not a recognized protocol contract.",
                }
            )
            score += 15
        else:
            score -= 10
        if token_scam:
            flags.append(
                {
                    "code": "TOKEN_FLAGGED_SCAM",
                    "detail": "The token contract is flagged by the block explorer.",
                }
            )
            score += 30
        if first_block is not None and head_block is not None:
            age_blocks = head_block - first_block
            if age_blocks * 12 > STALE_AGE_SECONDS:
                flags.append(
                    {
                        "code": "STALE",
                        "detail": "Approval is older than ~180 days and still active.",
                    }
                )
                score += 10
        if not meta_ok:
            flags.append(
                {
                    "code": "TOKEN_METADATA_UNREADABLE",
                    "detail": "Token name/symbol could not be read on-chain.",
                }
            )
            score += 5
        return flags, max(0, min(100, score))

    @staticmethod
    def _plain_language(active, unlimited, eoa, unknown, level, unverified=0):
        if active == 0 and unverified == 0:
            return (
                "No active ERC20 approvals were found for this address. "
                "Nothing can currently move this address's tokens via approvals."
            )
        parts = [
            "%d active ERC20 approval(s) found. Overall risk: %s." % (active, level)
        ]
        if unlimited:
            parts.append(
                "%d approval(s) are UNLIMITED, meaning the spender can take the full balance at any time."
                % unlimited
            )
        if eoa:
            parts.append(
                "%d approval(s) target externally owned accounts instead of contracts, which is unusual and risky."
                % eoa
            )
        if unknown:
            parts.append(
                "%d approval(s) target spenders that are not recognized protocols." % unknown
            )
        if unverified:
            parts.append(
                "%d approval(s) could not be verified (allowance unreadable)."
                % unverified
            )
        return " ".join(parts)

    @staticmethod
    def _recommendations(unlimited, eoa, unknown):
        recs = []
        if unlimited or eoa or unknown:
            recs.append(
                "Review the flagged approvals below. Consider revoking unlimited approvals and approvals to unknown or externally owned spenders."
            )
            recs.append(
                "Revoke from your own wallet (for example via revoke.cash or your wallet's approval manager). ApprovalGuard never asks for keys and cannot revoke for you."
            )
        else:
            recs.append(
                "No high-risk approvals found. Re-check periodically, especially after using new dApps."
            )
        recs.append(
            "Prefer exact-amount approvals over unlimited ones when a dApp offers the choice."
        )
        return recs


def canonical_json(report_without_signature) -> bytes:
    """Deterministic JSON encoding used for signing and verification."""
    return json.dumps(
        report_without_signature, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
