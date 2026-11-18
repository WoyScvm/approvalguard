# ApprovalGuard 🛡️

**A wallet-approval security scanner agent — Agent Games (ZkVerify) Wildcard entry.**

Paste any EVM address. ApprovalGuard scans its ERC20 token approvals from
public on-chain data, flags the risky ones in plain language, and returns a
report signed with the agent's Ed25519 key so anyone can verify it.

No sign-in. No API keys. No funds. Read-only: it never asks for a seed
phrase, private key, or signature, and it cannot revoke anything.

- **Competition:** [Agent Games by ZkVerify](https://agentgames.zkverify.io/) — Wildcard track
- **Live demo:** https://approvalguard-production.up.railway.app (Railway trial; `/health`, `/scan`, `/example`)
- **Agent public key (Ed25519, hex):** `2357efc2a0fc150b830003c2ae5f13efb2e6c8ae33d4e89eeafa926b97b63400`
  (also in `public_key.txt` and `GET /health`)

## What it does

1. **Discovers** ERC20 approvals for an address:
   - full-history scan of outgoing transactions, parsing `approve()` /
     `increaseAllowance()` calls (Blockscout v2 API, no key);
   - a recent-window `eth_getLogs` scan for permit-based approvals
     (public JSON-RPC, no key).
2. **Verifies** every approval's *current* allowance on-chain via
   `eth_call`, checks whether each spender is a contract (`eth_getCode`),
   and reads token metadata (`name`/`symbol`/`decimals`/`balanceOf`).
3. **Flags risks:** unlimited allowances, externally owned spenders,
   unknown spenders, stale approvals, allowances exceeding the balance,
   explorer-flagged scam tokens — with a 0–100 risk score and a
   plain-language summary + recommendations.
4. **Signs** every report with Ed25519 (pure-Python RFC 8032
   implementation, validated against the RFC test vectors). Verify any
   report with `POST /verify` or the demo page.

See [USE_CASE.md](USE_CASE.md) for the problem and who it helps, and
[BUILD_CONTEXT.md](BUILD_CONTEXT.md) for architecture, key decisions,
honest limitations, and the endpoint-contract analysis.

## Run it (one command, zero dependencies)

Python 3.10+ standard library only. Nothing to install.

```sh
python3 app.py            # listens on http://0.0.0.0:8000
# or
./run.sh 8000
# or
PORT=8080 python3 app.py
```

Open http://localhost:8000 for the demo page (form + example output).

On first start the server generates its Ed25519 signing keypair into
`agent_key.json` (mode `0600`, gitignored) and prints the public key.
To deploy with the *same* identity, set the seed in the host's secret
environment instead of copying the file:

```sh
AGENT_SEED_HEX=<64 hex chars> python3 app.py
```

Optional: `AGENT_GAMES_SECRET=<platform HMAC secret>` enables
verification/signing of the `x-agent-games-signature` header on
`POST /agent` (see "Agent Games envelope" below).

## API

### `GET /health`

```json
{
  "status": "ok",
  "agent": "ApprovalGuard",
  "version": "1.0.0",
  "platform_version": "1.0",
  "public_key": "2357efc2a0fc150b830003c2ae5f13efb2e6c8ae33d4e89eeafa926b97b63400",
  "signature_algorithm": "Ed25519",
  "chains": ["arbitrum", "base", "bsc", "ethereum", "optimism", "polygon"],
  "verified_chains": ["ethereum"]
}
```

### `GET /scan?address=0x...&chain=ethereum&depth=quick`

### `POST /scan`

```json
{"address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "chain": "ethereum", "depth": "full"}
```

`depth` is `quick` (10 transaction pages + 50k-block log window) or
`full` (120 pages + 200k-block log window). Response: the signed report
(truncated example):

```json
{
  "agent": "ApprovalGuard",
  "version": "1.0.0",
  "chain": "ethereum",
  "chain_id": 1,
  "address": "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
  "scanned_at": "2026-11-18T07:00:00Z",
  "block_number": 26400000,
  "scan_seconds": 42.0,
  "coverage": {"depth": "full", "transactions_scanned": 5000, "sources": ["blockscout-tx-scan", "rpc-log-scan", "rpc-allowance-verify"], "limitations": ["..."]},
  "summary": {
    "active_approvals": 1,
    "unlimited_approvals": 1,
    "risk_level": "HIGH",
    "risk_score": 55,
    "plain_language": "1 active ERC20 approval found. Overall risk: HIGH. 1 approval is UNLIMITED...",
    "recommendations": ["Review the flagged approvals below..."]
  },
  "approvals": [
    {
      "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
      "token_symbol": "USDC",
      "spender": "0x1111111254eeb25477b68fb85ed929f73a960582",
      "spender_label": "1inch v5 Router",
      "spender_is_contract": true,
      "allowance": "unlimited (2^256 - 1)",
      "unlimited": true,
      "status": "active",
      "risk_flags": [{"code": "UNLIMITED", "detail": "..."}],
      "risk_score": 30
    }
  ],
  "signature": {
    "algorithm": "Ed25519",
    "public_key": "2357efc2a0fc150b830003c2ae5f13efb2e6c8ae33d4e89eeafa926b97b63400",
    "signature": "<128 hex chars>",
    "signed_encoding": "canonical JSON: sort_keys=True, separators=(',',':'), UTF-8",
    "verify_with": "POST /verify with this full report object"
  }
}
```

### `POST /agent` — Agent Games envelope

Accepts the platform task envelope (`task_id` / `mode` / `task` payload
carrying an address). Preflight tasks (`mode: "preflight"` or
`task_id: "preflight_smoke_1"`) get an immediate `READY` response
without a scan. When `AGENT_GAMES_SECRET` is set, the
`x-agent-games-signature` HMAC-SHA256 header is verified against the raw
request body before any work (fail closed, 401 on mismatch) and
responses carry the same signature header. Responses are cached by
`task_id` so platform retries are idempotent.

```json
{"task_id": "scan_1", "mode": "task", "task": {"address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "chain": "ethereum", "depth": "quick"}}
```

### `POST /verify`

```json
{"report": { "...full signed report object..." }}
```

Response: `{"valid": true, "algorithm": "Ed25519", "public_key": "...", "reason": "signature valid"}`.
Accepts an optional top-level `public_key` to verify against a
different key.

### `GET /example`

A signed example report. Until a real scan is run, this serves a
**clearly labeled synthetic schema example** (its `coverage.limitations`
and summary say so). Running `python3 tests/test_live.py` overwrites it
with a real signed scan.

## Tests

```sh
python3 -m unittest discover -s tests -v   # 33 tests, no network needed
```

- `tests/test_ed25519.py` — RFC 8032 §7.1 vectors (key derivation,
  signing, verification), round-trips, tamper rejection.
- `tests/test_scanner_unit.py` — approval calldata parsing, risk-flag
  logic, canonical-JSON signing determinism.
- `tests/test_scan_stubs.py` — end-to-end scan with stubbed RPC +
  explorer: contract vs EOA vs unknown code (incl. EIP-7702
  delegation), active vs revoked vs unknown status, honest summary
  counts.
- `tests/test_api.py` — live local server: `/health`, demo page, input
  validation, `/verify` round-trip, `/agent` preflight + HMAC
  enforcement (including response signing) and idempotency.
- `tests/test_live.py` — real end-to-end scan against public chain data
  (needs network; see test status below).

## Test status (honest)

- **Unit + API + stub tests: 33/33 pass** (2026-11-18, Python 3.12.3).
- **Full live end-to-end scan: COMPLETED 2026-11-18** (block 26441736,
  291.6s, vitalik.eth, quick depth): 213 pairs found, 197 active, 3
  revoked, 13 unverified (allowance unreadable), 56 unlimited; the
  signed report is served by `/example` and saved as
  `example_report.json`. Signature verified valid.
- **What could NOT be verified live from the dev environment:**
  `eth_getCode` for large contract bytecode systematically failed
  from this VM (connections truncated — `IncompleteRead` — on
  publicnode/DRPC; `Internal error` from Cloudflare), so
  contract-vs-EOA detection returned "unknown" for all 213 spenders
  in the live run, and the report says so explicitly instead of
  guessing. Small `eth_getCode` responses (EOAs) work fine from the
  same endpoints, and the contract/EOA/unknown logic (including
  EIP-7702 delegation handling) is proven by
  `tests/test_scan_stubs.py`. A deployment on a normal network is
  expected to read contract code normally. The log layer also had 5
  failed chunks (0 logs) in the live run, so permit-based coverage
  is unverified live.

  ```sh
  python3 tests/test_live.py   # scans vitalik.eth, quick depth, saves example_report.json
  python3 tests/test_live.py 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 full
  ```

## Chains

Ethereum mainnet is fully verified. Base, Arbitrum, Optimism, Polygon,
and BSC are configured (RPC + explorer URLs in
`approvalguard/chains.py`) but their Blockscout instances blocked
automated access from the build environment, so scans for those chains
currently return a clear error instead of silently degraded results.
The scanner code is chain-generic: flip a chain's status to `verified`
once its explorer is reachable and the same code paths run unchanged.

## Security notes

- The agent keypair (`agent_key.json`) holds no funds and is used only
  to sign reports. It is gitignored and must never be committed. The
  Ed25519 implementation is non-constant-time; that is acceptable for
  signing public reports with a dedicated no-value key, and it is not
  suitable for high-value signing.
- No secrets, API keys, or wallet keys exist anywhere in this project.
  All data sources are keyless public endpoints.
- The curated "known spender" list (`approvalguard/known.py`) is a
  convenience to reduce false alarms, not a security audit. Unknown
  spenders are flagged as unknown by default.
- This tool reports on-chain state; it is not financial or security
  advice. Revocation must always be done by the wallet owner.

## Project layout

```
app.py                    HTTP server + Agent Games envelope + signing
approvalguard/
  ed25519.py              Pure-Python Ed25519 (RFC 8032)
  keys.py                 Agent keypair load/generate
  chains.py               Chain + data-source configuration
  rpc.py                  JSON-RPC client (batch, fallback, retries)
  blockscout.py           Blockscout v2 client (tx pagination)
  known.py                Curated well-known spender labels
  scanner.py              Discovery + verification + risk analysis
static/index.html         Demo page (form + results + signature check)
tests/                    Unit, API, and live tests
example_report.json       Signed example report (schema demo until a real scan runs)
public_key.txt            Agent Ed25519 public key
USE_CASE.md               Problem, users, what the agent does
BUILD_CONTEXT.md          Architecture, decisions, limitations, contract analysis
```
