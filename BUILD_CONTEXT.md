# ApprovalGuard — Build Context

How the agent works, the key decisions behind it, and the honest
limitations. Written for the Agent Games Wildcard submission.

## Architecture

```
                ┌─────────────────────────────┐
  HTTP client   │  app.py (ThreadingHTTPServer, stdlib only)
  (judge /      │  /health  /scan  /agent  /verify  /example  /
  platform)     └──────────────┬──────────────┘
                               │ scan(address, chain, depth)
                ┌──────────────▼──────────────┐
                │  scanner.py                 │
                │  L1 discovery: Blockscout   │  outgoing tx history
                │  L2 discovery: eth_getLogs  │  recent permit approvals
                │  verify: eth_call / code /  │  current allowance,
                │    metadata / balance       │  contract check, token info
                │  risk analysis + signing    │
                └──────┬──────────────┬───────┘
                       │              │
              blockscout.py         rpc.py
              (Blockscout v2,       (JSON-RPC batch,
               keyless)              multi-endpoint fallback)
```

Everything is **Python 3 standard library only** — no pip installs, no
native extensions, no API keys. The server is a `ThreadingHTTPServer`
listening on `0.0.0.0:$PORT` (default 8000).

### Discovery layer 1 — transaction history (full history)

The address's outgoing transactions are paginated from the Blockscout
v2 API (`/api/v2/addresses/{addr}/transactions?filter=from`, 50 per
page, cursor pagination). Each transaction's `raw_input` is decoded:
calls to `approve(address,uint256)` (`0x095ea7b3`),
`increaseAllowance` (`0x39509351`), and `decreaseAllowance`
(`0xa457c2d7`) are extracted, with the `decoded_input` field as a
fallback. This catches every approval the address ever *sent* — the
full history, no block-range limits. The spender and the most recent
approve call per (token, spender) pair are recorded.

### Discovery layer 2 — event logs (recent window)

Permit-based approvals (EIP-2612 `permit()` + `transferFrom`) never
appear as an `approve()` transaction from the owner, so L1 alone misses
them. L2 scans `Approval` events (`topic0 =
0x8c5be1...3b925`) with the owner as `topic1` over a recent window
(50k blocks quick / 200k blocks full) via `eth_getLogs`, chunked into
5,000-block requests across 8 threads, using DRPC as the logs endpoint
(free, keyless).

### Verification (current on-chain state)

Discovery tells us what was *approved*; verification tells us what is
*live now*. For every discovered (token, spender) pair the agent
batch-calls:

- `allowance(owner, spender)` — the current allowance (0 = revoked);
- `eth_getCode(spender)` — contract vs. externally-owned account;
- `name()` / `symbol()` / `decimals()` / `balanceOf(owner)` — token
  metadata and the balance the allowance is measured against.

Calls are batched (up to 100 per request) across multiple public RPC
endpoints with fallback and retries. Tokens whose metadata is
unreadable are reported as such rather than dropped.

### Risk model

Transparent additive scoring per approval:

| Flag | Weight | Meaning |
|---|---|---|
| `UNLIMITED` | +40 | Allowance is `2^256 - 1` |
| `EOA_SPENDER` | +25 | Spender is not a contract |
| `UNKNOWN_SPENDER` | +15 | No known label |
| `EXCEEDS_BALANCE` | +10 | Allowance > current balance |
| `STALE` | +10 | Last approval > ~180 days ago |
| `TOKEN_FLAGGED_SCAM` | +30 | Explorer tags the token as a scam |
| `TOKEN_METADATA_UNREADABLE` | +5 | Token contract doesn't answer metadata calls |
| `ALLOWANCE_UNREADABLE` | 10 (flat) | Allowance could not be read |
| `REVOKED` | 0 (flat) | Allowance is 0 — safe, shown for completeness |
| Known label | −10 | Curated well-known spender (Uniswap, Seaport, Aave, …) |

Overall level: LOW < 20, MEDIUM ≥ 20, HIGH ≥ 50, CRITICAL ≥ 80.
The plain-language summary and recommendations are generated from the
flags, not from a language model — the output is deterministic and
reproducible.

### Signing

Reports are signed with Ed25519 over the canonical JSON encoding
(`sort_keys=True`, `separators=(',',':')`, UTF-8) of the report minus
the `signature` block. The Ed25519 implementation is pure Python,
written from RFC 8032, and validated against the RFC's §7.1 test
vectors (TEST 1–3: key derivation, signing, and verification all
match). The keypair is generated on first run into `agent_key.json`
(mode 0600, gitignored); deployments can pin the same identity via the
`AGENT_SEED_HEX` environment variable (set in the host's secret env
config, never committed). The public key is published in the README,
`public_key.txt`, and `GET /health`. Verification is available via
`POST /verify` and the demo page.

## Key decisions and why

1. **Two discovery layers, not one.** A single source is not enough:
   transaction history misses permits; log scans are range-limited on
   free endpoints. Combining them covers both the full history and
   recent permit approvals. The report's `coverage` block states
   exactly what was scanned and what was not.

2. **Blockscout v2 transactions as the backbone.** The decisive
   experiment: querying Blockscout's v1 `getLogs` with `topic0` +
   `topic1` (owner) returned *no logs* for an Approval event that
   provably exists on-chain (USDC approval, block 18999xxx, verified
   by a topic0-only query over the same range). Topic1 filtering on
   that endpoint is broken/unreliable, so it cannot be the discovery
   source. The v2 transaction endpoint, by contrast, returned full
   pagination with `raw_input`/`decoded_input`/`method` reliably.

3. **Verification over trust.** Approvals are re-checked at scan time
   rather than trusting the historical approve call — a wallet may have
   revoked since, or spent down the allowance. Current state is what
   matters for risk.

4. **Read-only, keyless, no funds.** Every data source is a free public
   endpoint. The agent holds no wallet, no funds, and no credentials,
   so a compromised deployment cannot lose anything. The signing key is
   a dedicated no-value identity key.

5. **Deterministic output.** Risk flags and summaries are rule-based,
   not LLM-generated, so two scans of the same state produce the same
   report (up to timestamps/block numbers) and the signature is
   meaningful.

6. **Ethereum mainnet only, verified.** Other chains are configured but
   marked `rpc_only`: their Blockscout instances blocked automated
   access from the build environment (Cloudflare challenges / empty
   responses), and returning silently degraded results would be worse
   than a clear error. The scanner is chain-generic; enabling a chain
   is a one-line status change once its explorer is reachable.

## Endpoint contract — what the competition actually requires

Researched from the official pages on 2026-11-18
(agentgames.zkverify.io `/guide`, `/build`, `/rules`, `/events`,
`/events/wildcard`, `/register`).

**Wildcard requirements (from `/events/wildcard`):**

1. **Agent link** — a public repository, demo, or write-up showing the
   agent built.
2. **Public endpoint** — a public HTTPS endpoint for the agent, "as
   requested in the submission form."
3. **Use case** — explain the problem, who the agent helps, and what it
   actually does. *(This entry: `USE_CASE.md`.)*
4. **Build context** — briefly describe how the agent works and the key
   decisions behind it. *(This file.)*
5. **zkVerify (optional)** — if zkVerify strengthens the agent, explain
   the checkable claim and add a proof reference when available.
   Agents without zkVerify remain eligible.

**The endpoint contract question.** The HMAC-signed task contract
(`x-agent-games-signature` HMAC-SHA256 header, signed task envelope,
`GET /health`, 60-second deadline, signed preflight) is specified on
`/build` and `/rules` §1.2–1.3 for the **arena events** (Proof
Gatekeeper / Steal the VFY), where the platform dispatches tasks to the
agent. The Wildcard page does **not** reference that contract: it asks
only for "a public HTTPS endpoint for your agent," and Wildcard is
panel-judged, not platform-dispatched. **Conclusion: a Wildcard
endpoint does not need to follow the arena task contract; it needs to
be a working public HTTPS endpoint demonstrating the agent.**

Caveat: `/rules` §1.2 ("What an agent is") is written in general terms
— public HTTPS endpoint, no localhost/private IP/custom ports, respond
to signed task requests, sign responses with the HMAC secret issued at
registration, treat task IDs as idempotency keys. Because of that
general wording, this agent implements **both**: a natural scan API
(`GET/POST /scan`) *and* an HMAC-aware `POST /agent` endpoint that
verifies the platform signature (fail closed when the secret is
configured), signs responses, answers the preflight smoke task
immediately, and caches responses by task ID. Whichever contract the
judges or the platform use, the endpoint answers correctly.

Other competition facts that shaped the build: entry is free; tracks
close 21 Nov 2026 22:00 UTC; judging 22–30 Nov; one GitHub account per
competition account; `/rules` §1.4 warns that free-tier hosting that
sleeps after inactivity will cost tasks — see the deployment note
below.

## zkVerify stretch — verdict: not faked, documented for later

The stretch goal was a demo of verifying a proof via zkVerifyJS. On
reading the docs, both verification paths require account setup and
funds: Kurier (REST) needs a mainnet API key, and zkVerifyJS needs a
Volta session with a funded account. Neither was available without
account creation, which was out of scope for this build. So no zk
claim is made anywhere in this entry.

The honest verifiability story is: **Ed25519-signed reports over
publicly checkable on-chain data.** The checkable claim is "address X
has these live ERC20 approvals at block N" — anyone can re-derive it
from a public RPC and verify the signature. A future zkVerify
integration would prove the *computation* (e.g. a Groth16 proof that a
scan result follows from a set of RPC responses), and would slot in as
an additional `proof` field on the report alongside the signature.

## Data-source findings (from live probes, 2026-11-18)

| Source | Result |
|---|---|
| `ethereum.publicnode.com` | `eth_blockNumber`, batch `eth_call`, small `eth_getCode` work. Archive `eth_getLogs` → 403 (needs a personal token). Large `eth_getCode` responses truncated (`IncompleteRead`) from the dev VM. |
| `eth.drpc.org` | `eth_getLogs` works, max 10,000 blocks per request (use ≤5,000-block chunks). Large `eth_getCode` responses truncated (`IncompleteRead`) from the dev VM. |
| Cloudflare `cloudflare-eth.com` | Works for `eth_call`, max 800 blocks per `eth_getLogs` request. `eth_getCode` → `-32603 Internal error` in 2026-11-18 probes. |
| `eth.llamarpc.com` | HTTP 525 errors — unreliable, kept only as a fallback. |
| Ankr public (`rpc.ankr.com/eth`) | Requires an API key (`-32000 Unauthorized`) — unusable keyless, removed from rotation. |
| 1RPC (`1rpc.io/eth`) | Usage limit reached on the free plan (`-32001`) — removed from rotation. |
| 1RPC / Blast public | `eth_getLogs` capped at 50 / 10 blocks — too small for log scans. |
| Blockscout v2 tx list | Works, 50/page, cursor pagination, full calldata. |
| Blockscout v1 `getLogs` | Topic1 (owner) filtering returns no results for provably existing logs — **not used**. |
| Blockscout v2 `/approvals` | Does not exist (400 "Unknown API v2 action"). |
| Base/Polygon/Arbitrum/Optimism/BSC Blockscout | Cloudflare challenges / empty / 301 / 404 from the build environment — chains left `rpc_only`. |

## Deployment note (hosting)

The agent is a single process serving HTTP; any host that runs
`python3 app.py` with a `PORT` env var works. For the submission, a
stable public HTTPS URL is needed, and the build environment's VM is
not a durable host (it can be replaced and processes stopped). Free
options researched (no credit card):

- **Render (recommended):** free web service, no card, 750
  instance-hours/month per workspace, deploys from a GitHub repo,
  stable `*.onrender.com` HTTPS URL. Sleeps after 15 minutes idle with
  a ~30–60s cold start — acceptable for a panel-judged Wildcard entry
  (the demo page and `/example` make the output visible even before a
  scan runs), but note it in the submission. Start command:
  `python3 app.py`; set `AGENT_SEED_HEX` in Render's env config to
  keep the published public key, and `AGENT_GAMES_SECRET` if the
  platform issues one.
- **Railway trial (backup):** one-time $5 credit, no card, stays awake
  24/7 — but the credit is finite; the service stops when it runs out.
  Usable for the submission window, risky for the judging period.
- **Not recommended:** Hugging Face Spaces (Docker/compute Spaces now
  require a paid PRO plan as of late 2026 — free accounts get 402);
  PythonAnywhere free tier (outbound internet restricted to an
  allowlist that is unlikely to include these RPC/explorer hosts, and
  it is WSGI-only, which would need an adapter); tunnel services
  (ephemeral URLs, depend on the VM staying up).

## Limitations (stated in every report's coverage block)

- ERC20 only. ERC721/ERC1155 approvals (`setApprovalForAll`,
  `approve` on NFTs) are out of scope for this entry.
- Permit-based approvals older than the log-scan window (50k/200k
  blocks) may be missed; transaction-history discovery covers the full
  history for `approve()` calls only.
- The known-spender list is small and curated; unknown spenders are
  flagged as unknown, which is conservative but can over-flag
  legitimate new protocols.
- Scans depend on free public endpoints; if Blockscout or the RPC
  endpoints are slow or down, scans slow down or fail loudly (never
  silently partial). Failed lookups are reported as unknown
  (`SPENDER_CODE_UNKNOWN`, `ALLOWANCE_UNREADABLE`, `unknown` status),
  never guessed: an early live run falsely flagged every spender as
  an EOA because failed code lookups were coerced to empty code, and
  the scoring was fixed the same day (tri-state contract detection,
  chunked retries, stub-test coverage in
  `tests/test_scan_stubs.py`).
- Contract-vs-EOA detection could not be verified live from the dev
  environment (large `eth_getCode` responses truncated by the network
  path; see data-source findings). EIP-7702 delegation code
  (`0xef0100…`) is treated as an EOA, not a contract.
- Risk scores are a heuristic starting point for human review, not a
  security audit.
