# ApprovalGuard — Use Case

## The problem

ERC20 token approvals are one of the most quietly dangerous habits in
crypto. To use a DEX, a marketplace, or a lending app, a wallet must
first call `approve()` — granting that app's contract permission to move
its tokens. Most wallets and dapps default to **unlimited** approval:
`2^256 - 1`, i.e. "spend all of this token, forever." People click
through, use the app once, and forget. Months later, the approval is
still live.

That leftover permission is a real attack surface:

- **Contract exploits.** If an approved contract is later hacked or
  found vulnerable, the attacker can drain approved tokens from every
  wallet that never revoked. This has happened repeatedly in DeFi
  history (exploits where the damage was multiplied by stale unlimited
  approvals).
- **Phishing and fake dapps.** A single approval granted to a malicious
  contract hands it the same unlimited permission — and the theft often
  happens days later, long after the victim stopped paying attention.
- **Invisible accumulation.** Active users collect dozens of approvals
  across tokens and protocols. No wallet UI shows the full list in one
  place, and few people know what they approved a year ago.

Existing tools that show approvals (revoke.cash, wallet explorers) are
interactive dashboards: you have to open them, connect or paste, and
interpret raw tables. There is no simple, agent-friendly way to ask
"how exposed is this address, and what should I do about it?" — and no
signed, shareable report that a second party can verify.

## Who it helps

- **Everyday wallet users** — the person who has used a few DeFi apps
  and wants a plain-language answer: *am I exposed, and what should I
  revoke first?* ApprovalGuard answers without asking for anything
  sensitive.
- **Airdrop / whitelist grinders and multi-wallet users** — people who
  interact with many new contracts and need a fast hygiene check across
  addresses (one HTTP call per address).
- **Security-minded communities and support helpers** — anyone who
  helps newcomers can point them at a link or share a signed report
  instead of walking them through an explorer.
- **Agents and automation** — ApprovalGuard is itself an agent with an
  HTTP API, so other agents, bots, or scheduled jobs can integrate the
  scan and act on the structured output (e.g. alert when a new
  unlimited approval appears).

## What the agent actually does

Given an EVM address (and chain), ApprovalGuard:

1. **Discovers approvals** from two independent on-chain sources:
   the address's full outgoing-transaction history (catching every
   `approve()` call it ever made) and a recent-window event-log scan
   (catching permit-based approvals that never appear as transactions).
2. **Verifies current state** on-chain: the allowance as it stands now,
   whether the spender is a contract, and the token's name, symbol,
   decimals, and the wallet's current balance.
3. **Flags risks** with a transparent scoring model: unlimited
   allowances, externally-owned spenders (a contract should be a
   contract), unknown spenders, stale approvals older than ~180 days,
   allowances exceeding the balance, and tokens flagged as scams by
   the explorer. Each flag carries a plain-language explanation.
4. **Explains in plain language**: a summary sentence, an overall risk
   level (LOW / MEDIUM / HIGH / CRITICAL), and prioritized
   recommendations — starting with "revoke the unlimited approvals to
   unknown spenders first."
5. **Signs the report** with Ed25519, so the output is verifiable:
   anyone can check that the report came from this agent and was not
   altered, using the public key in the README or `GET /health`.

What it deliberately does **not** do: it never asks for a seed phrase,
private key, or wallet connection; it holds no funds; it cannot revoke
or move anything. It is a read-only scanner. Revocation remains the
wallet owner's action, in their own wallet.

## Why this fits the Wildcard track

The Wildcard track explicitly lists *"Wallet & transaction guard — an
agent that screens approvals and transactions for scams or risky
permissions before signing"* as a suggested use case. ApprovalGuard is
exactly that, built as a working, publicly accessible agent with a
verifiable output format. The Ed25519-signed report is the honest
version of the competition's "proofs decide" idea for an off-chain
scanner: the claim "this address has these live approvals" is checkable
by anyone against public chain data, and the signature binds the
report to the agent that produced it. A future zkVerify integration
(proving the scan computation itself) is documented in
`BUILD_CONTEXT.md`; it was not faked for this entry.

## Example

Scanning vitalik.eth's public address returns its live ERC20 approvals
with risk flags and a plain-language summary — try it on the demo page
or with:

```sh
curl "https://<endpoint>/scan?address=0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045&chain=ethereum&depth=quick"
```
