"""Chain configuration.

Only chains whose data sources were actually verified from this
environment are enabled for full scans. Discovery uses the chain's
Blockscout v2 API (no key needed); verification uses public JSON-RPC
endpoints (no key needed).

Status key:
  verified  -- discovery + verification tested end-to-end (2026-11-18)
  rpc_only  -- RPC endpoints respond, but the explorer blocks automated
               access from this environment, so approval discovery is
               unavailable; scans return a clear error for these chains.

Ethereum is the verified chain. The config table keeps the other major
EVM chains ready: if their explorers become reachable, flip the status
and the same code paths run unchanged.
"""

CHAINS = {
    "ethereum": {
        "chain_id": 1,
        "name": "Ethereum",
        "status": "verified",
        "blockscout": "https://eth.blockscout.com",
        "rpc_urls": [
            "https://ethereum.publicnode.com",
            "https://eth.drpc.org",
            "https://cloudflare-eth.com",
            "https://eth.llamarpc.com",
        ],
        "logs_rpc": "https://eth.drpc.org",
        "logs_rpc_urls": [
            "https://eth.drpc.org",
            "https://cloudflare-eth.com",
            "https://eth.llamarpc.com",
        ],
        "logs_max_range": 5000,
        "explorer_tx": "https://etherscan.io/tx/",
        "explorer_address": "https://etherscan.io/address/",
    },
    "base": {
        "chain_id": 8453,
        "name": "Base",
        "status": "rpc_only",
        "blockscout": "https://base.blockscout.com",
        "rpc_urls": [
            "https://mainnet.base.org",
            "https://base.llamarpc.com",
        ],
        "logs_rpc": None,
        "logs_max_range": 0,
        "explorer_tx": "https://basescan.org/tx/",
        "explorer_address": "https://basescan.org/address/",
    },
    "arbitrum": {
        "chain_id": 42161,
        "name": "Arbitrum One",
        "status": "rpc_only",
        "blockscout": "https://arbitrum.blockscout.com",
        "rpc_urls": [
            "https://arb1.arbitrum.io/rpc",
            "https://arbitrum.llamarpc.com",
        ],
        "logs_rpc": None,
        "logs_max_range": 0,
        "explorer_tx": "https://arbiscan.io/tx/",
        "explorer_address": "https://arbiscan.io/address/",
    },
    "optimism": {
        "chain_id": 10,
        "name": "Optimism",
        "status": "rpc_only",
        "blockscout": "https://optimism.blockscout.com",
        "rpc_urls": [
            "https://mainnet.optimism.io",
            "https://optimism.llamarpc.com",
        ],
        "logs_rpc": None,
        "logs_max_range": 0,
        "explorer_tx": "https://optimistic.etherscan.io/tx/",
        "explorer_address": "https://optimistic.etherscan.io/address/",
    },
    "polygon": {
        "chain_id": 137,
        "name": "Polygon",
        "status": "rpc_only",
        "blockscout": "https://polygon.blockscout.com",
        "rpc_urls": [
            "https://polygon-rpc.com",
            "https://polygon.llamarpc.com",
        ],
        "logs_rpc": None,
        "logs_max_range": 0,
        "explorer_tx": "https://polygonscan.com/tx/",
        "explorer_address": "https://polygonscan.com/address/",
    },
    "bsc": {
        "chain_id": 56,
        "name": "BNB Smart Chain",
        "status": "rpc_only",
        "blockscout": None,
        "rpc_urls": [
            "https://bsc-dataseed.binance.org",
            "https://bsc.publicnode.com",
        ],
        "logs_rpc": None,
        "logs_max_range": 0,
        "explorer_tx": "https://bscscan.com/tx/",
        "explorer_address": "https://bscscan.com/address/",
    },
}


def get_chain(name: str):
    key = (name or "ethereum").strip().lower()
    if key in ("eth", "mainnet", "ethereum"):
        key = "ethereum"
    if key not in CHAINS:
        raise ValueError(
            "unknown chain %r; supported: %s" % (name, ", ".join(sorted(CHAINS)))
        )
    return key, CHAINS[key]
