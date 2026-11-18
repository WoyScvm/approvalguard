"""Curated labels for well-known spender contracts (Ethereum mainnet).

A label here means "this address is a widely used, public protocol
contract" -- it is a convenience to reduce false alarms, NOT a security
audit and NOT a guarantee that an approval to it is safe. Unlimited
approvals are still flagged even for labelled spenders.

Only addresses the author is confident about are listed. The list is
deliberately small; unknown spenders are flagged as unknown, which is
the safe default for a security scanner.
"""

KNOWN_SPENDERS = {
    # Uniswap
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 SwapRouter",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap SwapRouter02",
    "0x000000000022d473030f116ddee9f6b43ac78ba3": "Uniswap Permit2",
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router",
    # OpenSea
    "0x00000000000000adc04c56bf30ac9d3f4458fa10": "OpenSea Seaport 1.5",
    "0x00000000006c3852cbef3e08e8df289169ede581": "OpenSea Seaport 1.1",
    # Aggregators
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch v5 Router",
    "0xdef1c0ded9bec7f1a1670819833240f027b25ef7": "0x Exchange Proxy",
    # Lending
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": "Aave V3 Pool",
    "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9": "Aave V2 LendingPool",
    "0x3dfd23a6c5e8bbcfc9581d2e728b4fae6d310657": "Aave V3 Pool (alt)",
    # Stablecoins / infra commonly approved
    "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI Token (self-approval / DSProxy use)",
}


def label_for(spender: str):
    return KNOWN_SPENDERS.get(spender.lower())
