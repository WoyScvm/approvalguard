"""Agent signing keypair management.

The agent signs every scan report with a dedicated Ed25519 keypair so
reports are verifiable. The keypair:

- is generated locally with os.urandom (never derived from any wallet),
- lives ONLY in the project directory (agent_key.json, mode 0600),
- is NEVER committed to git (see .gitignore) and holds no funds,
- has its PUBLIC key published in README.md, public_key.txt, and the
  /health endpoint so anyone can verify signatures.

If the key file is missing at startup, a fresh keypair is generated and
the new public key is printed. A fresh deployment therefore has a fresh
identity: update the published public key accordingly.
"""

import json
import os

from . import ed25519

DEFAULT_KEY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "agent_key.json",
)


def load_or_generate_keypair(key_file: str = None):
    """Return (seed_bytes, public_key_bytes).

    Resolution order:
      1. AGENT_SEED_HEX env var (deployments: set the seed in the host's
         secret env config so the deployed identity matches the published
         public key without committing any secret material).
      2. The key file (generated on first run if missing).
    """
    env_seed = os.environ.get("AGENT_SEED_HEX", "").strip()
    if env_seed:
        seed = bytes.fromhex(env_seed)
        if len(seed) != 32:
            raise ValueError("AGENT_SEED_HEX must be 32 bytes (64 hex chars)")
        return seed, ed25519.public_key_from_seed(seed)
    path = key_file or os.environ.get("AGENT_KEY_FILE") or DEFAULT_KEY_FILE
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        seed = bytes.fromhex(data["seed_hex"])
        public_key = ed25519.public_key_from_seed(seed)
        return seed, public_key
    seed = os.urandom(32)
    public_key = ed25519.public_key_from_seed(seed)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "seed_hex": seed.hex(),
                "public_key_hex": public_key.hex(),
                "algorithm": "Ed25519",
                "warning": (
                    "Agent signing key. Holds no funds. "
                    "Never commit this file. Never reuse for anything else."
                ),
            },
            fh,
            indent=2,
        )
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)
    return seed, public_key
