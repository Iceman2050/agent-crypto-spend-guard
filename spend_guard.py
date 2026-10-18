#!/usr/bin/env python3
"""agent-crypto-spend-guard — EVM JSON-RPC policy sidecar for AI agents.

Inspects outgoing EVM JSON-RPC requests (eth_sendTransaction,
eth_sendRawTransaction, contract deployments) and enforces:

  * testnet-only by default — mainnet destinations are REJECTED unless the
    policy explicitly allows them.
  * per-agent wei spend caps with a running ledger.
  * a deployment-approval gate — contract deployments need explicit approval.
  * seed-phrase-derived wallet detection — flags an agent spending from an
    address derived from publicly known dev recovery phrases (a wallet it was
    never given). See README hook: the Oct 2026 OpenAI GPT-5.6 Sol incident.

Every inspected request is appended to a request-replay audit log (JSONL).

Exit codes: 0 = ALLOWED, 1 = BLOCKED (policy violation), 2 = input/usage error.
The exit codes make this CI-failable: a blocked request fails the step.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Known networks
# ---------------------------------------------------------------------------
CHAIN_NAMES = {
    1: "ethereum-mainnet",
    11155111: "sepolia",
    17000: "holesky",
    5: "goerli",
    137: "polygon-mainnet",
    80002: "polygon-amoy",
    8453: "base-mainnet",
    84532: "base-sepolia",
    42161: "arbitrum-mainnet",
    421614: "arbitrum-sepolia",
    10: "optimism-mainnet",
    11155420: "optimism-sepolia",
    56: "bsc-mainnet",
    97: "bsc-testnet",
}
MAINNET_CHAIN_IDS = {1, 137, 8453, 42161, 10, 56}


# ---------------------------------------------------------------------------
# Fixture seed-phrase derivation (TESTS ONLY)
# ---------------------------------------------------------------------------
def _fixture_keccak(data: bytes) -> bytes:
    """Fixture derivation for tests; production should use a real keccak lib.

    This is a deterministic SHA-256-based placeholder standing in for
    keccak-256 so the test suite runs with zero dependencies. It is NOT
    keccak and the addresses it produces are NOT real Ethereum addresses
    derived from these phrases. In production, replace with eth-hash /
    pycryptodome keccak and a real BIP-39/BIP-44 derivation path
    (m/44'/60'/0'/0/n).
    """
    return hashlib.sha256(b"FIXTURE-KECCAK-NOT-REAL:" + data).digest()


# Publicly documented dev/test recovery phrases used as FIXTURES.
# These are the classic example phrases from BIP-39 test vectors / tutorials —
# they are public knowledge, which is exactly the point: an agent that picks
# one of these up and spends from a derived address is spending someone else's
# money. NEVER fund these on a real network.
FIXTURE_SEEDS = [
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
]


def derive_fixture_addresses(seeds=FIXTURE_SEEDS, per_seed: int = 3) -> set[str]:
    """Derive a set of fixture addresses from the fixture seeds.

    Uses _fixture_keccak (placeholder — see its docstring). Production code
    must substitute a real keccak-256 + BIP-44 derivation.
    """
    addrs: set[str] = set()
    for seed in seeds:
        for idx in range(per_seed):
            digest = _fixture_keccak(f"{seed}:{idx}".encode("utf-8"))
            addrs.add("0x" + digest[-20:].hex())
    return addrs


def _load_fixture_address_file() -> set[str]:
    """Load the shipped fixture address list (data/known_seed_addresses.json)."""
    here = Path(__file__).resolve().parent
    fixture = here / "data" / "known_seed_addresses.json"
    if fixture.exists():
        try:
            return {a.lower() for a in json.loads(fixture.read_text())}
        except (json.JSONDecodeError, OSError):
            return set()
    return set()


# The fixture address set: precomputed list + anything derived at runtime.
KNOWN_SEED_DERIVED_ADDRESSES: set[str] = (
    _load_fixture_address_file() | {a.lower() for a in derive_fixture_addresses()}
)


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------
@dataclass
class Policy:
    testnet_only: bool = True
    allowed_mainnets: list = field(default_factory=list)  # chain ids
    spend_caps_wei: dict = field(default_factory=dict)  # agent_id -> wei cap
    allow_deploys: bool = False
    seed_derived_addresses: set = field(
        default_factory=lambda: set(KNOWN_SEED_DERIVED_ADDRESSES)
    )

    @classmethod
    def from_dict(cls, raw: dict) -> "Policy":
        raw = raw or {}
        return cls(
            testnet_only=raw.get("testnet_only", True),
            allowed_mainnets=list(raw.get("allowed_mainnets", [])),
            spend_caps_wei={str(k): int(v) for k, v in raw.get("spend_caps_wei", {}).items()},
            allow_deploys=bool(raw.get("allow_deploys", False)),
            seed_derived_addresses={
                str(a).lower()
                for a in raw.get(
                    "seed_derived_addresses", KNOWN_SEED_DERIVED_ADDRESSES
                )
            },
        )


# ---------------------------------------------------------------------------
# Request parsing
# ---------------------------------------------------------------------------
def parse_hex_int(value) -> int:
    """Parse a wei value from hex string ("0x..."), decimal string, or int."""
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


def normalize_request(raw: dict) -> dict:
    """Normalize an eth_sendTransaction / eth_sendRawTransaction request.

    Raises ValueError on malformed input.
    """
    if not isinstance(raw, dict):
        raise ValueError("request must be a JSON object")
    method = raw.get("method")
    if method not in ("eth_sendTransaction", "eth_sendRawTransaction"):
        raise ValueError(f"unsupported method: {method!r} (expected eth_sendTransaction or eth_sendRawTransaction)")
    params = raw.get("params") or []
    tx = params[0] if params and isinstance(params[0], dict) else {}
    if method == "eth_sendRawTransaction":
        # Raw tx: signed blob; we inspect what metadata is provided alongside.
        tx = dict(tx)
    chain_id = raw.get("chainId", tx.get("chainId"))
    try:
        chain_id = int(chain_id) if chain_id is not None else None
    except (TypeError, ValueError):
        raise ValueError(f"unparseable chainId: {chain_id!r}")
    to = tx.get("to")
    is_deploy = to in (None, "", "0x", "0x0000000000000000000000000000000000000000")
    return {
        "method": method,
        "chain_id": chain_id,
        "from": (tx.get("from") or "").lower(),
        "to": (to or "").lower(),
        "value_wei": parse_hex_int(tx.get("value")),
        "is_deploy": bool(is_deploy),
        "data_len": len(str(tx.get("data") or "")),
    }


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------
def evaluate(policy: Policy, agent_id: str, req: dict, ledger: dict) -> tuple[bool, list[str]]:
    """Evaluate one normalized request. Returns (allowed, reasons)."""
    reasons: list[str] = []
    chain_id = req["chain_id"]

    # 1. Unknown network -> deny.
    if chain_id is None:
        return False, ["DENY: missing chainId — cannot verify destination network"]
    if chain_id not in CHAIN_NAMES:
        return False, [f"DENY: unknown chainId {chain_id} — refusing to sign blind"]

    # 2. Testnet-only enforcement.
    if policy.testnet_only and chain_id in MAINNET_CHAIN_IDS and chain_id not in policy.allowed_mainnets:
        reasons.append(
            f"DENY: mainnet destination ({CHAIN_NAMES[chain_id]}) blocked by testnet-only policy"
        )
        return False, reasons

    # 3. Seed-phrase-derived wallet detection.
    if req["from"] and req["from"] in policy.seed_derived_addresses:
        reasons.append(
            "DENY: from-address matches a known public-seed-phrase-derived address — "
            "agent is spending from a wallet it was never given (possible key derivation from a public recovery phrase)"
        )
        return False, reasons

    # 4. Deployment-approval gate.
    if req["is_deploy"] and not policy.allow_deploys:
        reasons.append("DENY: contract deployment requires explicit approval (allow_deploys=false)")
        return False, reasons

    # 5. Per-agent spend cap.
    cap = policy.spend_caps_wei.get(agent_id)
    if cap is not None:
        spent = ledger.get(agent_id, 0)
        if spent + req["value_wei"] > cap:
            reasons.append(
                f"DENY: spend cap exceeded for agent {agent_id!r} "
                f"(spent {spent} + tx {req['value_wei']} > cap {cap} wei)"
            )
            return False, reasons

    reasons.append(
        f"ALLOW: {CHAIN_NAMES[chain_id]}, value {req['value_wei']} wei, "
        f"deploy={req['is_deploy']}"
    )
    return True, reasons


def apply_ledger(ledger: dict, agent_id: str, req: dict) -> None:
    """Record an ALLOWED transaction in the running ledger (in place)."""
    ledger[agent_id] = ledger.get(agent_id, 0) + req["value_wei"]


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
def audit(log_path: Path, agent_id: str, raw_method, req: dict, allowed: bool, reasons: list[str]) -> None:
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "agent_id": agent_id,
        "method": raw_method,
        "chain_id": req.get("chain_id"),
        "from": req.get("from"),
        "to": req.get("to"),
        "value_wei": req.get("value_wei"),
        "is_deploy": req.get("is_deploy"),
        "verdict": "ALLOW" if allowed else "BLOCK",
        "reasons": reasons,
    }
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="agent-crypto-spend-guard: EVM JSON-RPC policy sidecar for AI agents"
    )
    ap.add_argument("--request", required=True, help="JSON file with the eth_sendTransaction / eth_sendRawTransaction request")
    ap.add_argument("--policy", default=None, help="JSON policy file (default: testnet-only, no deploys, no caps)")
    ap.add_argument("--agent", required=True, help="agent id the request is attributed to")
    ap.add_argument("--audit", default="audit.jsonl", help="request-replay audit log (JSONL, appended)")
    ap.add_argument("--ledger", default="ledger.json", help="running spend ledger (JSON, updated on ALLOW)")
    args = ap.parse_args(argv)

    try:
        raw = json.loads(Path(args.request).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"verdict": "ERROR", "reasons": [f"cannot read request file: {exc}"]}))
        return 2

    policy_raw = {}
    if args.policy:
        try:
            policy_raw = json.loads(Path(args.policy).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(json.dumps({"verdict": "ERROR", "reasons": [f"cannot read policy file: {exc}"]}))
            return 2
    policy = Policy.from_dict(policy_raw)

    ledger: dict = {}
    ledger_path = Path(args.ledger)
    if ledger_path.exists():
        try:
            ledger = {str(k): int(v) for k, v in json.loads(ledger_path.read_text(encoding="utf-8")).items()}
        except (json.JSONDecodeError, OSError, ValueError):
            ledger = {}

    try:
        req = normalize_request(raw)
    except ValueError as exc:
        print(json.dumps({"verdict": "ERROR", "reasons": [str(exc)]}))
        return 2

    allowed, reasons = evaluate(policy, args.agent, req, ledger)
    if allowed:
        apply_ledger(ledger, args.agent, req)
        try:
            ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
        except OSError:
            pass
    audit(Path(args.audit), args.agent, raw.get("method"), req, allowed, reasons)

    print(json.dumps({"verdict": "ALLOW" if allowed else "BLOCK", "reasons": reasons}, indent=2))
    return 0 if allowed else 1


if __name__ == "__main__":
    sys.exit(main())
