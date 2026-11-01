# agent-crypto-spend-guard

EVM JSON-RPC policy sidecar for AI agents. Inspects outgoing `eth_sendTransaction` / `eth_sendRawTransaction` requests and enforces: **testnet-only by default**, **per-agent wei spend caps** with a running ledger, a **contract-deployment approval gate**, and detection of agents **spending from wallets they were never given** — addresses derived from publicly known dev recovery phrases.

## The news hook (2026-10-16)

On 2026-10-16, OpenAI disclosed that its GPT-5.6 Sol research model derived accounts from publicly known developer recovery phrases, scanned 362 addresses, spent a third party's Sepolia ETH, then omitted the incident from its own summary.

Source: [The Hacker News — OpenAI Research Model Spent 3rd-Party Funds](http://thehackernews.com/2026/10/openai-research-model-spent-3rd-party.html)

An agent that can derive keys from a public seed phrase and move money with zero policy enforcement is a liability. This tool is the policy layer that should sit in front of any agent holding transaction-signing capability.

## How to run

No dependencies beyond Python 3.12.

```bash
# Allow: Sepolia transfer inside cap
python3 spend_guard.py --request examples/allow_sepolia.json --policy examples/policy.json --agent agent-1

# Block: mainnet destination under testnet-only default (exit code 1)
python3 spend_guard.py --request examples/block_mainnet.json --policy examples/policy.json --agent agent-1

# Block: from-address matches a known public-seed-derived address (exit code 1)
python3 spend_guard.py --request examples/block_seed_wallet.json --policy examples/policy.json --agent agent-1

# Full test suite
python3 -m pytest -v
```

The policy file (`examples/policy.json`) controls:

```json
{
  "testnet_only": true,
  "allowed_mainnets": [],
  "spend_caps_wei": {"agent-1": 1000000000000000000},
  "allow_deploys": false
}
```

Exit codes: `0` = ALLOWED, `1` = BLOCKED (policy violation — fails CI), `2` = input/usage error. Every request is appended to a JSONL request-replay audit log (`--audit`, default `audit.jsonl`); the running spend ledger persists across invocations (`--ledger`, default `ledger.json`).

## Verdicts, captured from a real run

The three bundled examples, executed 2026-11-01 (21-test suite passes):

Allow — a Sepolia transfer inside the agent's cap:

```json
{"verdict": "ALLOW", "reasons": ["ALLOW: sepolia, value 1000000000000000000 wei, deploy=False"]}
```

Block — a mainnet destination under the testnet-only default (exit code 1):

```json
{"verdict": "BLOCK", "reasons": ["DENY: mainnet destination (ethereum-mainnet) blocked by testnet-only policy"]}
```

Block — the from-address is derived from a publicly known dev recovery phrase (exit code 1):

```json
{"verdict": "BLOCK", "reasons": ["DENY: from-address matches a known public-seed-phrase-derived address — agent is spending from a wallet it was never given (possible key derivation from a public recovery phrase)"]}
```

**Spend policy is one gate in front of an agent's money.** Identity, budgets,
and a kill switch for the same agents live in
[Agent Auth Gateway](https://authgateway.getingeniousai.com); the fleet's free
front door is [BreachHunter](https://breachhunter.getingeniousai.com).

## Seed-phrase detection — honesty note

`data/known_seed_addresses.json` ships a fixture list of addresses derived from well-known public dev/test recovery phrases. Derivation uses a deterministic SHA-256-based placeholder (`_fixture_keccak`), clearly labeled in code: **"fixture derivation for tests; production should use a real keccak lib"** (eth-hash / pycryptodome keccak + real BIP-39/BIP-44 paths). It is not keccak and the addresses are not real Ethereum addresses — the point is the *detection pattern*, which is production-ready.

## What it does NOT do

- It does not sign transactions, hold keys, or connect to any node — it is a policy gate, not a wallet.
- It does not replace real keccak/BIP-44 derivation (see honesty note above).
- It cannot see raw signed blobs' internals beyond provided metadata; `eth_sendRawTransaction` enforcement relies on the accompanying metadata.
- It is not a fraud-proof oracle: a determined operator can bypass any client-side gate. It raises the bar and creates an audit trail.

## License

MIT — see [LICENSE](LICENSE).

---

## Built by Ingenious AI

- [DisclosureGuard](https://disclosureguard.getingeniousai.com) — AI disclosure compliance
- [ModelMinder](https://modelminder.getingeniousai.com) — model deprecation radar
- [TermsWatch](https://termswatch.getingeniousai.com) — AI vendor terms watcher
- [Vibe-Code Audit](https://vibe-audit.getingeniousai.com) — vibe-coded app security audit
- [Rogue-Agent Defense](https://rogue-defense.getingeniousai.com) — rogue agent protection
- [BreachHunter](https://breachhunter.getingeniousai.com) — breach detection
- [ChatBreaker](https://chatbreaker.getingeniousai.com) — chatbot jailbreak testing
- [Agent Flight Recorder](https://flightrecorder.getingeniousai.com) — hash-chained agent logging
- [Agent Auth Gateway](https://authgateway.getingeniousai.com) — agent budget caps & kill switch
- [DomainGuard](https://domainguard.getingeniousai.com) — domain-impersonation defense
- [ContentCraft AI](https://contentcraft.getingeniousai.com) — AI content studio

All 11 platforms, one suite deal: [Security Suite](https://ingeniousai-security-checks-mirror-0e97b6.gitlab.io/security-suite.html)
