"""Tests for agent-crypto-spend-guard. Fixtures only — no network, no mocks of
the tool itself (the fixture keccak placeholder IS the tool's declared test
hook; the shipped data/known_seed_addresses.json is a fixture list)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import spend_guard as sg

ROOT = Path(__file__).resolve().parent.parent


def make_req(method="eth_sendTransaction", chain_id=11155111, frm="0xaaaa", value=100, to="0xbbbb"):
    return {
        "method": method,
        "params": [{"from": frm, "to": to, "value": hex(value), "chainId": chain_id}],
    }


def norm(raw):
    return sg.normalize_request(raw)


# --- testnet-only enforcement ---------------------------------------------
def test_mainnet_blocked_by_default():
    pol = sg.Policy()
    req = norm(make_req(chain_id=1))
    allowed, reasons = sg.evaluate(pol, "agent-1", req, {})
    assert not allowed
    assert any("testnet-only" in r for r in reasons)


def test_sepolia_allowed_by_default():
    pol = sg.Policy()
    req = norm(make_req(chain_id=11155111))
    allowed, reasons = sg.evaluate(pol, "agent-1", req, {})
    assert allowed
    assert any("ALLOW" in r for r in reasons)


def test_mainnet_allowed_when_explicitly_permitted():
    pol = sg.Policy(allowed_mainnets=[1])
    req = norm(make_req(chain_id=1))
    allowed, _ = sg.evaluate(pol, "agent-1", req, {})
    assert allowed


def test_unknown_chain_id_denied():
    pol = sg.Policy()
    req = norm(make_req(chain_id=999999))
    allowed, reasons = sg.evaluate(pol, "agent-1", req, {})
    assert not allowed
    assert any("unknown chainId" in r for r in reasons)


def test_missing_chain_id_denied():
    pol = sg.Policy()
    raw = {"method": "eth_sendTransaction", "params": [{"from": "0xa", "to": "0xb", "value": "0x1"}]}
    req = norm(raw)
    allowed, reasons = sg.evaluate(pol, "agent-1", req, {})
    assert not allowed
    assert any("missing chainId" in r for r in reasons)


# --- spend caps ------------------------------------------------------------
def test_spend_cap_blocks_over_cap():
    pol = sg.Policy(spend_caps_wei={"agent-1": 500})
    ledger = {"agent-1": 400}
    req = norm(make_req(value=200))
    allowed, reasons = sg.evaluate(pol, "agent-1", req, ledger)
    assert not allowed
    assert any("spend cap exceeded" in r for r in reasons)


def test_spend_cap_allows_at_exact_boundary():
    pol = sg.Policy(spend_caps_wei={"agent-1": 500})
    ledger = {"agent-1": 400}
    req = norm(make_req(value=100))
    allowed, _ = sg.evaluate(pol, "agent-1", req, ledger)
    assert allowed


def test_ledger_accumulates_only_allowed():
    ledger: dict = {}
    pol = sg.Policy(spend_caps_wei={"agent-1": 1000})
    for value in (300, 300):
        req = norm(make_req(value=value))
        allowed, _ = sg.evaluate(pol, "agent-1", req, ledger)
        assert allowed
        sg.apply_ledger(ledger, "agent-1", req)
    assert ledger["agent-1"] == 600
    req = norm(make_req(value=500))
    allowed, _ = sg.evaluate(pol, "agent-1", req, ledger)
    assert not allowed  # 600 + 500 > 1000
    assert ledger["agent-1"] == 600  # blocked tx does not touch the ledger


# --- deployment gate -------------------------------------------------------
def test_deploy_blocked_by_default():
    pol = sg.Policy()
    raw = make_req(to=None)  # no `to` => contract deployment
    req = norm(raw)
    assert req["is_deploy"]
    allowed, reasons = sg.evaluate(pol, "agent-1", req, {})
    assert not allowed
    assert any("deployment requires explicit approval" in r for r in reasons)


def test_deploy_allowed_with_approval():
    pol = sg.Policy(allow_deploys=True)
    req = norm(make_req(to=None))
    allowed, _ = sg.evaluate(pol, "agent-1", req, {})
    assert allowed


# --- seed-derived wallet detection -----------------------------------------
def test_seed_derived_from_address_flagged():
    addrs = sg.derive_fixture_addresses()
    assert addrs, "fixture derivation produced no addresses"
    victim = sorted(addrs)[0]
    pol = sg.Policy()  # default policy ships the fixture address set
    assert victim.lower() in pol.seed_derived_addresses
    req = norm(make_req(frm=victim))
    allowed, reasons = sg.evaluate(pol, "agent-1", req, {})
    assert not allowed
    assert any("never given" in r for r in reasons)


def test_normal_from_address_not_flagged():
    pol = sg.Policy()
    req = norm(make_req(frm="0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))
    assert req["from"] not in pol.seed_derived_addresses
    allowed, _ = sg.evaluate(pol, "agent-1", req, {})
    assert allowed


def test_fixture_derivation_deterministic():
    assert sg.derive_fixture_addresses() == sg.derive_fixture_addresses()


def test_shipped_fixture_list_matches_derivation():
    fixture_path = ROOT / "data" / "known_seed_addresses.json"
    assert fixture_path.exists(), "data/known_seed_addresses.json must be shipped"
    shipped = {a.lower() for a in json.loads(fixture_path.read_text())}
    assert shipped.issubset({a.lower() for a in sg.derive_fixture_addresses()})


# --- raw transaction path ---------------------------------------------------
def test_send_raw_transaction_path():
    pol = sg.Policy()
    raw = {
        "method": "eth_sendRawTransaction",
        "params": [{"from": "0xaaa", "to": "0xbbb", "value": "0x64", "chainId": 11155111}],
    }
    req = norm(raw)
    allowed, _ = sg.evaluate(pol, "agent-1", req, {})
    assert allowed


def test_unsupported_method_is_input_error():
    with pytest.raises(ValueError, match="unsupported method"):
        norm({"method": "eth_call", "params": []})


# --- audit log ---------------------------------------------------------------
def test_audit_log_written(tmp_path):
    log = tmp_path / "audit.jsonl"
    req = norm(make_req(chain_id=1))
    sg.audit(log, "agent-1", "eth_sendTransaction", req, False, ["DENY: test"])
    lines = log.read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["verdict"] == "BLOCK"
    assert entry["agent_id"] == "agent-1"
    assert entry["chain_id"] == 1


# --- CLI end-to-end -----------------------------------------------------------
def run_cli(tmp_path, request_obj, policy_obj=None, extra=()):
    req_f = tmp_path / "req.json"
    req_f.write_text(json.dumps(request_obj))
    cmd = [sys.executable, str(ROOT / "spend_guard.py"), "--request", str(req_f),
           "--agent", "agent-1", "--audit", str(tmp_path / "audit.jsonl"),
           "--ledger", str(tmp_path / "ledger.json"), *extra]
    if policy_obj is not None:
        pol_f = tmp_path / "policy.json"
        pol_f.write_text(json.dumps(policy_obj))
        cmd += ["--policy", str(pol_f)]
    return subprocess.run(cmd, capture_output=True, text=True)


def test_cli_allow_exit_zero(tmp_path):
    res = run_cli(tmp_path, make_req(chain_id=11155111))
    assert res.returncode == 0, res.stderr
    assert json.loads(res.stdout)["verdict"] == "ALLOW"
    assert (tmp_path / "ledger.json").exists()


def test_cli_block_exit_one(tmp_path):
    res = run_cli(tmp_path, make_req(chain_id=1))
    assert res.returncode == 1, res.stderr
    assert json.loads(res.stdout)["verdict"] == "BLOCK"


def test_cli_bad_input_exit_two(tmp_path):
    res = run_cli(tmp_path, {"method": "eth_call", "params": []})
    assert res.returncode == 2
    assert json.loads(res.stdout)["verdict"] == "ERROR"


def test_cli_ledger_persists_across_invocations(tmp_path):
    policy = {"spend_caps_wei": {"agent-1": 250}}
    r1 = run_cli(tmp_path, make_req(chain_id=11155111, value=200), policy)
    assert r1.returncode == 0
    r2 = run_cli(tmp_path, make_req(chain_id=11155111, value=100), policy)
    assert r2.returncode == 1  # 200 + 100 > 250 cap, running ledger persisted
