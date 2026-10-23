"""Tests for the Branch B adapter and worked case.  Run: python test_branch_b_adapter.py"""
import json
from math import prod

import branch_b_adapter
from fusion import fuse, parse_branch
from worked_case_branch_b import FIXTURES, build_request

PHISH, LEGIT = FIXTURES


def _fx(path):
    return json.load(open(path))


def test_noisy_or_reproduces_reported_branch_b_scores():
    for path, tol in ((PHISH, 0.005), (LEGIT, 0.001)):
        fx = _fx(path)
        p = 1 - prod(1 - e["weight"] for e in fx["result"]["evidence"])
        assert abs(p - fx["result"]["risk_score"]) <= tol, (path, p)


def test_adapter_output_parses_with_no_dropped_evidence():
    for path in FIXTURES:
        for b in build_request(path)["branches"]:
            parsed = parse_branch(b)
            if b["branch"] != "visual":
                assert parsed.usable and parsed.dropped_evidence == 0, (path, b["branch"])


def test_only_rule_ids_matching_shared_types_become_evidence():
    mapped = sum(len(b["evidence"]) for b in branch_b_adapter.convert(_fx(PHISH)["result"], _fx(PHISH)["url"]))
    unmapped = sum(len(b["features"]) for b in branch_b_adapter.convert(_fx(PHISH)["result"], _fx(PHISH)["url"]))
    assert (mapped, unmapped) == (5, 8)  # real Branch B fires 13 rules; 5 are explainable today


def test_phishing_fixture_warns_with_grounded_explanations():
    out = fuse(build_request(PHISH))
    assert out["decision"] == "warn" and out["diagnostics"]["rule_floor"]
    assert out["explanations"][0]["type"] == "brand_domain_mismatch"
    summary = {b["branch"]: b for b in out["branch_summary"]}
    assert summary["visual"]["status"] == "missing" and not summary["visual"]["used"]
    assert out["uncertainty"]["coverage"] == 0.6


def test_legitimate_fixture_allowed():
    out = fuse(build_request(LEGIT))
    assert out["decision"] == "allow" and out["p_fused"] < 0.01


def test_domain_owner_comes_from_registry_not_from_branch_b():
    fx = _fx(PHISH)
    fx["url"] = "https://www.paypal.com/signin"  # same evidence, genuine domain
    req = {"schema_version": "0.1.0", "request_id": "x",
           "branches": [build_request(PHISH)["branches"][0]] + branch_b_adapter.convert(fx["result"], fx["url"])}
    out = fuse(req)
    assert all(x["type"] != "brand_domain_mismatch" for x in out["explanations"])


if __name__ == "__main__":
    tests = [(n, f) for n, f in globals().items() if n.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn(); print(f"PASS  {name}")
        except AssertionError as exc:
            failed += 1; print(f"FAIL  {name}  {exc!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(failed)
