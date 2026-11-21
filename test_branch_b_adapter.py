"""Tests for the Branch B adapter and worked case.  Run: python test_branch_b_adapter.py"""
import json
from math import prod

import branch_b_adapter
from fusion import SCHEMA_VERSION, fuse, parse_branch
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
    assert out["uncertainty"]["coverage"] == 0.4  # Branch B counts as ONE source: 0.8 / 2 sources


def test_legitimate_fixture_allowed():
    out = fuse(build_request(LEGIT))
    assert out["decision"] == "allow" and out["risk_score"] < 0.2


def test_domain_owner_comes_from_registry_not_from_branch_b():
    fx = _fx(PHISH)
    fx["url"] = "https://www.paypal.com/signin"  # same evidence, genuine domain
    req = {"schema_version": "0.1.0", "request_id": "x",
           "branches": [build_request(PHISH)["branches"][0]] + branch_b_adapter.convert(fx["result"], fx["url"])}
    out = fuse(req)
    assert all(x["type"] != "brand_domain_mismatch" for x in out["explanations"])


def test_default_combination_is_the_equal_weight_mean_and_noisy_or_stays_selectable():
    fx = _fx(PHISH)
    assert {b["combine"] for b in branch_b_adapter.convert(fx["result"], fx["url"])} == {"mean"}
    assert {b["combine"] for b in branch_b_adapter.convert(fx["result"], fx["url"], combine="noisy_or")} == {"noisy_or"}


def test_modules_whose_input_branch_b_reports_missing_are_not_counted():
    """URL-only analysis: Branch B lists html and visible_text as missing, so DOM and text are 'missing', not 0.0."""
    fx = _fx(PHISH)
    url_only = {"confidence": 0.4, "missing": ["html", "visible_text", "ocr_text"],
                "evidence": [e for e in fx["result"]["evidence"] if e["id"].startswith("url.")]}
    mods = {b["branch"]: b for b in branch_b_adapter.convert(url_only, fx["url"])}
    assert mods["url"]["status"] == "ok" and mods["url"]["p_phish"] > 0.5
    for name, flag in (("dom", "html"), ("text", "visible_text")):
        assert mods[name]["status"] == "missing" and mods[name]["p_phish"] is None and mods[name]["missing_flags"] == [flag]
    req = {"schema_version": SCHEMA_VERSION, "request_id": "u", "branches": list(mods.values())}
    out = fuse(req)
    assert out["diagnostics"]["source_scores"]["branch_b"]["score"] == round(mods["url"]["p_phish"], 4)   # not diluted


def test_degraded_inputs_lower_reliability_but_do_not_remove_a_module():
    """limited_visible_text and ocr_text are degraded inputs, not missing modules."""
    mods = {b["branch"]: b for b in build_request(PHISH)["branches"] if b["branch"] != "visual"}
    assert mods["text"]["status"] == "partial" and mods["text"]["reliability"] == 0.8


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
