"""Tests for the Branch B input path: Student B's shared_adapter + branch_b_input.  Run: python test_branch_b_input.py"""
import copy
import json

import branch_b_input
import evaluate_fusion as E
from fusion import SCHEMA_VERSION, fuse, parse_branch
from shared_adapter import to_shared
from worked_case_branch_b import FIXTURES, VISUAL_MISSING, build_request

PHISH, LEGIT = FIXTURES
CORPUS = E.load_corpus()["pages"]


def _fx(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _req(mods):
    return {"schema_version": SCHEMA_VERSION, "request_id": "t", "branches": [VISUAL_MISSING] + mods}


def test_fusion_branch_b_score_equals_student_b_risk_score_on_every_page():
    for p in CORPUS:
        src = fuse(_req(branch_b_input.convert(p["branch_b"])))["diagnostics"]["source_scores"]["branch_b"]
        expected = min(max(p["branch_b"]["risk_score"], 0.02), 0.99)   # fusion's own source limits
        assert src["combine"] == "noisy_or" and abs(src["score"] - expected) < 0.0015, (p["name"], src)


def test_shared_adapter_output_is_used_unchanged_apart_from_three_documented_fields():
    for p in CORPUS:
        raw, ours = to_shared(p["branch_b"]), branch_b_input.convert(p["branch_b"])
        for a, b in zip(raw, ours):
            a, b = copy.deepcopy(a), copy.deepcopy(b)
            assert b.pop("combine") == "noisy_or"
            for m in (a, b):
                m.pop("reliability")
                m.pop("p_phish")
            assert a == b, (p["name"], a["branch"])


def test_url_reliability_is_branch_b_confidence_so_a_legitimate_page_can_be_allowed():
    mods = {m["branch"]: m for m in branch_b_input.convert(_fx(LEGIT)["result"])}
    assert mods["url"]["reliability"] == _fx(LEGIT)["result"]["confidence"] == 1.0
    out = fuse(build_request(LEGIT))
    assert out["uncertainty"]["coverage"] == 0.5 and out["decision"] == "allow" and out["risk_score"] < 0.2


def test_a_module_where_no_rule_fired_adds_nothing():
    blog = next(p for p in CORPUS if p["name"] == "plain blog")
    assert [m["p_phish"] for m in to_shared(blog["branch_b"])] == [0.05, 0.05, 0.05]   # the adapter's floor
    assert [m["p_phish"] for m in branch_b_input.convert(blog["branch_b"])] == [0.0, 0.0, 0.0]
    src = fuse(_req(branch_b_input.convert(blog["branch_b"])))["diagnostics"]["source_scores"]["branch_b"]
    assert src["score"] == 0.02   # fusion's source floor: weak evidence of safety, not certainty


def test_output_parses_with_no_dropped_evidence():
    for path in FIXTURES:
        for b in build_request(path)["branches"][1:]:
            parsed = parse_branch(b)
            assert parsed.usable and parsed.dropped_evidence == 0, (path, b["branch"])


def test_phishing_fixture_warns_with_grounded_explanations():
    out = fuse(build_request(PHISH))
    assert out["decision"] == "warn" and out["diagnostics"]["rule_floor"]
    assert out["explanations"][0]["type"] == "brand_domain_mismatch"
    assert out["uncertainty"]["coverage"] == 0.4   # Branch B counts as ONE source: 0.8 / 2 sources


def test_missing_html_makes_dom_and_text_missing_not_zero():
    r = _fx(PHISH)["result"]
    url_only = {**r, "confidence": 0.4, "missing": ["html", "visible_text", "ocr_text"],
                "evidence": [e for e in r["evidence"] if e["id"].startswith("url.")]}
    mods = {m["branch"]: m for m in branch_b_input.convert(url_only)}
    assert mods["url"]["status"] == "ok" and mods["dom"]["status"] == mods["text"]["status"] == "missing"
    assert mods["dom"]["p_phish"] is None and mods["text"]["p_phish"] is None


def test_registry_override_only_changes_domain_ownership():
    legit = next(p for p in CORPUS if p["name"] == "unseen-brand legit A")
    assert branch_b_input.convert(legit["branch_b"])[0]["claims"]["domain_owner_brand"] is None
    owned = branch_b_input.convert(legit["branch_b"], registry={"wealthsimple": {"wealthsimple.com"}})
    assert owned[0]["claims"]["domain_owner_brand"] == "wealthsimple"


def test_combination_rule_stays_selectable():
    assert {m["combine"] for m in branch_b_input.convert(_fx(PHISH)["result"], combine="mean")} == {"mean"}


if __name__ == "__main__":
    tests = [(n, f) for n, f in globals().items() if n.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {name}  {exc!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(failed)
