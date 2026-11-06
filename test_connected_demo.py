"""Tests for the connected demonstration.  Run: python test_connected_demo.py   (also works under pytest)"""
import contextlib
import io
import os
import subprocess
import sys
from dataclasses import replace

import connected_demo as D
import evaluate_fusion as E
from fusion import DEFAULT, fuse
from worked_case_branch_b import build_request

HERE = os.path.dirname(os.path.abspath(__file__))
SUSPICIOUS, LEGIT = D.PAGES[0], D.PAGES[1]


def _run(page, state):
    _, path, is_phish = page
    return fuse(D.with_visual(build_request(path), state, is_phish))


def test_visual_missing_is_handled_and_visible_in_the_summary():
    for page, decision, coverage in ((SUSPICIOUS, "warn", 0.4), (LEGIT, "allow", 0.5)):
        out = _run(page, "missing")
        v = next(b for b in out["branch_summary"] if b["branch"] == "visual")
        assert v["status"] == "missing" and not v["used"]
        assert out["decision"] == decision and out["uncertainty"]["coverage"] == coverage


def test_agreeing_visual_verdict_does_not_change_either_decision():
    assert _run(SUSPICIOUS, "agrees")["decision"] == "warn" and _run(LEGIT, "agrees")["decision"] == "allow"


def test_contradicting_visual_on_a_legitimate_page_gives_uncertain_with_a_disagreement_reason():
    out = _run(LEGIT, "contradicts")
    assert out["decision"] == "uncertain" and out["uncertainty"]["reasons"] == ["branch_disagreement"]
    assert out["uncertainty"]["disagreement"] > DEFAULT.max_disagreement


def test_contradicting_visual_on_the_suspicious_page_still_warns_but_reports_the_conflict():
    out = _run(SUSPICIOUS, "contradicts")
    assert out["decision"] == "warn" and out["diagnostics"]["rule_floor"]
    assert out["uncertainty"]["disagreement"] > DEFAULT.max_disagreement


def test_branch_b_is_one_source_and_the_old_independent_design_changes_a_decision():
    corpus = E.load_corpus()
    page = next(p for p in corpus["pages"] if p["name"] == "phish shortened + hidden form")
    req = E.build(page, "real_only", corpus["visual_reference"])
    one = fuse(req)
    old = fuse(D.as_independent(req), replace(DEFAULT, rho=0.0))
    assert one["diagnostics"]["source_groups"]["branch_b"] == ["url", "dom", "text"]
    assert one["diagnostics"]["source_scores"]["branch_b"]["combine"] == "noisy_or"
    assert one["decision"] == "warn" and old["decision"] == "uncertain"


def test_every_demo_labels_its_score_as_a_preliminary_risk_score():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        D.main()
    assert "preliminary risk score" in buf.getvalue() and "uncalibrated" in buf.getvalue()
    for script in ("demo.py", "worked_case_branch_b.py"):
        out = subprocess.run([sys.executable, os.path.join(HERE, script)], capture_output=True, text=True, cwd=HERE).stdout
        assert "preliminary risk score" in out and "p_fused" not in out and "risk_score=" not in out, script


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
