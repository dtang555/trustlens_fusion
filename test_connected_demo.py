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


def test_branch_b_is_one_source_with_equal_weights_and_the_rule_changes_a_decision():
    corpus = E.load_corpus()
    page = next(p for p in corpus["pages"] if p["name"] == "phish shortened + hidden form")
    req = E.build(page, "real_only", corpus["visual_reference"])
    mods = [b["p_phish"] for b in req["branches"] if b["branch"] != "visual"]
    mean, noisy, old = fuse(req), fuse(E.as_noisy_or(req)), fuse(D.as_independent(req), replace(DEFAULT, rho=0.0))
    assert mean["diagnostics"]["source_groups"]["branch_b"] == ["url", "dom", "text"]
    assert mean["diagnostics"]["source_scores"]["branch_b"] == {"combine": "mean", "score": round(sum(mods) / 3, 4)}
    assert (mean["decision"], noisy["decision"], old["decision"]) == ("uncertain", "warn", "uncertain")


def test_a_missing_input_is_left_out_of_the_average_not_counted_as_zero():
    with open(D.FIXTURES[0], encoding="utf-8") as f:
        fixture = D.json.load(f)
    mods = D.branch_b_adapter.convert(D.url_only(fixture["result"]), fixture["url"])
    by = {m["branch"]: m for m in mods}
    assert by["dom"]["status"] == "missing" and by["text"]["status"] == "missing" and by["url"]["status"] == "ok"
    req = {"schema_version": D.SCHEMA_VERSION, "request_id": "u", "branches": [D.mock_visual("missing", True)] + mods}
    left_out, zeros = fuse(req), fuse(D.counted_as_zero(req))
    assert left_out["diagnostics"]["source_scores"]["branch_b"]["score"] == round(by["url"]["p_phish"], 4)
    assert zeros["diagnostics"]["source_scores"]["branch_b"]["score"] < left_out["diagnostics"]["source_scores"]["branch_b"]["score"] / 2
    assert zeros["uncertainty"]["coverage"] > left_out["uncertainty"]["coverage"]      # counting them overstates the evidence


def test_every_demo_labels_its_score_as_a_preliminary_risk_score():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        D.main()
    assert "preliminary risk score" in buf.getvalue() and "uncalibrated" in buf.getvalue()
    for script in ("demo.py", "worked_case_branch_b.py"):
        res = subprocess.run([sys.executable, os.path.join(HERE, script)], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", cwd=HERE)
        assert res.returncode == 0, f"{script} crashed: {res.stderr.strip()[-300:]}"
        assert "preliminary risk score" in res.stdout, (
            f"{script} does not print 'preliminary risk score'. Its first header line is: "
            f"{next((l for l in res.stdout.splitlines() if l.startswith('===')), '(none)')!r}. "
            "If it still shows 'risk_score=', replace this file with the latest demo.py / run_bundle.py.")
        assert "p_fused" not in res.stdout and "risk_score=" not in res.stdout, f"{script} still prints the old field name"


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
