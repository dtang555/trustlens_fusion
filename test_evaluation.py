"""Evaluation-harness tests.  Run: python test_evaluation.py   (also works under pytest)

The decision tables are GOLDEN values: they pin what the current placeholder parameters do on the
corpus. If a code or parameter change alters one, the test fails so the change gets reviewed; update
the table deliberately, do not "fix" the test.
"""
import evaluate_fusion as E
from dataclasses import replace
from fusion import DEFAULT

CORPUS = E.load_corpus()
PAGES, REF = CORPUS["pages"], CORPUS["visual_reference"]

GOLDEN_SIM = {
    "paypal legit": "allow", "acme sso": "allow", "plain blog": "allow", "bank legit login": "allow",
    "legit short login (little text)": "allow", "phish classic": "warn", "phish ip host": "warn",
    "phish typosquat": "warn", "phish shortened + hidden form": "uncertain", "evasive: clean domain, no brand text": "uncertain",
    "unseen-brand phish A": "uncertain", "unseen-brand phish B": "uncertain", "unseen-brand legit A": "uncertain",
    "unseen-brand legit B": "uncertain",
}
GOLDEN_REAL_DIFFERENCES = {"legit short login (little text)": "uncertain"}   # coverage 0.4 < 0.5 with the visual module missing


def _run(mode, params=DEFAULT):
    reqs = [E.build(p, mode, REF) for p in PAGES]
    return E.run(PAGES, reqs, params)


def test_corpus_is_small_real_branch_b_output_and_both_classes_present():
    assert CORPUS["meta"]["n"] == len(PAGES) == 14 and 0 < CORPUS["meta"]["n_phishing"] < 14
    for p in PAGES:
        assert p["branch_b"]["evidence"] is not None and 0.0 <= p["branch_b"]["risk_score"] <= 1.0


def test_default_decisions_with_simulated_visual_are_pinned():
    assert {r["name"]: r["decision"] for r in _run("sim_visual")} == GOLDEN_SIM


def test_default_decisions_with_visual_missing_are_pinned():
    expected = {**GOLDEN_SIM, **GOLDEN_REAL_DIFFERENCES}
    assert {r["name"]: r["decision"] for r in _run("real_only")} == expected


def test_no_false_warns_and_every_phishing_page_is_flagged_by_default():
    for mode in E.MODES:
        m = E.metrics(_run(mode))
        assert m["FP"] == 0 and m["FN"] == 0 and m["flagged_recall"] == 1.0, (mode, m)


def test_unseen_brand_rule_does_not_need_the_visual_module():
    rows = {r["name"]: r for r in _run("real_only")}
    for name in ("unseen-brand phish A", "unseen-brand phish B", "evasive: clean domain, no brand text"):
        assert rows[name]["decision"] == "uncertain" and "unseen_brand" in rows[name]["reasons"], name


def test_genuine_brand_domain_is_never_unseen_even_if_logo_detection_fails():
    reqs = [E.build(p, "sim_visual", REF) for p in PAGES]
    for r in reqs:   # make the visual module fail to recognise any logo
        for b in r["branches"]:
            if b["branch"] == "visual":
                b["claims"] = {"brand": None, "brand_conf": 0.0}
    rows = {r["name"]: r for r in E.run(PAGES, reqs)}
    assert rows["paypal legit"]["decision"] == "allow" and rows["bank legit login"]["decision"] == "allow"


def test_registry_and_visual_reference_must_agree_or_genuine_pages_warn():
    unseen = {v["variant"]: v for v in E.unseen_brand(PAGES, REF)}
    only_visual = unseen["brand added to visual reference ONLY"]["rows"]
    both = unseen["brand added to visual reference AND shared registry"]["rows"]
    assert sum(1 for r in only_visual if r["label"] == 0 and r["decision"] == "warn") == 2
    assert sum(1 for r in both if r["label"] == 0 and r["decision"] == "warn") == 0
    assert all(r["decision"] == "warn" for r in both if r["label"] == 1)


def test_ablation_of_every_module_never_crashes_and_visual_only_is_uninformative():
    abl = {a["config"]: a for a in E.ablations(PAGES, [E.build(p, "sim_visual", REF) for p in PAGES])}
    assert abl["full system"]["flips_vs_full"] == 0
    assert abl["visual only (drop all Branch B)"]["auc"] == 0.5
    assert abl["no uncertain state (binary at 0.5)"]["uncertain_rate"] == 0.0


def test_metrics_on_hand_built_rows():
    rows = [{"label": 1, "decision": "warn", "risk": 0.9}, {"label": 1, "decision": "uncertain", "risk": 0.4},
            {"label": 0, "decision": "allow", "risk": 0.1}, {"label": 0, "decision": "warn", "risk": 0.85}]
    m = E.metrics(rows)
    assert (m["TP"], m["phish_uncertain"], m["TN"], m["FP"]) == (1, 1, 1, 1)
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["flagged_recall"] == 1.0 and m["fpr"] == 0.5
    assert E.cost(m, (10, 3, 1)) == 10 * 0 + 3 * 1 + 1 * 1


def test_report_never_claims_calibration_and_uses_the_preliminary_label():
    R = E.main()
    md = open(E.os.path.join(E.HERE, "EVALUATION.md"), encoding="utf-8").read()
    assert "preliminary risk score" in md and "p_fused" not in md
    for key in ("real_only", "sim_visual", "branch_b_alone"):
        c = R["calibration"][key]
        assert c["claim_supported"] is False and "not as calibration" in c["claim_note"]
    assert len(E.findings(R)) == 11 and all(f[0].isdigit() for f in E.findings(R))


def test_processing_cost_is_measured_and_small():
    R = E.main()
    assert 0 < R["cost"]["fuse_ms"]["median"] < 50 and R["cost"]["calls_timed"] >= 14 * 300


def test_text_module_importance_depends_on_whether_a_visual_module_supplies_brand_claims():
    """Regression for a misleading finding: 'text matters least' was true only with the simulated visual module."""
    R = E.main()
    text = {mode: next(m for m in R["missing_injection"][mode] if m["dropped"] == "text") for mode in E.MODES}
    assert text["sim_visual"]["changed"] == 0
    assert text["real_only"]["changed"] == 7 and text["real_only"]["lost_brand_mismatch"] == 3
    f8 = next(f for f in E.findings(R) if "Single-module loss" in f)
    assert "depends on the configuration" in f8 and "matters least" not in f8


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
