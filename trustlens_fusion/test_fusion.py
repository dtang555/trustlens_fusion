"""Regression tests. Run with:  python test_fusion.py   (also works under pytest)"""
import copy

from demo import SCENARIOS, branch, ev, req
from dataclasses import replace

from fusion import DEFAULT, MAX_DISAGREEMENT, SCHEMA_VERSION, SchemaError, fuse, logit

S = dict(SCENARIOS)


def raises_schema_error(request):
    try:
        fuse(request)
    except SchemaError:
        return True
    return False


def test_phishing_warns_with_evidence():
    out = fuse(S["phishing_paypal"])
    assert out["decision"] == "warn" and out["explanations"]
    assert out["explanations"][0]["type"] == "brand_domain_mismatch"


def test_legit_sso_allowed():
    assert fuse(S["legit_sso_microsoft"])["decision"] == "allow"


def test_thin_input_is_uncertain_not_allow():
    out = fuse(S["thin_input"])
    assert out["decision"] == "uncertain" and "low_coverage" in out["uncertainty"]["reasons"]


def test_unseen_brand_is_uncertain():
    out = fuse(S["unseen_brand_login"])
    assert out["decision"] == "uncertain" and "unseen_brand" in out["uncertainty"]["reasons"]


def test_contradictory_demo_scenario_is_uncertain_with_disagreement():
    out = fuse(S["contradictory_rbc"])
    assert out["decision"] == "uncertain" and out["uncertainty"]["reasons"] == ["branch_disagreement"]
    assert out["uncertainty"]["disagreement"] > MAX_DISAGREEMENT


def test_no_usable_branches_is_uncertain():
    _, r = req("none", [branch("visual", status="missing"), branch("url", status="error")])
    out = fuse(r)
    assert out["decision"] == "uncertain" and out["uncertainty"]["reasons"] == ["no_usable_branches"]
    assert fuse({"schema_version": SCHEMA_VERSION, "branches": []})["decision"] == "uncertain"


def test_missing_branch_is_masked_not_neutral():
    full = copy.deepcopy(S["phishing_paypal"])
    full["branches"] = [b for b in full["branches"] if b["branch"] != "text"]
    assert fuse(full)["decision"] == "warn"  # dropping a branch must not flip a clear attack


def test_bad_branch_becomes_error_and_others_continue():
    r = copy.deepcopy(S["phishing_paypal"])
    r["branches"][3]["p_phish"] = 1.5
    out = fuse(r)
    summary = {b["branch"]: b for b in out["branch_summary"]}
    assert summary["text"]["status"] == "error" and not summary["text"]["used"]
    assert out["decision"] == "warn"


def test_nan_rejected():
    r = copy.deepcopy(S["phishing_paypal"])
    r["branches"][0]["p_phish"] = float("nan")
    out = fuse(r)
    assert {b["branch"]: b for b in out["branch_summary"]}["visual"]["status"] == "error"


def test_unknown_and_unverified_evidence_never_explained():
    r = copy.deepcopy(S["phishing_paypal"])
    r["branches"][2]["evidence"].append(ev("model_says_scam", 0.99))
    r["branches"][2]["evidence"].append(ev("hidden_input", 0.9, {"count": 4}, verified=False))
    texts = " ".join(x["text"] for x in fuse(r)["explanations"])
    assert "scam" not in texts and "hidden form fields" not in texts


def test_explanation_strings_are_escaped():
    r = copy.deepcopy(S["phishing_paypal"])
    r["branches"][1]["claims"]["domain"] = "<script>alert(1)</script>.xyz"
    out = fuse(r)
    text = " ".join(x["text"] for x in out["explanations"])
    assert "<script>" not in text and "&lt;script&gt;" in text


def test_request_level_faults_raise():
    assert raises_schema_error({"schema_version": "9.0.0", "branches": []})
    dup = copy.deepcopy(S["phishing_paypal"])
    dup["branches"].append(copy.deepcopy(dup["branches"][0]))
    assert raises_schema_error(dup)
    assert raises_schema_error({"schema_version": SCHEMA_VERSION, "branches": [{"branch": "bogus"}]})


def test_conflicting_branches_not_allowed_silently():
    _, r = req("conflict", [
        branch("visual", 0.02, 0.9, claims={"brand": "rbc", "brand_conf": 0.9}),
        branch("url", 0.97, 0.9, claims={"domain": "rbc-secure.top", "domain_owner_brand": "rbc"}),
        branch("dom", 0.5, 0.9),
        branch("text", 0.5, 0.9),
    ])
    out = fuse(r)
    assert out["uncertainty"]["disagreement"] > MAX_DISAGREEMENT
    assert out["decision"] != "warn" or out["risk_score"] >= 0.8  # warn only via the score, never silently allow


def test_agreeing_branches_with_different_confidence_are_not_disagreement():
    # Regression: found during URL-branch integration. -5.5 vs -1.1 both mean "safe".
    _, r = req("agree", [
        branch("visual", 0.15, 0.85, claims={"brand": "microsoft", "brand_conf": 0.95}),
        branch("url", 0.004, 0.9, claims={"domain": "microsoftonline.com", "domain_owner_brand": "microsoft"}),
        branch("dom", 0.25, 0.9, claims={"brand": "microsoft", "brand_conf": 0.8}),
        branch("text", 0.2, 0.6),
    ])
    out = fuse(r)
    assert out["uncertainty"]["disagreement"] == 0.0 and out["decision"] == "allow"


def test_logit_is_finite_at_extremes():
    assert abs(logit(0.0)) < 20 and abs(logit(1.0)) < 20


# ------------------------------------------------- fusion v0.2: source groups ----
def _same_source(rho_params=None, src="branch_b", visual=True):
    """Three modules from one source (like Branch B), visual optionally missing."""
    bs = [branch("url", 0.8, 0.8), branch("dom", 0.8, 0.8), branch("text", 0.8, 0.8)]
    for b in bs:
        b["source"] = src
    bs.insert(0, branch("visual", status="missing") if not visual else branch("visual", 0.5, 0.7))
    return {"schema_version": SCHEMA_VERSION, "request_id": "s", "branches": bs}


def test_same_source_modules_are_discounted_not_summed():
    t0 = fuse(_same_source(), replace(DEFAULT, rho=0.0))["diagnostics"]["branch_terms"]
    t5 = fuse(_same_source())["diagnostics"]["branch_terms"]
    t1 = fuse(_same_source(), replace(DEFAULT, rho=1.0))["diagnostics"]["branch_terms"]
    for n in ("url", "dom", "text"):
        assert abs(t5[n] - t0[n] / 2) < 1e-2          # rho=0.5, n=3 -> factor 1/2
        assert abs(t1[n] - t0[n] / 3) < 1e-2          # rho=1   -> the source counts once (mean)
    assert abs(sum(t1.values()) - sum(t0.values()) / 3) < 2e-2


def test_rho_zero_reproduces_independent_modules():
    with_source = fuse(_same_source(), replace(DEFAULT, rho=0.0))
    without = _same_source()
    for b in without["branches"]:
        b.pop("source", None)
    assert with_source["risk_score"] == fuse(without)["risk_score"]


def test_coverage_counts_a_source_once():
    shared = fuse(_same_source(visual=False))["uncertainty"]["coverage"]
    r = _same_source(visual=False)
    for b in r["branches"]:
        b.pop("source", None)
    independent = fuse(r)["uncertainty"]["coverage"]
    assert shared == 0.4 and independent == 0.6      # 0.8/2 sources vs 3*0.8/4 modules


def test_disagreement_is_between_sources_not_inside_one():
    r = {"schema_version": SCHEMA_VERSION, "request_id": "d", "branches": [
        branch("visual", status="missing"), branch("url", 0.95, 0.9), branch("dom", 0.05, 0.9),
        branch("text", status="missing")]}
    assert fuse(r)["uncertainty"]["disagreement"] > MAX_DISAGREEMENT          # independent: opposite verdicts
    for b in r["branches"]:
        b["source"] = "branch_b"
    assert fuse(r)["uncertainty"]["disagreement"] == 0.0                      # one source: its own mix, not a conflict


def test_warn_and_allow_use_separate_coverage_floors():
    r = {"schema_version": SCHEMA_VERSION, "request_id": "c", "branches": [
        branch("url", 0.99, 0.5), branch("dom", 0.99, 0.5), branch("visual", status="missing"), branch("text", status="missing")]}
    out = fuse(r)                                   # coverage 0.25 < 0.30 and no rule floor -> uncertain
    assert out["decision"] == "uncertain" and out["uncertainty"]["reasons"] == ["low_coverage"]
    assert fuse(r, replace(DEFAULT, min_coverage_warn=0.2))["decision"] == "warn"


def test_conflict_blocks_warn_is_optional_and_floor_still_wins():
    r = {"schema_version": SCHEMA_VERSION, "request_id": "k", "branches": [
        branch("visual", 0.02, 0.9), branch("url", 0.999, 0.9, claims={"domain": "x.top", "domain_owner_brand": None}),
        branch("dom", 0.999, 0.9), branch("text", 0.999, 0.9)]}
    assert fuse(r)["decision"] == "warn"            # default: a high score still warns
    out = fuse(r, replace(DEFAULT, conflict_blocks_warn=True))
    assert out["decision"] == "uncertain" and out["uncertainty"]["reasons"] == ["branch_disagreement"]


def test_output_is_labelled_a_preliminary_uncalibrated_risk_score():
    for out in (fuse(S["phishing_paypal"]), fuse(S["thin_input"])):
        assert out["score_label"] == "preliminary risk score" and out["calibration_status"] == "uncalibrated"
        assert "p_fused" not in out and "risk_score" in out


def test_params_are_immutable_and_defaults_untouched():
    try:
        DEFAULT.rho = 0.9
    except Exception:
        pass
    else:
        raise AssertionError("Params must be frozen")
    fuse(S["phishing_paypal"], replace(DEFAULT, rho=1.0, t_high=0.5))
    assert DEFAULT.rho == 0.5 and DEFAULT.t_high == 0.8


def test_known_brand_domain_is_not_unseen_even_if_logo_detection_failed():
    r = {"schema_version": SCHEMA_VERSION, "request_id": "o", "branches": [
        branch("visual", 0.5, 0.7, claims={"brand": None, "brand_conf": 0.1}),
        branch("url", 0.05, 0.9, claims={"domain": "paypal.com", "domain_owner_brand": "paypal"}),
        branch("dom", 0.1, 0.9, evidence=[ev("credential_solicitation", 0.9)]), branch("text", 0.1, 0.9)]}
    assert fuse(r)["decision"] == "allow"
    assert fuse(r, replace(DEFAULT, unseen_brand_rule="form"))["decision"] == "uncertain"   # the earlier rule


def test_credential_form_on_unowned_domain_is_unseen_even_without_the_visual_module():
    r = {"schema_version": SCHEMA_VERSION, "request_id": "u", "branches": [
        branch("visual", status="missing"), branch("url", 0.05, 1.0, claims={"domain": "shop.example", "domain_owner_brand": None}),
        branch("dom", 0.1, 1.0, evidence=[ev("credential_solicitation", 0.9)]), branch("text", 0.1, 1.0)]}
    out = fuse(r)
    assert out["decision"] == "uncertain" and "unseen_brand" in out["uncertainty"]["reasons"]


def test_credential_wording_in_text_alone_does_not_trigger_unseen_brand():
    r = {"schema_version": SCHEMA_VERSION, "request_id": "t", "branches": [
        branch("visual", 0.5, 0.7, claims={"brand": None, "brand_conf": 0.1}),
        branch("url", 0.05, 1.0, claims={"domain": "intranet.example", "domain_owner_brand": None}),
        branch("dom", 0.05, 1.0), branch("text", 0.1, 1.0, evidence=[ev("credential_solicitation", 0.1)])]}
    assert fuse(r)["decision"] == "allow"
    assert fuse(r, replace(DEFAULT, unseen_brand_rule="v0.1"))["decision"] == "uncertain"


# --------------------------------------- fusion v0.2: noisy-OR sources (Branch B) ----
def _noisy(ps, r=0.8, visual=None):
    """URL / DOM / text modules sharing one noisy-OR score, like Branch B."""
    bs = [dict(branch(n, p, r), source="branch_b", combine="noisy_or") for n, p in zip(("url", "dom", "text"), ps)]
    bs.insert(0, branch("visual", status="missing") if visual is None else visual)
    return {"schema_version": SCHEMA_VERSION, "request_id": "n", "branches": bs}


def test_noisy_or_source_reproduces_the_upstream_combined_score():
    out = fuse(_noisy([0.5, 0.5, 0.5]))
    assert out["diagnostics"]["source_scores"]["branch_b"] == {"combine": "noisy_or", "score": 0.875}  # 1 - 0.5^3
    # the three module terms together equal ONE term for the combined score (reliability 0.8, source weight 1.0)
    assert abs(sum(out["diagnostics"]["branch_terms"].values()) - 0.8 * logit(0.875)) < 1e-2


def test_a_module_with_no_findings_adds_nothing_instead_of_voting_safe():
    """The failure found during evaluation: an empty text modality (score ~0) used to give a large 'safe' vote."""
    out = fuse(_noisy([0.24, 0.73, 0.0], r=1.0))
    assert out["diagnostics"]["source_scores"]["branch_b"]["score"] == round(1 - 0.76 * 0.27, 4)  # empty module changes nothing
    assert out["diagnostics"]["branch_terms"]["text"] == 0.0
    # contrast: the same modules scored as independent log-odds votes (empty module -> 0.01) are dragged down hard
    independent = _noisy([0.24, 0.73, 0.01], r=1.0)
    for b in independent["branches"]:
        b.pop("combine", None)
        b.pop("source", None)
    assert fuse(independent)["diagnostics"]["branch_terms"]["text"] < -1.5


def test_source_with_no_findings_is_weak_evidence_of_safety_not_certainty():
    out = fuse(_noisy([0.0, 0.0, 0.0], r=1.0))
    assert out["diagnostics"]["source_scores"]["branch_b"]["score"] == DEFAULT.source_p_floor


def test_dropping_a_module_recomputes_the_source_score():
    r = _noisy([0.5, 0.5, 0.5])
    r["branches"][3].update({"status": "missing", "p_phish": None, "reliability": None})   # text lost
    assert fuse(r)["diagnostics"]["source_scores"]["branch_b"]["score"] == 0.75               # 1 - 0.5^2


def test_noisy_or_source_ignores_rho_and_module_weights_but_uses_source_weight():
    r = _noisy([0.6, 0.6, 0.6])
    base = fuse(r)["diagnostics"]["branch_terms"]
    assert fuse(r, replace(DEFAULT, rho=1.0, branch_w={k: 9.0 for k in DEFAULT.branch_w}))["diagnostics"]["branch_terms"] == base
    heavier = fuse(r, replace(DEFAULT, source_w={"branch_b": 2.0}))["diagnostics"]["branch_terms"]
    assert abs(sum(heavier.values()) - 2 * sum(base.values())) < 1e-2


def test_mixed_combine_rules_fall_back_to_log_odds():
    r = _noisy([0.6, 0.6, 0.6])
    r["branches"][1].pop("combine")
    assert "branch_b" not in fuse(r)["diagnostics"]["source_scores"]


def test_noisy_or_source_counts_once_for_coverage_and_disagreement():
    r = _noisy([0.9, 0.9, 0.9], visual=branch("visual", 0.05, 0.9))
    out = fuse(r)
    assert out["uncertainty"]["coverage"] == round((0.9 + 0.8) / 2, 3)               # 2 sources, not 4 modules
    assert out["uncertainty"]["disagreement"] > MAX_DISAGREEMENT                      # visual vs the Branch B source


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
