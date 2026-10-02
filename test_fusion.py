"""Regression tests. Run with:  python test_fusion.py   (also works under pytest)"""
import copy

from demo import SCENARIOS, branch, ev, req
from fusion import SCHEMA_VERSION, SchemaError, fuse, logit

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
    assert out["decision"] != "allow" or out["uncertainty"]["disagreement"] <= 3.0
    assert out["uncertainty"]["disagreement"] > 3.0


def test_logit_is_finite_at_extremes():
    assert abs(logit(0.0)) < 20 and abs(logit(1.0)) < 20


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
