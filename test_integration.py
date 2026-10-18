"""Integration / contract tests.  Run with:  python test_integration.py  (also works under pytest)"""
import glob
import json
import os
import tempfile

import url_branch
from fusion import fuse, parse_branch
from make_sample_bundle import build
from run_bundle import PATTERN, run_folder


# ------------------------------------------------------------ URL branch ----
def test_lookalike_domain_detected():
    o = url_branch.analyze("https://www.paypa1-login.xyz/signin")
    assert o["claims"]["domain"] == "paypa1-login.xyz" and o["claims"]["domain_owner_brand"] is None
    assert o["claims"]["brand_in_domain"] == "paypal" and o["features"]["url.leet_swap"] and o["p_phish"] > 0.6


def test_genuine_brand_domain_owned_and_low_risk():
    o = url_branch.analyze("https://login.microsoftonline.com/common/oauth2")
    assert o["claims"]["domain_owner_brand"] == "microsoft" and o["p_phish"] < 0.05


def test_subdomain_trick_is_not_owned():
    o = url_branch.analyze("https://paypal.com.evil-site.xyz/login")
    assert o["claims"]["domain"] == "evil-site.xyz" and o["claims"]["domain_owner_brand"] is None
    assert o["claims"]["brand_in_domain"] == "paypal"


def test_userinfo_trick_uses_real_host():
    o = url_branch.analyze("https://paypal.com@evil.xyz/")
    assert o["claims"]["domain"] == "evil.xyz" and o["features"]["url.has_userinfo"]


def test_punycode_emits_verified_evidence_and_passes_fusion_parser():
    o = url_branch.analyze("https://xn--pypal-4ve.com")
    assert [e["type"] for e in o["evidence"]] == ["punycode_domain"]
    b = parse_branch(o)
    assert b.usable and len(b.evidence) == 1 and b.dropped_evidence == 0


def test_shortener_is_partial_with_lower_reliability():
    o = url_branch.analyze("https://bit.ly/3abc")
    assert o["status"] == "partial" and o["reliability"] < 0.9


def test_unparseable_urls_become_error_branches():
    for bad in ["", "   ", "http://", "x" * 3000]:
        o = url_branch.analyze(bad)
        assert o["status"] == "error" and o["missing_flags"] == ["url.unparseable"]
        assert not parse_branch(o).usable


def test_url_output_always_satisfies_fusion_schema():
    for u in ["https://a.b", "http://192.168.0.1/x", "https://www.example.co.uk/login", "paypal.com/x"]:
        b = parse_branch(url_branch.analyze(u))
        assert b.status in ("ok", "partial") and b.usable, u


# ------------------------------------------------------- bundle end-to-end ----
def _bundle():
    d = tempfile.mkdtemp()
    build(d)
    return d


def test_bundle_decisions_with_real_url_branch():
    results = run_folder(_bundle(), write=False)
    got = {page: r["decision"] for page, (_, r) in results.items()}
    assert got == {"phishing_paypal": "warn", "legit_sso_microsoft": "allow",
                   "thin_input": "uncertain", "unseen_brand_login": "uncertain"}, got


def test_bundle_writes_request_and_response_json():
    d = _bundle()
    run_folder(d)
    for page in ("phishing_paypal", "thin_input"):
        for kind in ("request", "response"):
            with open(os.path.join(d, "out", f"{page}.{kind}.json")) as f:
                json.load(f)


def test_contract_every_branch_file_parses_without_error():
    d = _bundle()
    for path in glob.glob(os.path.join(d, "*.json")):
        branch = PATTERN.match(os.path.basename(path))["branch"]
        raw = json.load(open(path))
        assert raw["branch"] == branch
        assert parse_branch(raw).status in ("ok", "partial", "missing", "error")
    for page in ("phishing_paypal", "legit_sso_microsoft", "unseen_brand_login"):
        b = parse_branch(json.load(open(os.path.join(d, f"{page}.visual.json"))))
        assert b.usable and b.dropped_evidence == 0  # no evidence silently dropped by the parser


# --------------------------------------------------------- fault injection ----
def test_corrupted_branch_file_degrades_to_error_not_crash():
    d = _bundle()
    with open(os.path.join(d, "phishing_paypal.visual.json"), "w") as f:
        f.write("{ not json")
    _, r = run_folder(d, only="phishing_paypal", write=False)["phishing_paypal"]
    summary = {b["branch"]: b for b in r["branch_summary"]}
    assert summary["visual"]["status"] == "error" and r["decision"] in ("warn", "uncertain")


def test_branch_file_with_wrong_branch_name_is_rejected():
    d = _bundle()
    os.replace(os.path.join(d, "phishing_paypal.dom.json"), os.path.join(d, "phishing_paypal.text.json"))
    _, r = run_folder(d, only="phishing_paypal", write=False)["phishing_paypal"]
    assert {b["branch"]: b for b in r["branch_summary"]}["text"]["status"] == "error"


def test_all_branch_files_missing_is_uncertain_never_allow():
    d = tempfile.mkdtemp()
    for b in ("visual", "dom", "text"):
        with open(os.path.join(d, f"p1.{b}.json"), "w") as f:
            f.write("garbage")
    with open(os.path.join(d, "p1.url.txt"), "w") as f:
        f.write("")
    _, r = run_folder(d, write=False)["p1"]
    assert r["decision"] == "uncertain" and r["uncertainty"]["reasons"] == ["no_usable_branches"]


def test_full_pipeline_phishing_url_is_what_triggers_the_mismatch():
    d = _bundle()
    _, r = run_folder(d, only="phishing_paypal", write=False)["phishing_paypal"]
    assert r["explanations"][0]["type"] == "brand_domain_mismatch"
    # swap in the genuine PayPal URL: the cross-modal mismatch must disappear
    with open(os.path.join(d, "phishing_paypal.url.txt"), "w") as f:
        f.write("https://www.paypal.com/signin\n")
    _, r2 = run_folder(d, only="phishing_paypal", write=False)["phishing_paypal"]
    assert all(x["type"] != "brand_domain_mismatch" for x in r2["explanations"])
    assert r2["p_fused"] < r["p_fused"]


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
