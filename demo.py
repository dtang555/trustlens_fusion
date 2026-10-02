"""Run synthetic scenarios through the fusion prototype:  python demo.py [--json]"""
import json
import sys

from fusion import SCHEMA_VERSION, fuse


def ev(etype, strength, fields=None, kind="none", value=None, verified=True, eid=None):
    return {"id": eid or etype, "type": etype, "strength": strength,
            "locator": {"kind": kind, "value": value}, "fields": fields or {}, "verified": verified}


def branch(name, p=None, r=None, status="ok", claims=None, evidence=None, flags=None):
    return {"branch": name, "status": status, "p_phish": p, "reliability": r,
            "claims": claims or {}, "evidence": evidence or [],
            "missing_flags": flags or [], "latency_ms": 10}


def req(name, branches):
    return name, {"schema_version": SCHEMA_VERSION, "request_id": name, "branches": branches}


SCENARIOS = [
    # 1. Fake PayPal page on a look-alike domain: every branch agrees -> warn
    req("phishing_paypal", [
        branch("visual", 0.91, 0.85, claims={"brand": "paypal", "brand_conf": 0.93},
               evidence=[ev("visual_impersonation", 0.93, {"claimed_brand": "paypal", "similarity": 0.93},
                            "bbox", [120, 40, 200, 60])]),
        branch("url", 0.72, 0.90, claims={"domain": "paypa1-login.xyz", "domain_owner_brand": None}),
        branch("dom", 0.88, 0.90, claims={"brand": "paypal", "brand_conf": 0.7},
               evidence=[ev("credential_solicitation", 0.9, kind="dom_path", value="form#login input[type=password]"),
                         ev("form_action_mismatch", 0.8, {"page_domain": "paypa1-login.xyz",
                                                           "action_domain": "collector.example"})]),
        branch("text", 0.70, 0.60, evidence=[ev("urgency_language", 0.6, {"phrase_class": "account suspended"})]),
    ]),
    # 2. Real Microsoft single sign-on page: has a credential form but domain matches brand -> allow
    req("legit_sso_microsoft", [
        branch("visual", 0.15, 0.85, claims={"brand": "microsoft", "brand_conf": 0.95}),
        branch("url", 0.10, 0.90, claims={"domain": "login.microsoftonline.com", "domain_owner_brand": "microsoft"}),
        branch("dom", 0.25, 0.90, claims={"brand": "microsoft", "brand_conf": 0.8},
               evidence=[ev("credential_solicitation", 0.9)]),
        branch("text", 0.20, 0.60),
    ]),
    # 3. Only a weak URL signal arrived (visual missing, DOM errored, text missing) -> uncertain
    req("thin_input", [
        branch("visual", status="missing", flags=["vis.no_screenshot"]),
        branch("url", 0.55, 0.80, claims={"domain": "example-shop.top", "domain_owner_brand": None}),
        branch("dom", status="error"),
        branch("text", status="missing", flags=["text.ocr_empty"]),
    ]),
    # 4. Login form on a brand not in the reference store -> uncertain (unseen brand)
    req("unseen_brand_login", [
        branch("visual", 0.30, 0.80, claims={"brand": None, "brand_conf": 0.1}),
        branch("url", 0.25, 0.90, claims={"domain": "smallbank-example.ca", "domain_owner_brand": None}),
        branch("dom", 0.30, 0.90, evidence=[ev("credential_solicitation", 0.9)]),
        branch("text", 0.30, 0.60),
    ]),
]

if __name__ == "__main__":
    for name, request in SCENARIOS:
        out = fuse(request)
        print(f"\n=== {name}: {out['decision'].upper()}  (p_fused={out['p_fused']}) ===")
        if out["uncertainty"]["reasons"]:
            print("  reasons:", ", ".join(out["uncertainty"]["reasons"]))
        print(f"  coverage={out['uncertainty']['coverage']}  disagreement={out['uncertainty']['disagreement']}")
        for x in out["explanations"]:
            print(f"  - [{x['contribution']:+.2f}] {x['text']}")
    if "--json" in sys.argv:  # python demo.py --json  -> full FusionResponse for scenario 1
        print(json.dumps(fuse(SCENARIOS[0][1]), indent=2))
