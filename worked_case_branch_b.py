"""Worked case built from Branch B output:  python worked_case_branch_b.py [--json]

Branch B fixture -> adapter (url / dom / text) + visual marked missing -> fusion.
"""
import json
import os
import sys

import branch_b_adapter
from fusion import SCHEMA_VERSION, cross_modal, fuse, parse_branch, score

HERE = os.path.dirname(os.path.abspath(__file__))  # fixtures are found relative to this file, not the cwd
FIXTURES = [os.path.join(HERE, "branch_b_fixtures", "phishing_paypal_branch_b.json"),
            os.path.join(HERE, "branch_b_fixtures", "legit_paypal_branch_b.json")]
VISUAL_MISSING = {"branch": "visual", "status": "missing", "p_phish": None, "reliability": None,
                  "missing_flags": ["visual.not_connected"], "model_version": "n/a", "latency_ms": 0}


def build_request(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        fx = json.load(f)
    branches = [VISUAL_MISSING] + branch_b_adapter.convert(fx["result"], fx["url"])
    return {"schema_version": SCHEMA_VERSION, "request_id": os.path.basename(path), "branches": branches}


def report(path: str) -> None:
    request = build_request(path)
    parsed = {b["branch"]: parse_branch(b) for b in request["branches"]}
    cross = cross_modal(parsed)
    z, branch_terms, cross_terms = score(parsed, cross)
    out = fuse(request)
    print(f"\n=== {path} ===")
    for b in request["branches"][1:]:
        print(f"  {b['branch']:5} score={b['p_phish']:.3f} reliability={b['reliability']}  term={branch_terms[b['branch']]:+.2f}")
    print("  cross terms:", {k: round(v, 2) for k, v in cross_terms.items() if v})
    print(f"  z={z:.2f}  -> preliminary risk score {out['p_fused']}  decision={out['decision'].upper()}")
    print(f"  coverage={out['uncertainty']['coverage']}  disagreement={out['uncertainty']['disagreement']}  "
          f"reasons={out['uncertainty']['reasons']}  rule_floor={out['diagnostics']['rule_floor']}")
    for x in out["explanations"]:
        print(f"  - [{x['contribution']:+.2f}] {x['text']}")
    if "--json" in sys.argv:
        print(json.dumps(request, indent=2))


if __name__ == "__main__":
    for p in FIXTURES:
        report(p)