"""Connected demonstration:  python connected_demo.py

Real Branch B output (captured from Student B's module) -> adapter -> fusion, with the visual module in
three states. What is real and what is mocked:

    Branch B (URL / DOM / text)   REAL output, captured from Student B's module
    adapter, fusion               REAL code
    visual module: missing        the ACTUAL state today (no real visual output is connected)
    visual module: agrees         MOCKED verdict, only to exercise the handling
    visual module: contradicts    MOCKED verdict, only to exercise the handling

Part 1  missing and contradictory handling      Part 2  Branch B counted as ONE source
Part 3  the output is labelled a preliminary risk score
"""
import copy
import os
from dataclasses import replace

import evaluate_fusion as E
from fusion import DEFAULT, SCHEMA_VERSION, fuse
from worked_case_branch_b import FIXTURES, build_request

PAGES = [("suspicious page (phish classic)", FIXTURES[0], True), ("legitimate page (paypal legit)", FIXTURES[1], False)]


def mock_visual(state: str, is_phish: bool) -> dict:
    if state == "missing":
        return {"branch": "visual", "status": "missing", "p_phish": None, "reliability": None,
                "missing_flags": ["visual.not_connected"], "model_version": "n/a", "latency_ms": 0}
    agrees = state == "agrees"
    p = (0.9 if is_phish else 0.1) if agrees else (0.05 if is_phish else 0.95)
    return {"branch": "visual", "status": "ok", "p_phish": p, "reliability": 0.9,
            "claims": {"brand": "paypal", "brand_conf": 0.9}, "evidence": [], "missing_flags": [],
            "model_version": "visual-MOCK", "latency_ms": 0}


def with_visual(request: dict, state: str, is_phish: bool) -> dict:
    r = copy.deepcopy(request)
    r["branches"][0] = mock_visual(state, is_phish)  # build_request puts the visual module first
    return r


def as_independent(request: dict) -> dict:
    """The earlier design: Branch B's modules as separate, independent log-odds votes."""
    r = copy.deepcopy(request)
    for b in r["branches"]:
        b.pop("combine", None)
        if b.get("p_phish") == 0.0:
            b["p_phish"] = 0.01
    return r


def line(label: str, out: dict) -> str:
    u = out["uncertainty"]
    why = ", ".join(u["reasons"]) or "-"
    return (f"  {label:<26} {out['decision'].upper():<10} preliminary risk score {out['risk_score']:<7}"
            f" coverage {u['coverage']:<6} disagreement {u['disagreement']:<6} reasons: {why}")


def main() -> None:
    print("PART 1: missing and contradictory-modality handling (Branch B real, visual module in three states)")
    for title, path, is_phish in PAGES:
        base = build_request(path)
        print(f"\n {title}")
        for state, note in (("missing", "visual MISSING (real state today)"), ("agrees", "visual agrees (mocked)"),
                            ("contradicts", "visual CONTRADICTS (mocked)")):
            print(line(note, fuse(with_visual(base, state, is_phish))))
    print("\n  A contradicting visual verdict on a legitimate page gives UNCERTAIN (branch_disagreement). On the suspicious page the")
    print("  brand mismatch plus credential form (rule floor) still warns; the conflict shows in the disagreement value.")

    print("\n\nPART 2: Branch B's URL, DOM and text are one combined result, so they count as ONE source")
    corpus = E.load_corpus()
    page = next(p for p in corpus["pages"] if p["name"] == "phish shortened + hidden form")
    req = E.build(page, "real_only", corpus["visual_reference"])
    out = fuse(req)
    mods = {b["branch"]: b for b in req["branches"] if b["branch"] != "visual"}
    print(f"\n {page['name']}  (real Branch B output; visual module missing)")
    print("  module scores (noisy-OR of each modality's own rules): " + ", ".join(f"{k} {v['p_phish']:.3f}" for k, v in mods.items()))
    src = out["diagnostics"]["source_scores"]["branch_b"]
    print(f"  combined ONCE as one source ({src['combine']}): {src['score']}      source groups: {out['diagnostics']['source_groups']}")
    print(f"  coverage counts the source once: {out['uncertainty']['coverage']}")
    print(line("as ONE source (current)", out))
    print(line("as independent votes (old)", fuse(as_independent(req), replace(DEFAULT, rho=0.0))))
    print("  The old design summed the three modules' log-odds as independent votes. The weakly-scoring modules (URL 0.30, text 0.10)")
    print("  each voted 'safe' and pulled a genuinely suspicious page below the warn threshold. Regression tests: test_fusion.py.")
    print("\n\nPART 3: output labelling")
    print(f"  score_label:        {out['score_label']}")
    print(f"  calibration_status: {out['calibration_status']}")
    print(f"  schema_version:     {SCHEMA_VERSION}")


if __name__ == "__main__":
    main()
