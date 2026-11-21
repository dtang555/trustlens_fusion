"""Connected demonstration:  python connected_demo.py

Real Branch B output (captured from Student B's module) -> adapter -> fusion, with the visual module in
three states. What is real and what is mocked:

    Branch B (URL / DOM / text)   REAL output, captured from Student B's module
    adapter, fusion               REAL code
    visual module: missing        the ACTUAL state today (no real visual output is connected)
    visual module: agrees         MOCKED verdict, only to exercise the handling
    visual module: contradicts    MOCKED verdict, only to exercise the handling

Part 1  missing and contradictory handling   Part 2a/2b  Branch B: one source, equal weights, missing not counted
Part 3  the output is labelled a preliminary risk score
"""
import copy
import json
import os
from dataclasses import replace

import branch_b_adapter
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


def url_only(result: dict) -> dict:
    """What Branch B returns for a URL with no HTML: only URL rules can fire, HTML and visible text are missing and
    confidence drops to 0.4. Constructed from the fixture's own URL rules (Branch B's module is not needed to run this demo)."""
    return {**result, "confidence": 0.4, "missing": ["html", "visible_text", "ocr_text"],
            "evidence": [e for e in result["evidence"] if str(e["id"]).startswith("url.")]}


def counted_as_zero(request: dict) -> dict:
    """Counterfactual: the missing modules counted as real 'found nothing' scores of 0.0 instead of being left out."""
    r = copy.deepcopy(request)
    for b in r["branches"]:
        if b["branch"] in ("dom", "text"):
            b.update({"status": "ok", "p_phish": 0.0, "reliability": 0.4})
    return r


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

    print("\n\nPART 2a: Branch B's URL, DOM and text are ONE combined result: one source, equal weights")
    corpus = E.load_corpus()
    page = next(p for p in corpus["pages"] if p["name"] == "phish shortened + hidden form")
    req = E.build(page, "real_only", corpus["visual_reference"])
    mods = {b["branch"]: b for b in req["branches"] if b["branch"] != "visual"}
    out = fuse(req)
    print(f"\n {page['name']}  (real Branch B output; visual module missing)")
    print("  module scores: " + ", ".join(f"{k} {v['p_phish']:.3f}" for k, v in mods.items()))
    src = out["diagnostics"]["source_scores"]["branch_b"]
    shown = " + ".join("%.3f" % v["p_phish"] for v in mods.values())
    print(f"  equal weights: ({shown}) / {len(mods)} = {src['score']}   [{src['combine']}, "
          f"source groups: {out['diagnostics']['source_groups']}]")
    print(f"  coverage counts the source once: {out['uncertainty']['coverage']}")
    print(line("equal-weight mean (current)", out))
    print(line("noisy-OR (earlier default)", fuse(E.as_noisy_or(req))))
    print(line("independent votes (earliest)", fuse(as_independent(req), replace(DEFAULT, rho=0.0))))
    print("  Averaging dilutes one strong module (DOM 0.811) with weaker ones, so this page is uncertain, not a warning; noisy-OR let the")
    print("  evidence accumulate and warned. The mean cannot be inflated by many weak signals. The trade-off is measured in EVALUATION.md.")

    print("\n\nPART 2b: a missing input is not counted")
    title, path, _ = PAGES[0]
    with open(path, encoding="utf-8") as f:
        fixture = json.load(f)
    uo = branch_b_adapter.convert(url_only(fixture["result"]), fixture["url"])
    req2 = {"schema_version": SCHEMA_VERSION, "request_id": "url-only", "branches": [mock_visual("missing", True)] + uo}
    out2 = fuse(req2)
    print(f"\n {title}, analysed from the URL alone (no HTML supplied)")
    for b in uo:
        p = "-" if b["p_phish"] is None else f"{b['p_phish']:.3f}"
        note = "  <- input missing, NOT counted" if b["status"] == "missing" else ""
        print(f"  {b['branch']:<5} status {b['status']:<8} score {p:<6} missing_flags {b['missing_flags']}{note}")
    s2 = out2["diagnostics"]["source_scores"]["branch_b"]["score"]
    s0 = fuse(counted_as_zero(req2))["diagnostics"]["source_scores"]["branch_b"]["score"]
    print(f"  source score with the missing modules left out: {s2}      if they were counted as 0.0: {s0}")
    print(line("left out (current)", out2))
    print(line("counted as 0.0 (wrong)", fuse(counted_as_zero(req2))))

    print("\n\nPART 3: output labelling")
    print(f"  score_label:        {out['score_label']}")
    print(f"  calibration_status: {out['calibration_status']}")
    print(f"  schema_version:     {SCHEMA_VERSION}")


if __name__ == "__main__":
    main()
