"""Integrated-system evaluation on the SMALL corpus.   python evaluate_fusion.py

Corpus: 13 pages, real Branch B output (corpus/branch_b_outputs.json, from build_corpus.py).
Two configurations of the integrated system:
  real_only    visual module MISSING (the actual state today), Branch B via the adapter
  sim_visual   plus a SIMULATED visual module that reports only the brand a page visibly shows
               (claim + confidence) and gives NO phishing verdict (p_phish = 0.5), because the
               real visual baseline cannot yet separate legitimate from phishing pages.

What this is for: threshold sensitivity, modality ablation, missing / contradictory-module
behaviour, unseen-brand cases, processing cost, and branch contributions. With 13 pages it
CANNOT support a calibration claim, and it does not make one. Outputs are preliminary risk scores.
Writes eval_results.json, EVALUATION.md and (if matplotlib is present) eval_figures.png.
"""
from __future__ import annotations

import copy
import json
import os
import re
import statistics
import time
import tracemalloc
from dataclasses import replace

import branch_b_adapter
import calibration as cal
import url_branch
from fusion import DEFAULT, SCHEMA_VERSION, fuse, logit

HERE = os.path.dirname(os.path.abspath(__file__))
REG = url_branch.load_registry()
COSTS = {"cost A (miss 10, false warn 3, uncertain 1)": (10, 3, 1),
         "cost B (miss 10, false warn 1, uncertain 2)": (10, 1, 2)}
MODES = ("real_only", "sim_visual")
ALL_ZERO_CROSS = {k: 0.0 for k in DEFAULT.cross_w}


# ------------------------------------------------------------------ building ----
def load_corpus() -> dict:
    with open(os.path.join(HERE, "corpus", "branch_b_outputs.json"), encoding="utf-8") as f:
        return json.load(f)


def visual_sim(page: dict, reference: list[str], extra_known: bool = False) -> dict:
    """Simulated visual module: reports the brand the page visibly shows, with high confidence only
    if that brand is in the visual reference set. No phishing verdict (0.5 = neutral)."""
    brand = page["shown_brand"]
    seen = bool(brand) and (brand in reference or extra_known)
    return {"branch": "visual", "status": "ok", "p_phish": 0.5, "reliability": 0.7,
            "claims": {"brand": brand if seen else None, "brand_conf": 0.9 if seen else 0.1},
            "evidence": [], "missing_flags": [], "model_version": "visual-sim-0.1", "latency_ms": 0}


def visual_missing() -> dict:
    return {"branch": "visual", "status": "missing", "p_phish": None, "reliability": None,
            "missing_flags": ["visual.not_connected"], "model_version": "n/a", "latency_ms": 0}


def build(page: dict, mode: str, reference: list[str], registry=REG, extra_known: bool = False) -> dict:
    vis = visual_missing() if mode == "real_only" else visual_sim(page, reference, extra_known)
    return {"schema_version": SCHEMA_VERSION, "request_id": page["name"],
            "branches": [vis] + branch_b_adapter.convert(page["branch_b"], page["url"], registry)}


def ablate(request: dict, drop: set[str]) -> dict:
    r = copy.deepcopy(request)
    for b in r["branches"]:
        if b["branch"] in drop:
            b.update({"status": "missing", "p_phish": None, "reliability": None, "evidence": [], "claims": {},
                      "features": {}, "missing_flags": ["ablated"]})
    return r


# ------------------------------------------------------------------ running ----
def run(pages: list[dict], requests: list[dict], params=DEFAULT) -> list[dict]:
    rows = []
    for page, req in zip(pages, requests):
        res = fuse(req, params)
        d = res["diagnostics"]
        rows.append({"name": page["name"], "label": page["label"], "group": page["group"],
                     "unseen": page["unseen_brand"], "decision": res["decision"], "risk": res["risk_score"],
                     "z": d.get("z"), "floor": d.get("rule_floor", False), "coverage": res["uncertainty"]["coverage"],
                     "disagreement": res["uncertainty"]["disagreement"], "reasons": res["uncertainty"]["reasons"],
                     "branch_terms": d.get("branch_terms", {}), "cross_terms": d.get("cross_terms", {}),
                     "top_explanation": res["explanations"][0]["text"] if res["explanations"] else None})
    return rows


def metrics(rows: list[dict]) -> dict:
    pos = [r for r in rows if r["label"] == 1]
    neg = [r for r in rows if r["label"] == 0]
    c = lambda rs, d: sum(1 for r in rs if r["decision"] == d)  # noqa: E731
    tp, fn, up = c(pos, "warn"), c(pos, "allow"), c(pos, "uncertain")
    fp, tn, ul = c(neg, "warn"), c(neg, "allow"), c(neg, "uncertain")
    scores = [r["risk"] if r["risk"] is not None else 0.5 for r in rows]
    return {"TP": tp, "FN": fn, "phish_uncertain": up, "FP": fp, "TN": tn, "legit_uncertain": ul,
            "precision": tp / (tp + fp) if tp + fp else None, "recall": tp / len(pos) if pos else None,
            "fpr": fp / len(neg) if neg else None, "flagged_recall": (tp + up) / len(pos) if pos else None,
            "uncertain_rate": (up + ul) / len(rows), "auc": cal.auc(scores, [r["label"] for r in rows])}


def cost(m: dict, weights: tuple[int, int, int]) -> int:
    fn_w, fp_w, unc_w = weights
    return fn_w * m["FN"] + fp_w * m["FP"] + unc_w * (m["phish_uncertain"] + m["legit_uncertain"])


def flips(base: list[dict], other: list[dict]) -> int:
    return sum(1 for a, b in zip(base, other) if a["decision"] != b["decision"])


def fmt(x, nd=2):
    return "n/a" if x is None else f"{x:.{nd}f}"


# ------------------------------------------------------------------- analyses ----
def threshold_sensitivity(pages, reqs) -> dict:
    base = run(pages, reqs)
    one_at_a_time = {}
    sweeps = {
        "t_high (warn at or above)": ([0.5, 0.6, 0.7, 0.8, 0.9, 0.95], lambda v: replace(DEFAULT, t_high=v)),
        "t_low (allow at or below)": ([0.05, 0.1, 0.2, 0.3, 0.4], lambda v: replace(DEFAULT, t_low=v)),
        "min_coverage (to allow)": ([0.3, 0.4, 0.5, 0.6], lambda v: replace(DEFAULT, min_coverage=v)),
        "min_coverage_warn": ([0.0, 0.2, 0.3, 0.4, 0.5], lambda v: replace(DEFAULT, min_coverage_warn=v)),
        "max_disagreement": ([0.5, 1.0, 2.0, 3.0], lambda v: replace(DEFAULT, max_disagreement=v)),
        "bias": ([-3.0, -2.5, -2.0, -1.5, -1.0, -0.5, 0.0], lambda v: replace(DEFAULT, bias=v)),
        "Branch B source weight": ([0.5, 1.0, 1.5, 2.0, 3.0], lambda v: replace(DEFAULT, source_w={"branch_b": v})),
    }
    for label, (values, make) in sweeps.items():
        rows = []
        for v in values:
            res = run(pages, reqs, make(v))
            m = metrics(res)
            rows.append({"value": v, "flips_vs_default": flips(base, res), "warn": m["TP"] + m["FP"],
                         "allow": m["FN"] + m["TN"], "uncertain": m["phish_uncertain"] + m["legit_uncertain"],
                         "FN": m["FN"], "FP": m["FP"], "recall": m["recall"], "fpr": m["fpr"]})
        one_at_a_time[label] = rows

    grid = {}
    for cname, w in COSTS.items():
        cells = []
        for th in (0.5, 0.6, 0.7, 0.8, 0.9):
            for tl in (0.05, 0.1, 0.2, 0.3, 0.4):
                if tl >= th:
                    continue
                m = metrics(run(pages, reqs, replace(DEFAULT, t_high=th, t_low=tl)))
                cells.append({"t_high": th, "t_low": tl, "cost": cost(m, w), "FN": m["FN"], "FP": m["FP"],
                              "uncertain": m["phish_uncertain"] + m["legit_uncertain"]})
        best = min(c["cost"] for c in cells)
        grid[cname] = {"cells": cells, "min_cost": best, "argmin": [c for c in cells if c["cost"] == best],
                       "default_cost": next(c["cost"] for c in cells if c["t_high"] == 0.8 and c["t_low"] == 0.2)}
    return {"one_at_a_time": one_at_a_time, "cost_grid": grid}


def branch_b_alone(pages) -> dict:
    """Baseline: Branch B's own risk score with its own threshold, no fusion."""
    rows = []
    for thr in (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9):
        tp = sum(1 for p in pages if p["label"] == 1 and p["branch_b"]["risk_score"] >= thr)
        fp = sum(1 for p in pages if p["label"] == 0 and p["branch_b"]["risk_score"] >= thr)
        P = sum(p["label"] for p in pages)
        rows.append({"threshold": thr, "recall": tp / P, "fpr": fp / (len(pages) - P), "FP": fp, "FN": P - tp})
    hint = [{"name": p["name"], "label": p["label"], "risk": p["branch_b"]["risk_score"],
             "hint": p["branch_b"]["label_hint"]} for p in pages]
    return {"sweep": rows, "per_page": hint,
            "auc": cal.auc([p["branch_b"]["risk_score"] for p in pages], [p["label"] for p in pages])}


def as_logodds(request: dict) -> dict:
    """The earlier adapter behaviour: Branch B's modules as separate log-odds votes. An empty modality (score 0) was
    floored at 0.01 because a log-odds vote needs a non-zero probability."""
    r = copy.deepcopy(request)
    for b in r["branches"]:
        b.pop("combine", None)
        if b.get("p_phish") == 0.0:
            b["p_phish"] = 0.01
    return r


def ablations(pages, reqs) -> list[dict]:
    configs = [
        ("full system", set(), DEFAULT),
        ("drop URL module", {"url"}, DEFAULT), ("drop DOM module", {"dom"}, DEFAULT),
        ("drop text module", {"text"}, DEFAULT),
        ("drop visual module", {"visual"}, DEFAULT),
        ("visual only (drop all Branch B)", {"url", "dom", "text"}, DEFAULT),
        ("no cross-modal terms, no rule floor", set(), replace(DEFAULT, cross_w=ALL_ZERO_CROSS, floor_p=0.0)),
        ("no rule floor", set(), replace(DEFAULT, floor_p=0.0)),
        ("Branch B modules as discounted log-odds votes (rho = 0.5)", set(), DEFAULT, as_logodds),
        ("Branch B modules as independent log-odds votes (rho = 0)", set(), replace(DEFAULT, rho=0.0), as_logodds),
        ("no uncertain state (binary at 0.5)", set(),
         replace(DEFAULT, t_low=0.5, t_high=0.5, min_coverage=0.0, min_coverage_warn=0.0, max_disagreement=99.0,
                 brand_conf_min=0.0)),
        ("v0.1 unseen-brand rule (credential wording + visual)", set(), replace(DEFAULT, unseen_brand_rule="v0.1")),
        ("v0.2 unseen-brand rule (credential form + visual)", set(), replace(DEFAULT, unseen_brand_rule="form")),
        ("conflict blocks warn", set(), replace(DEFAULT, conflict_blocks_warn=True)),
    ]
    base = run(pages, reqs)
    out = []
    for name, drop, params, *mutate in [c if len(c) == 4 else (*c, None) for c in configs]:
        mut = mutate[0]
        rs = run(pages, [ablate(mut(r) if mut else r, drop) for r in reqs], params)
        m = metrics(rs)
        out.append({"config": name, **m, "flips_vs_full": flips(base, rs),
                    "cost_A": cost(m, list(COSTS.values())[0]), "cost_B": cost(m, list(COSTS.values())[1]),
                    "decisions": {r["name"]: r["decision"] for r in rs}})
    return out


def missing_injection(pages, reqs) -> list[dict]:
    base = run(pages, reqs)
    out = []
    for mod in ("visual", "url", "dom", "text"):
        rs = run(pages, [ablate(r, {mod}) for r in reqs])
        changes = [{"page": b["name"], "label": b["label"], "from": b["decision"], "to": r["decision"],
                    # why: did the page lose its brand-domain mismatch, and/or fall below the coverage floor?
                    "lost_brand_mismatch": b["cross_terms"].get("brand_domain_mismatch", 0) > 0 and r["cross_terms"].get("brand_domain_mismatch", 0) == 0,
                    "low_coverage_after": "low_coverage" in r["reasons"] and "low_coverage" not in b["reasons"]}
                   for b, r in zip(base, rs) if b["decision"] != r["decision"]]
        out.append({"dropped": mod, "changed": len(changes),
                    "phish_now_allowed": sum(1 for c in changes if c["label"] == 1 and c["to"] == "allow"),
                    "legit_now_warned": sum(1 for c in changes if c["label"] == 0 and c["to"] == "warn"),
                    "lost_brand_mismatch": sum(c["lost_brand_mismatch"] for c in changes),
                    "low_coverage_after": sum(c["low_coverage_after"] for c in changes),
                    "changes": changes})
    return out


def contradiction_injection(pages, reqs) -> dict:
    """Replace the visual module with a CONFIDENTLY WRONG verdict (0.05 on phishing pages, 0.95 on legitimate
    ones, reliability 0.9) and see whether fusion absorbs it, flags it, or follows it."""
    wrong = []
    for page, r in zip(pages, reqs):
        r = copy.deepcopy(r)
        for b in r["branches"]:
            if b["branch"] == "visual":
                b["p_phish"] = 0.05 if page["label"] == 1 else 0.95
                b["reliability"] = 0.9
        wrong.append(r)
    out = {}
    for name, params in (("default (a high score still warns)", DEFAULT),
                         ("conflict_blocks_warn", replace(DEFAULT, conflict_blocks_warn=True))):
        base = run(pages, reqs, params)
        rs = run(pages, wrong, params)
        wrong_final = sum(1 for r in rs if (r["label"] == 1 and r["decision"] == "allow")
                          or (r["label"] == 0 and r["decision"] == "warn"))
        out[name] = {"decisions_changed": flips(base, rs), "wrong_final_verdicts": wrong_final,
                     "routed_to_uncertain": sum(1 for r in rs if r["decision"] == "uncertain"),
                     "newly_uncertain": sum(1 for a, b in zip(base, rs) if b["decision"] == "uncertain" and a["decision"] != "uncertain"),
                     "disagreement_flagged": sum(1 for r in rs if "branch_disagreement" in r["reasons"]),
                     "rows": [{"page": r["name"], "label": r["label"], "decision": r["decision"],
                               "reasons": r["reasons"]} for r in rs]}
    return out


def unseen_brand(pages, ref) -> list[dict]:
    idx = [i for i, p in enumerate(pages) if p["unseen_brand"]]
    sub = [pages[i] for i in idx]
    reg2 = {**REG, "wealthsimple": {"wealthsimple.com"}, "questrade": {"questrade.com"}}  # registry learns the brands
    variants = [
        ("v0.1 rule (credential wording + visual confidence)", [build(p, "sim_visual", ref) for p in sub],
         replace(DEFAULT, unseen_brand_rule="v0.1")),
        ("v0.2 rule (credential form + visual confidence)", [build(p, "sim_visual", ref) for p in sub],
         replace(DEFAULT, unseen_brand_rule="form")),
        ("current rule (credential form, no brand owns the domain, no module identifies a brand)",
         [build(p, "sim_visual", ref) for p in sub], DEFAULT),
        ("current rule, visual module missing", [build(p, "real_only", ref) for p in sub], DEFAULT),
        ("brand added to visual reference ONLY", [build(p, "sim_visual", ref, REG, True) for p in sub], DEFAULT),
        ("brand added to visual reference AND shared registry", [build(p, "sim_visual", ref, reg2, True) for p in sub],
         DEFAULT),
    ]
    out = []
    for name, reqs, params in variants:
        rs = run(sub, reqs, params)
        out.append({"variant": name, "rows": [{"page": r["name"], "label": r["label"], "decision": r["decision"],
                                               "risk": r["risk"], "reasons": r["reasons"]} for r in rs]})
    return out


def calibration_measurements(pages, reqs_by_mode) -> dict:
    out = {}
    for mode, reqs in reqs_by_mode.items():
        rows = run(pages, reqs)
        out[mode] = cal.summarize([r["z"] for r in rows], [r["label"] for r in rows], n_bins=5, n_boot=1000, seed=0)
    out["branch_b_alone"] = cal.summarize([logit(p["branch_b"]["risk_score"]) for p in pages],
                                          [p["label"] for p in pages], n_bins=5, n_boot=1000, seed=0)
    return out


def processing_cost(pages, reqs, ref) -> dict:
    n_loops = 300
    times = []
    for _ in range(n_loops):
        for r in reqs:
            t0 = time.perf_counter()
            fuse(r)
            times.append((time.perf_counter() - t0) * 1000)
    times.sort()
    conv = []
    for _ in range(n_loops):
        for p in pages:
            t0 = time.perf_counter()
            branch_b_adapter.convert(p["branch_b"], p["url"], REG)
            conv.append((time.perf_counter() - t0) * 1000)
    tracemalloc.start()
    for r in reqs:
        fuse(r)
    peak = tracemalloc.get_traced_memory()[1] / 1024
    tracemalloc.stop()
    bb = [p["branch_b_ms"] for p in pages]
    return {"fuse_ms": {"median": statistics.median(times), "mean": statistics.fmean(times),
                        "p95": times[int(0.95 * len(times))], "max": times[-1]},
            "adapter_ms_median": statistics.median(conv), "branch_b_ms_median": statistics.median(bb),
            "peak_memory_kib_all_pages": peak, "calls_timed": len(times),
            "fusion_share_of_pipeline": statistics.median(times) / (statistics.median(times) + statistics.median(conv)
                                                                     + statistics.median(bb))}


def contributions(pages, reqs) -> dict:
    rows = run(pages, reqs)
    base = {r["name"]: r["risk"] for r in rows}
    out = {"modules": {}, "cross_terms": {}}
    for mod in ("visual", "url", "dom", "text"):
        loo = run(pages, [ablate(r, {mod}) for r in reqs])
        entry = {}
        for lab, name in ((1, "phishing"), (0, "legitimate")):
            sel = [r for r in rows if r["label"] == lab]
            terms = [r["branch_terms"].get(mod) for r in sel if r["branch_terms"].get(mod) is not None]
            deltas = [base[r["name"]] - r2["risk"] for r, r2 in zip(rows, loo) if r["label"] == lab and r2["risk"] is not None]
            entry[name] = {"mean_term": statistics.fmean(terms) if terms else None,
                           "mean_abs_term": statistics.fmean(abs(t) for t in terms) if terms else None,
                           "mean_score_drop_if_removed": statistics.fmean(deltas) if deltas else None}
        out["modules"][mod] = entry
    for key in DEFAULT.cross_w:
        out["cross_terms"][key] = {name: statistics.fmean(r["cross_terms"].get(key, 0.0) for r in rows if r["label"] == lab)
                                   for lab, name in ((1, "phishing"), (0, "legitimate"))}
    return out


# --------------------------------------------------------------------- report ----
def md_table(header: list[str], rows: list[list]) -> str:
    line = lambda cells: "| " + " | ".join(str(c) for c in cells) + " |"  # noqa: E731
    return "\n".join([line(header), line(["---"] * len(header))] + [line(r) for r in rows])


def findings(R: dict) -> list[str]:
    n, npos = R["corpus"]["n"], R["corpus"]["n_phishing"]
    plural = lambda k, w: f"{k} {w}" + ("" if k == 1 else "s")  # noqa: E731
    out = []
    ro, sv = R["metrics"]["real_only"], R["metrics"]["sim_visual"]
    ba = R["branch_b_alone"]["sweep"][2]  # threshold 0.5
    ba_tp = round(ba["recall"] * npos)
    out.append(f"1. **With the visual module missing, fusion warns on {ro['TP']}/{npos} phishing pages and Branch B alone (score at "
               f"or above 0.5) on {ba_tp}/{npos}.** Fusion routes {ro['phish_uncertain']} more phishing pages to uncertain and allows "
               f"{ro['FN']}, so flagged recall (warn + uncertain) is {fmt(ro['flagged_recall'])} against {fmt(ba['recall'])} for Branch B. "
               f"It also sends {ro['legit_uncertain']} of {n - npos} legitimate pages to uncertain and warns on {ro['FP']}.")
    full = R["ablations"]["sim_visual"][0]
    nf = next(a for a in R["ablations"]["sim_visual"] if a["config"].startswith("no cross-modal"))
    nfl = next(a for a in R["ablations"]["sim_visual"] if a["config"] == "no rule floor")
    warned = {n_ for n_, d in full["decisions"].items() if d == "warn"}
    lost_no_floor = [n_ for n_ in warned if nfl["decisions"][n_] != "warn"]
    lost_no_cross = [n_ for n_ in warned if nf["decisions"][n_] != "warn"]
    out.append(f"2. **The rule floor and cross-modal terms carry most of the warnings.** Of {len(warned)} warnings, removing the floor "
               f"removes {len(lost_no_floor)} and removing the cross-modal terms as well removes {len(lost_no_cross)} "
               f"({', '.join(lost_no_cross) or 'none'}).")
    comb = {a["config"]: a for a in R["ablations"]["real_only"]}
    nor, lo5 = comb["full system"], comb["Branch B modules as discounted log-odds votes (rho = 0.5)"]
    differs = [n_ for n_ in nor["decisions"] if nor["decisions"][n_] != lo5["decisions"][n_]]
    out.append(f"3. **How Branch B's three modules are combined changes outcomes.** One noisy-OR source (current): {nor['TP']} warns, "
               f"{nor['FN']} missed, AUC {fmt(nor['auc'])}. Discounted log-odds votes (earlier design): {lo5['TP']} warns, {lo5['FN']} missed, "
               f"AUC {fmt(lo5['auc'])}. The decisions differ on {len(differs)} page(s): {', '.join(differs) or 'none'}. The mechanism, covered by a "
               "regression test: under the earlier design a module with no findings was scored near 0 and cast a large vote for 'safe'.")
    rows_sv = R["default"]["sim_visual"]
    edge = [f"{r['name']} ({fmt(r['risk'], 3)}, {r['decision']})" for r in rows_sv
            if abs(r["risk"] - DEFAULT.t_high) <= 0.03 or abs(r["risk"] - DEFAULT.t_low) <= 0.03]
    out.append(f"3b. **Knife-edge pages** (score within 0.03 of a threshold): {'; '.join(edge) or 'none'}. Thresholds, the bias and the "
               "Branch B source weight can flip these with small changes; see section 2.")
    low_phish = [r for r in rows_sv if r["label"] == 1 and r["risk"] <= DEFAULT.t_low]
    out.append(f"3c. **{len(low_phish)} of {npos} phishing pages score at or below the allow threshold ({DEFAULT.t_low}), so the score alone cannot "
               f"tell them from legitimate pages** ({', '.join(r['name'] for r in low_phish) or 'none'}). Their decisions: "
               f"{', '.join(sorted({r['decision'] for r in low_phish})) or 'n/a'}. Only the uncertain state (unseen brand) catches them.")
    sc = R["sensitivity"]["real_only"]["one_at_a_time"]["min_coverage (to allow)"]
    f4 = next(r for r in sc if r["value"] == 0.4)
    f6 = next(r for r in sc if r["value"] == 0.6)
    out.append(f"4. **The allow-coverage threshold sits on the edge when the visual module is missing.** With two sources the best "
               f"attainable coverage is 0.5, so a Branch B confidence below 1.0 forces uncertain. Lowering it to 0.4 changes "
               f"{plural(f4['flips_vs_default'], 'decision')}; raising it to 0.6 changes {plural(f6['flips_vs_default'], 'decision')}.")
    u = {v["variant"]: v for v in R["unseen_brand"]}
    cur = u["current rule (credential form, no brand owns the domain, no module identifies a brand)"]["rows"]
    cur_miss = u["current rule, visual module missing"]["rows"]
    cf1 = u["brand added to visual reference ONLY"]["rows"]
    cf2 = u["brand added to visual reference AND shared registry"]["rows"]
    flagged = lambda rows: sum(1 for r in rows if r["label"] == 1 and r["decision"] in ("warn", "uncertain"))  # noqa: E731
    friction = lambda rows: sum(1 for r in rows if r["label"] == 0 and r["decision"] != "allow")  # noqa: E731
    out.append(f"5. **Unseen brands are caught by the uncertain state, at a cost.** {flagged(cur)} of {sum(r['label'] for r in cur)} unseen-brand phishing "
               f"pages are flagged, and {friction(cur)} of {sum(1 - r['label'] for r in cur)} legitimate unseen-brand logins also become uncertain. "
               f"The rule no longer depends on the visual module ({flagged(cur_miss)} flagged without it). Adding a brand to the visual "
               f"reference WITHOUT its domains in the shared registry gives {sum(1 for r in cf1 if r['label'] == 0 and r['decision'] == 'warn')} false warns on the "
               f"genuine pages; adding both gives {sum(1 for r in cf2 if r['label'] == 0 and r['decision'] == 'warn')}.")
    mi = {mode: {m["dropped"]: m for m in R["missing_injection"][mode]} for mode in MODES}
    per = "; ".join(f"{mode}: " + ", ".join(f"{k} {v['changed']}" for k, v in mi[mode].items()) for mode in MODES)
    worst = max((m for mode in MODES for m in mi[mode].values()), key=lambda m: m["phish_now_allowed"])
    t_ro, t_sv = mi["real_only"]["text"], mi["sim_visual"]["text"]
    out.append(f"8. **Single-module loss** (decisions changed per dropped module): {per}. At most {worst['phish_now_allowed']} phishing pages become allow. "
               f"**The text module's importance depends on the configuration.** With a simulated visual module it changes {t_sv['changed']} decisions; "
               f"with the visual module missing it changes {t_ro['changed']}, because {t_ro['lost_brand_mismatch']} warnings lose the brand-domain mismatch "
               f"(Branch B's text rule is then the only brand claim) and {t_ro['low_coverage_after']} pages fall below the coverage floor.")
    cd, cb = R["contradiction"]["default (a high score still warns)"], R["contradiction"]["conflict_blocks_warn"]
    changed = sum(1 for x, y in zip(cd["rows"], cb["rows"]) if x["decision"] != y["decision"])
    out.append(f"7. **A confidently wrong visual module** produced {cd['wrong_final_verdicts']} wrong final verdicts; {cd['newly_uncertain']} pages "
               f"were newly routed to uncertain and {cd['disagreement_flagged']} carry a disagreement flag. `conflict_blocks_warn` changes "
               f"{changed} of {len(cd['rows'])} decisions relative to the default.")
    cs = R["calibration"]["sim_visual"]
    out.append(f"8. **No calibration claim is possible.** ECE {fmt(cs['raw']['ece'], 3)} has a 95% bootstrap interval of "
               f"{fmt(cs['raw']['ece_95ci'][0], 3)} to {fmt(cs['raw']['ece_95ci'][1], 3)} on {n} pages; the fitted temperature "
               f"({fmt(cs['temperature_fit']['T'])}) is an in-sample figure, not a result.")
    pc = R["cost"]
    out.append(f"9. **Processing cost is negligible:** fusion takes a median {pc['fuse_ms']['median']:.2f} ms per page "
               f"({pc['fusion_share_of_pipeline'] * 100:.0f}% of the Branch B + adapter + fusion pipeline).")
    return [f"{i}. " + re.sub(r"^\w+\. ", "", s) for i, s in enumerate(out, 1)]  # number sequentially


def write_markdown(R: dict) -> str:
    n, npos = R["corpus"]["n"], R["corpus"]["n_phishing"]
    L = ["# TrustLens fusion: small-corpus evaluation (preliminary)", "",
         f"Corpus: **{n} pages** ({npos} phishing-style, {n - npos} legitimate). Branch B output is real; the visual "
         "module is either missing (`real_only`) or simulated (`sim_visual`, brand claim only, no phishing verdict). "
         "Every score below is a **preliminary risk score**, not a calibrated probability. The corpus is far too small "
         "to support a calibration claim, so this document reports threshold sensitivity, ablations and measurements only.", ""]

    L += ["## Key findings (computed from the tables below)", ""] + findings(R) + [""]
    L += ["## 1. Per-page results", ""]
    rows = []
    for i, p in enumerate(R["pages"]):
        rows.append([p["name"], "phishing" if p["label"] else "legit", fmt(p["branch_b_risk"], 3), p["branch_b_hint"],
                     f"{R['default']['real_only'][i]['decision']} ({fmt(R['default']['real_only'][i]['risk'], 3)})",
                     f"{R['default']['sim_visual'][i]['decision']} ({fmt(R['default']['sim_visual'][i]['risk'], 3)})",
                     ", ".join(R["default"]["sim_visual"][i]["reasons"]) or "-"])
    L += [md_table(["Page", "Label", "Branch B score", "Branch B hint", "Fusion, visual missing", "Fusion, simulated visual",
                    "Uncertainty reasons (sim)"], rows), ""]
    for mode in MODES:
        m = R["metrics"][mode]
        L.append(f"- **{mode}**: warn on {m['TP']}/{npos} phishing, allow on {m['FN']}, uncertain on {m['phish_uncertain']}; "
                 f"false warns {m['FP']}, uncertain on {m['legit_uncertain']} legitimate. Flagged recall (warn + uncertain) "
                 f"{fmt(m['flagged_recall'])}, AUC {fmt(m['auc'])}.")
    ba = R["branch_b_alone"]
    L += [f"- **Branch B alone** (score at or above 0.5): AUC {fmt(ba['auc'])}.", ""]

    L += ["## 2. Threshold sensitivity (the main result at this corpus size)", "",
          "One parameter varied at a time around the defaults. Cells show warn / allow / uncertain counts, then missed "
          "phishing (FN) and false warns (FP), then `flips` = pages whose decision differs from the default configuration.", ""]
    for name in R["sensitivity"]["real_only"]["one_at_a_time"]:
        rows_ = []
        for ro, sv in zip(R["sensitivity"]["real_only"]["one_at_a_time"][name], R["sensitivity"]["sim_visual"]["one_at_a_time"][name]):
            cellf = lambda r: f"{r['warn']}/{r['allow']}/{r['uncertain']}, FN {r['FN']}, FP {r['FP']}, flips {r['flips_vs_default']}"  # noqa: E731
            rows_.append([ro["value"], cellf(ro), cellf(sv)])
        L += [f"**{name}**", "", md_table(["value", "visual missing", "simulated visual"], rows_), ""]
    L += ["**Cost surface over t_high x t_low** (lower is better). The best thresholds depend on the assumed costs, and "
          "many settings tie, which is expected at this corpus size.", ""]
    for mode in MODES:
        for cname, g in R["sensitivity"][mode]["cost_grid"].items():
            best = "; ".join(f"({c['t_high']}, {c['t_low']})" for c in g["argmin"][:5])
            L.append(f"- {mode}, {cname}: minimum cost {g['min_cost']} (default {g['default_cost']}); "
                     f"{len(g['argmin'])} of {len(g['cells'])} (t_high, t_low) cells tie, e.g. {best}.")
    L += ["", "**Branch B alone, threshold sweep:**", "",
          md_table(["threshold", "recall", "false-positive rate", "missed", "false warn"],
                   [[r["threshold"], fmt(r["recall"]), fmt(r["fpr"]), r["FN"], r["FP"]] for r in ba["sweep"]]), ""]

    L += ["## 3. Modality ablations", ""]
    for mode in MODES:
        L += [f"**{mode}**", "", md_table(
            ["config", "warn on phishing", "missed", "uncertain (phish / legit)", "false warn", "precision", "recall", "AUC",
             "flips vs full", "cost A", "cost B"],
            [[a["config"], f"{a['TP']}/{npos}", a["FN"], f"{a['phish_uncertain']} / {a['legit_uncertain']}", a["FP"],
              fmt(a["precision"]), fmt(a["recall"]), fmt(a["auc"]), a["flips_vs_full"], a["cost_A"], a["cost_B"]]
             for a in R["ablations"][mode]]), ""]

    L += ["## 4. Missing-module and contradictory-module behaviour", "",
          "Each module removed in turn. `lost brand mismatch` = changed pages that lost the brand-domain mismatch term; "
          "`low coverage` = changed pages that fell below the coverage floor.", ""]
    for mode in MODES:
        L += [f"**{mode}**", "", md_table(
            ["module removed", "decisions changed", "phishing now allowed", "legitimate now warned", "lost brand mismatch", "low coverage"],
            [[m["dropped"], m["changed"], m["phish_now_allowed"], m["legit_now_warned"], m["lost_brand_mismatch"], m["low_coverage_after"]]
             for m in R["missing_injection"][mode]]), ""]
    L += [
          "Contradiction injection (simulated visual): the visual module is replaced by a confidently wrong verdict (0.05 on phishing, 0.95 on legitimate).", "",
          md_table(["setting", "decisions changed", "wrong final verdicts (allow on phishing / warn on legit)", "newly uncertain",
                    "disagreement flagged"],
                   [[k, v["decisions_changed"], v["wrong_final_verdicts"], v["newly_uncertain"], v["disagreement_flagged"]]
                    for k, v in R["contradiction"].items()]), ""]

    L += ["## 5. Unseen-brand cases", ""]
    for v in R["unseen_brand"]:
        L += [f"**{v['variant']}**", "", md_table(["page", "label", "decision", "risk score", "reasons"],
                                                  [[r["page"], "phishing" if r["label"] else "legit", r["decision"], fmt(r["risk"], 3),
                                                    ", ".join(r["reasons"]) or "-"] for r in v["rows"]]), ""]

    L += ["## 6. Reliability and calibration measurements (illustrative only)", ""]
    for key, c in R["calibration"].items():
        fit = c["temperature_fit"]
        L += [f"**{key}** (n = {c['n']}, {c['n_positive']} phishing)", "",
              f"- ECE {fmt(c['raw']['ece'], 3)} (95% bootstrap interval {fmt(c['raw']['ece_95ci'][0], 3)} to "
              f"{fmt(c['raw']['ece_95ci'][1], 3)}), Brier {fmt(c['raw']['brier'], 3)}, log loss {fmt(c['raw']['log_loss'], 3)}, AUC {fmt(c['auc'])}.",
              f"- Temperature fit: T = {fmt(fit['T'])}, separable data: {fit['separable']}, at search boundary: {fit['at_boundary']}. "
              f"Leave-one-out ECE {fmt(c['leave_one_out']['ece'], 3)}, Brier {fmt(c['leave_one_out']['brier'], 3)}.",
              f"- Calibration claim supported: **{c['claim_supported']}**. {c['claim_note']}", "",
              "```", cal.bins_text(c["raw"]["bins"]), "```", ""]

    pc = R["cost"]
    L += ["## 7. Processing cost", "",
          md_table(["measure", "value"],
                   [["fusion call, median / p95 / max (ms)", f"{pc['fuse_ms']['median']:.3f} / {pc['fuse_ms']['p95']:.3f} / {pc['fuse_ms']['max']:.3f}"],
                    ["Branch B to shared-format adapter, median (ms)", f"{pc['adapter_ms_median']:.3f}"],
                    ["Branch B analysis, median (ms, from Student B's module)", f"{pc['branch_b_ms_median']:.3f}"],
                    ["fusion share of the Branch B + adapter + fusion pipeline", f"{pc['fusion_share_of_pipeline'] * 100:.1f}%"],
                    ["peak memory, fusing all pages (KiB)", f"{pc['peak_memory_kib_all_pages']:.0f}"],
                    ["calls timed", pc["calls_timed"]]]), "",
          "Python on the development machine, not the browser. Visual and browser overheads are not included.", ""]

    ct = R["contributions"]
    L += ["## 8. How each module contributes to the risk assessment (simulated visual)", "",
          "Mean discounted log-odds term per module, and the mean drop in risk score when that module is removed.", "",
          md_table(["module", "mean term (phishing)", "mean term (legit)", "score drop if removed (phishing)",
                    "score drop if removed (legit)"],
                   [[m, fmt(v["phishing"]["mean_term"]), fmt(v["legitimate"]["mean_term"]),
                     fmt(v["phishing"]["mean_score_drop_if_removed"], 3), fmt(v["legitimate"]["mean_score_drop_if_removed"], 3)]
                    for m, v in ct["modules"].items()]), "",
          md_table(["cross-modal term", "mean (phishing)", "mean (legit)"],
                   [[k, fmt(v["phishing"]), fmt(v["legitimate"])] for k, v in ct["cross_terms"].items()]), "",
          "The simulated visual module supplies brand claims only (its own term is zero), so its effect enters through the "
          "cross-modal brand-domain mismatch term.", ""]
    return "\n".join(L)


def figures(R: dict, path: str) -> bool:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return False
    fig, ax = plt.subplots(1, 2, figsize=(11, 4.6))
    rows = sorted(R["default"]["sim_visual"], key=lambda r: r["risk"])
    for i, r in enumerate(rows):
        ax[0].scatter(r["risk"], i, color="#C0392B" if r["label"] else "#2471A3", s=46, zorder=3)
        ax[0].text(1.05, i, f"{r['decision']}", va="center", fontsize=7.5, color="#444")  # fixed decision column
    ax[0].set_yticks(range(len(rows)))
    ax[0].set_yticklabels([r["name"] for r in rows], fontsize=7.5)
    for x, ls in ((DEFAULT.t_low, "--"), (DEFAULT.t_high, "--")):
        ax[0].axvline(x, color="gray", linestyle=ls, linewidth=1)
    ax[0].set_xlim(-0.02, 1.25)
    ax[0].set_xticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax[0].set_xlabel("preliminary risk score")
    ax[0].set_title("Risk score by page (red = phishing-style, blue = legitimate)\ndashed: allow / warn thresholds", fontsize=9)
    bins = R["calibration"]["sim_visual"]["raw"]["bins"]
    for b in bins:
        if b["n"]:
            ax[1].bar((b["lo"] + b["hi"]) / 2, b["frac_positive"], width=0.17, color="#7F8C8D", alpha=0.8)
            ax[1].text((b["lo"] + b["hi"]) / 2, b["frac_positive"] + 0.03, f"n={b['n']}", ha="center", fontsize=8)
    ax[1].plot([0, 1], [0, 1], color="black", linewidth=1, linestyle=":")
    ax[1].set_xlim(0, 1)
    ax[1].set_ylim(0, 1.15)
    ax[1].set_xlabel("preliminary risk score (bin)")
    ax[1].set_ylabel("fraction actually phishing-style")
    ax[1].set_title(f"Reliability diagram, n = {R['corpus']['n']}: illustrative only,\nnot a calibration claim", fontsize=9)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return True


def main() -> dict:
    corpus = load_corpus()
    pages, ref = corpus["pages"], corpus["visual_reference"]
    reqs = {m: [build(p, m, ref) for p in pages] for m in MODES}
    R = {"corpus": corpus["meta"],
         "pages": [{"name": p["name"], "label": p["label"], "branch_b_risk": p["branch_b"]["risk_score"],
                    "branch_b_hint": p["branch_b"]["label_hint"]} for p in pages],
         "default": {m: run(pages, reqs[m]) for m in MODES}}
    R["metrics"] = {m: metrics(R["default"][m]) for m in MODES}
    R["branch_b_alone"] = branch_b_alone(pages)
    R["sensitivity"] = {m: threshold_sensitivity(pages, reqs[m]) for m in MODES}
    R["ablations"] = {m: ablations(pages, reqs[m]) for m in MODES}
    R["missing_injection"] = {m: missing_injection(pages, reqs[m]) for m in MODES}
    R["contradiction"] = contradiction_injection(pages, reqs["sim_visual"])
    R["unseen_brand"] = unseen_brand(pages, ref)
    R["calibration"] = calibration_measurements(pages, reqs)
    R["cost"] = processing_cost(pages, reqs["sim_visual"], ref)
    R["contributions"] = contributions(pages, reqs["sim_visual"])
    with open(os.path.join(HERE, "eval_results.json"), "w", encoding="utf-8") as f:
        json.dump(R, f, indent=1, default=str)
    with open(os.path.join(HERE, "EVALUATION.md"), "w", encoding="utf-8") as f:
        f.write(write_markdown(R))
    R["_figure"] = figures(R, os.path.join(HERE, "eval_figures.png"))
    return R


if __name__ == "__main__":
    R = main()
    print(open(os.path.join(HERE, "EVALUATION.md"), encoding="utf-8").read())
    print("figure written:", R["_figure"])
