"""Adapter: Branch B result (url_html_text_branch.py) -> shared BranchOutput format.

Branch B returns ONE result {risk_score, confidence, missing, evidence[]}. Fusion expects
separate url / dom / text branches, so the adapter splits the evidence list by modality and
re-applies Branch B's own noisy-OR per modality:   p = 1 - prod(1 - weight_i)

Mapping decisions (document these in the report):
  * Rule IDs that match a shared evidence type become evidence items (verified=True,
    strength = rule weight). The others are kept as boolean `features` and still count toward
    the modality score, but cannot be explained to the user until the shared registry covers them.
  * Branch B reports no brand confidence: claims.brand_conf = weight of the brand rule.
  * Branch B reports one overall confidence: it is used as `reliability` for all three branches.
  * Modality score is clamped to [0.01, 0.99] so an empty modality cannot dominate the log-odds.
  * Domain ownership (needed for brand-domain mismatch) comes from the shared brand registry.

Field names (`id`, `modality`, `weight`, `details`) are assumed - confirm with Student B.
"""
from __future__ import annotations

from math import prod
from urllib.parse import urlsplit

import url_branch

PREFIX_TO_BRANCH = {"url": "url", "html": "dom", "text": "text"}

# rule id -> (shared evidence type, builder(details, ctx) -> fields)
EVIDENCE_MAP = {
    "html.cross_domain_form": ("form_action_mismatch",
                               lambda d, c: {"page_domain": c["domain"], "action_domain": d["action_domain"]}),
    "html.mismatched_link": ("misleading_link_destination",
                             lambda d, c: {"displayed_domain": d["displayed_domain"],
                                           "actual_domain": d["actual_domain"]}),
    "html.password_form": ("credential_solicitation", lambda d, c: {"input_types": "password"}),
    "text.credential_request": ("credential_solicitation", lambda d, c: {"phrase_class": "credential request"}),
    "text.urgency": ("urgency_language",
                     lambda d, c: {"phrase_class": ", ".join(d.get("phrases", [])[:2]) or "urgency"}),
}


def _noisy_or(weights: list[float]) -> float:
    return 1.0 - prod(1.0 - w for w in weights)


def convert(result: dict, url: str, registry: dict | None = None) -> list[dict]:
    registry = registry or url_branch.load_registry()
    host = urlsplit(url if "://" in url else "http://" + url).hostname or ""
    domain = url_branch.registered_domain(host) or host
    owner = next((slug for slug, doms in registry.items() if domain in doms), None)
    ctx = {"domain": domain}
    reliability = float(result.get("confidence", 0.0))
    missing = [str(m) for m in result.get("missing", [])]

    items: dict[str, list[dict]] = {"url": [], "dom": [], "text": []}
    for ev in result.get("evidence", []):
        prefix = str(ev["id"]).split(".")[0]
        if prefix in PREFIX_TO_BRANCH:
            items[PREFIX_TO_BRANCH[prefix]].append(ev)

    out = {}
    for branch, evs in items.items():
        weights = [float(e["weight"]) for e in evs]
        p = min(max(_noisy_or(weights), 0.01), 0.99)
        features, evidence, claims = {}, [], {}
        for e in evs:
            rid, d = e["id"], e.get("details", {})
            if rid in EVIDENCE_MAP:
                etype, build = EVIDENCE_MAP[rid]
                evidence.append({"id": rid, "type": etype, "strength": float(e["weight"]), "verified": True,
                                 "locator": {"kind": "none"}, "fields": build(d, ctx)})
            else:
                features[rid] = True  # carried, scored, but not yet explainable
            if rid == "text.brand_claim_mismatch":
                claims = {"brand": str(d.get("brand", "")).lower() or None, "brand_conf": float(e["weight"])}
            if rid == "url.brand_in_domain":
                claims["brand_in_domain"] = str(d.get("brand", "")).lower() or None
        if branch == "url":
            claims.update({"domain": domain, "domain_owner_brand": owner})
        out[branch] = {
            "branch": branch, "status": "partial" if (branch == "text" and "limited_visible_text" in missing) else "ok",
            "p_phish": round(p, 4), "reliability": reliability, "features": features, "claims": claims,
            "evidence": evidence, "missing_flags": missing if branch == "text" else [],
            "model_version": "branch-b-adapter-0.1", "latency_ms": 0,
        }
    return [out["url"], out["dom"], out["text"]]
