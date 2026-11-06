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
  * A modality with no fired rule gets score 0.0. Fusion combines the three modules with Branch B's own
    noisy-OR (combine="noisy_or"), so an empty modality adds nothing rather than voting "safe".
  * Domain ownership (needed for brand-domain mismatch) comes from the shared brand registry.
  * The three outputs carry source="branch_b" and combine="noisy_or": they are NOT independent evidence.
    Fusion scores the source ONCE from 1 - prod(1 - p_m) (= Branch B's own combined score) and counts it as
    one source for coverage and disagreement.

Field names follow Student B's real output: id, modality, weight, description, detail.
(`details` is also accepted.) html.mismatched_link currently reports only {"count": n}; the
shared registry has a count-only variant for it. Ask Student B to also report the displayed and
actual domains so the explanation can name them.
"""
from __future__ import annotations

import ipaddress
from math import prod
from urllib.parse import urlsplit

import url_branch

PREFIX_TO_BRANCH = {"url": "url", "html": "dom", "text": "text"}
# All three modules come from ONE Branch B result and share its rules, so they are correlated.
# Tagging them with a common source id lets fusion discount them instead of counting 3 voices.
SOURCE_ID = "branch_b"

# rule id -> (shared evidence type, builder(details, ctx) -> fields)
EVIDENCE_MAP = {
    "html.cross_domain_form": ("form_action_mismatch",
                               lambda d, c: {"page_domain": c["domain"], "action_domain": d["action_domain"]}),
    "html.mismatched_link": ("misleading_link_destination",
                             lambda d, c: ({"displayed_domain": d["displayed_domain"], "actual_domain": d["actual_domain"]}
                                           if "displayed_domain" in d and "actual_domain" in d
                                           else {"count": int(d.get("count", 1))})),
    "html.password_form": ("credential_solicitation", lambda d, c: {"input_types": "password"}),
    "text.credential_request": ("credential_solicitation", lambda d, c: {"phrase_class": "credential request"}),
    "text.urgency": ("urgency_language",
                     lambda d, c: {"phrase_class": ", ".join(d.get("terms", d.get("phrases", []))[:2]) or "urgency"}),
}


def _noisy_or(weights: list[float]) -> float:
    return 1.0 - prod(1.0 - w for w in weights)


def convert(result: dict, url: str, registry: dict | None = None) -> list[dict]:
    registry = registry or url_branch.load_registry()
    host = urlsplit(url if "://" in url else "http://" + url).hostname or ""
    try:  # a raw IP has no registered domain: report the address itself
        ipaddress.ip_address(host)
        domain = host
    except ValueError:
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
        p = _noisy_or(weights)  # 0.0 when no rule fired in this modality: it adds nothing to the source score
        features, evidence, claims = {}, [], {}
        for e in evs:
            rid, d = e["id"], e.get("detail", e.get("details", {}))
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
            "branch": branch, "source": SOURCE_ID, "combine": "noisy_or",
            "status": "partial" if (branch == "text" and "limited_visible_text" in missing) else "ok",
            "p_phish": round(p, 4), "reliability": reliability, "features": features, "claims": claims,
            "evidence": evidence, "missing_flags": missing if branch == "text" else [],
            "model_version": "branch-b-adapter-0.1", "latency_ms": 0,
        }
    return [out["url"], out["dom"], out["text"]]
