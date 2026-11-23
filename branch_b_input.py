"""Branch B -> fusion input, built on Student B's shared_adapter.to_shared() (her file, used unmodified).

    convert(result, registry=None, combine=COMBINE) -> [url, dom, text] branch outputs for fusion

to_shared() does the format conversion: one object per modality, evidence mapped to the shared types, claims, missing
flags, source="branch_b". This module only adds what fusion needs on top, on the fusion side:

  * combine = "noisy_or": the three modules are ONE Branch B result, scored once with Branch B's own combination
    1 - prod(1 - p_m), so fusion's Branch B source score equals Student B's risk_score.
  * URL reliability = Branch B's confidence. to_shared() fixes it at 0.9; with the visual module missing that puts
    coverage at 0.483, under the 0.5 allow floor, so no page could ever be allowed.
  * A module in which no rule fired gets p_phish 0.0 instead of the adapter's 0.05 floor, so it adds nothing to the
    noisy-OR (with the floor, plain blog would score 0.14 instead of Branch B's 0.00). Fusion keeps its own source
    floor of 0.02, so "found nothing" is still weak evidence of safety, not certainty.
  * registry (optional): a {brand: {domains}} map that overrides Branch B's own brand-ownership list. Only the
    evaluation's "brand added to the shared registry" counterfactual uses it.
"""
from __future__ import annotations

from shared_adapter import to_shared

COMBINE = "noisy_or"


def convert(result: dict, registry: dict | None = None, combine: str = COMBINE,
            request_id: str | None = None, page_id: str | None = None) -> list[dict]:
    mods = to_shared(result, request_id=request_id, page_id=page_id)
    for m in mods:
        m["combine"] = combine
        if m["status"] != "ok":
            continue
        if m["branch"] == "url":
            m["reliability"] = float(result.get("confidence", m["reliability"]))
            if registry is not None:
                dom = m["claims"].get("domain")
                m["claims"]["domain_owner_brand"] = next((b for b, ds in registry.items() if dom in ds), None)
        if not m["evidence"] and not m["features"]:
            m["p_phish"] = 0.0
    return mods
