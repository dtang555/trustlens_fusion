"""TrustLens fusion service prototype (schema v0.1.0).

Stdlib only. Takes branch outputs (visual / url / dom / text), validates them,
computes cross-modal features, fuses them with a transparent log-odds baseline,
and returns warn / allow / uncertain with explanations built only from verified
detector evidence.

All weights, thresholds and the temperature below are PLACEHOLDERS. They must be
fit / calibrated on the development set before any results are reported.
"""
from __future__ import annotations

import html
import math
import re
from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = "0.1.0"
BRANCHES = ("visual", "url", "dom", "text")
STATUSES = ("ok", "partial", "missing", "error")
USABLE = ("ok", "partial")

# ---------------------------------------------------------------- config ----
# Placeholder parameters (fit with regularised logistic regression later).
BIAS = -2.0
BRANCH_W = {"visual": 1.0, "url": 1.2, "dom": 1.0, "text": 0.6}
CROSS_W = {
    "brand_domain_mismatch": 2.0,
    "cred_request": 1.0,
    "action_mismatch": 1.0,
    "link_deception": 0.5,  # per mismatched link, capped at 3
}
FLOOR_P = 0.90          # rule floor when brand_domain_mismatch AND cred_request
TEMPERATURE = 1.0       # fit after the weights (calibration step)
T_LOW, T_HIGH = 0.20, 0.80
MIN_COVERAGE = 0.50     # sum(reliability of usable branches) / 4
MAX_DISAGREEMENT = 1.0  # strength of the weaker side when reliable branches give opposite verdicts
RELIABLE_R = 0.5        # branches below this are ignored for disagreement
BRAND_CONF_MIN = 0.60   # visual brand confidence needed to call a brand "matched"
TOP_K = 3

# Evidence registry: type -> (required fields, explanation template)
EVIDENCE: dict[str, tuple[tuple[str, ...], str]] = {
    "visual_impersonation": (
        ("claimed_brand", "similarity"),
        "Page visually resembles {claimed_brand} (similarity {similarity}).",
    ),
    "brand_domain_mismatch": (
        ("claimed_brand", "observed_domain"),
        "Page appears to be {claimed_brand} but is hosted on {observed_domain}, "
        "which is not a {claimed_brand} domain.",
    ),
    "credential_solicitation": ((), "Page asks you to enter sign-in credentials."),
    "misleading_link_destination": (
        ("displayed_domain", "actual_domain"),
        "A link shows {displayed_domain} but actually goes to {actual_domain}.",
    ),
    "form_action_mismatch": (
        ("page_domain", "action_domain"),
        "The form on this page submits to {action_domain}, not {page_domain}.",
    ),
    "urgency_language": (("phrase_class",), "Page uses pressuring language ({phrase_class})."),
    "punycode_domain": (("domain",), "The domain {domain} uses disguised (punycode) characters."),
    "hidden_input": (("count",), "The page contains {count} hidden form fields."),
}
LOCATOR_KINDS = ("bbox", "dom_path", "url_span", "none")
MAX_STR = 80
MAX_EVIDENCE = 50


class SchemaError(ValueError):
    """Request-level schema violation (maps to HTTP 422 in a service)."""


# ------------------------------------------------------------- utilities ----
def _num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def _prob(x: Any) -> bool:
    return _num(x) and 0.0 <= x <= 1.0


def logit(p: float, eps: float = 1e-4) -> float:
    p = min(max(p, eps), 1 - eps)
    return math.log(p / (1 - p))


def sigmoid(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-z)) if z >= 0 else math.exp(z) / (1.0 + math.exp(z))


def clean(value: Any) -> str:
    """Untrusted page-derived value -> safe, short, HTML-escaped string."""
    s = re.sub(r"[^\x20-\x7e]", "?", str(value))[:MAX_STR]
    return html.escape(s, quote=True)


# ---------------------------------------------------------------- parsing ----
@dataclass
class Evidence:
    id: str
    type: str
    strength: float
    source_branch: str
    locator: dict
    fields: dict
    verified: bool


@dataclass
class Branch:
    name: str
    status: str
    p_phish: float | None = None
    reliability: float | None = None
    features: dict = field(default_factory=dict)
    claims: dict = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    missing_flags: list[str] = field(default_factory=list)
    latency_ms: int = 0
    dropped_evidence: int = 0
    error: str | None = None

    @property
    def usable(self) -> bool:
        return self.status in USABLE and self.p_phish is not None and self.reliability is not None


def parse_branch(raw: Any) -> Branch:
    """Validate one branch output. Bad branches become status='error', never raise."""
    name = raw.get("branch") if isinstance(raw, dict) else None
    if name not in BRANCHES:
        raise SchemaError(f"unknown branch: {clean(name)}")
    try:
        status = raw.get("status")
        if status not in STATUSES:
            raise ValueError("bad status")
        b = Branch(name=name, status=status, latency_ms=int(raw.get("latency_ms", 0) or 0))
        b.missing_flags = [clean(f) for f in raw.get("missing_flags", [])][:20]
        b.claims = dict(raw.get("claims", {}))
        b.features = dict(raw.get("features", {}))
        if status in USABLE:
            if not (_prob(raw.get("p_phish")) and _prob(raw.get("reliability"))):
                raise ValueError("p_phish / reliability must be finite and in [0,1]")
            b.p_phish, b.reliability = float(raw["p_phish"]), float(raw["reliability"])
        for i, e in enumerate(list(raw.get("evidence", []))[:MAX_EVIDENCE]):
            ev = _parse_evidence(e, name, i)
            if ev is None:
                b.dropped_evidence += 1
            else:
                b.evidence.append(ev)
        return b
    except (ValueError, TypeError, AttributeError) as exc:
        return Branch(name=name, status="error", error=clean(exc))


def _parse_evidence(e: Any, branch: str, i: int) -> Evidence | None:
    """Unknown types / malformed items are dropped (and counted), not passed through."""
    try:
        if e["type"] not in EVIDENCE or not _prob(e["strength"]) or not isinstance(e["verified"], bool):
            return None
        loc = e.get("locator") or {"kind": "none"}
        if loc.get("kind") not in LOCATOR_KINDS:
            return None
        fields = dict(e.get("fields", {}))
        if any(k not in fields for k in EVIDENCE[e["type"]][0]):
            return None
        return Evidence(str(e.get("id", f"{branch}{i}")), e["type"], float(e["strength"]),
                        branch, loc, fields, e["verified"])
    except (KeyError, TypeError, AttributeError, ValueError):
        return None


# ------------------------------------------------------ cross-modal layer ----
def cross_modal(branches: dict[str, Branch]) -> dict:
    """Features no single branch can compute: brand consensus, mismatch, etc."""
    usable = {n: b for n, b in branches.items() if b.usable}

    # Brand consensus: summed confidence of branches claiming each brand.
    votes: dict[str, float] = {}
    for n in ("visual", "text", "dom"):
        b = usable.get(n)
        brand = b.claims.get("brand") if b else None
        if brand:
            votes[brand] = votes.get(brand, 0.0) + float(b.claims.get("brand_conf", 0.0))
    consensus = max(votes, key=votes.get) if votes else None

    url = usable.get("url")
    domain = url.claims.get("domain") if url else None
    owner = url.claims.get("domain_owner_brand") if url else None  # None = not a known brand domain

    all_ev = [e for b in usable.values() for e in b.evidence if e.verified]
    count = lambda t: sum(1 for e in all_ev if e.type == t)  # noqa: E731

    return {
        "consensus_brand": consensus,
        "domain": domain,
        "brand_domain_mismatch": bool(consensus and url and owner != consensus),
        "cred_request": count("credential_solicitation") > 0,
        "action_mismatch": count("form_action_mismatch") > 0,
        "link_deception": min(count("misleading_link_destination"), 3),
    }


# ------------------------------------------------------------------ scoring ----
def score(branches: dict[str, Branch], cross: dict) -> tuple[float, dict, dict]:
    """Weighted log-odds stack with masking. Returns (z, branch_terms, cross_terms)."""
    branch_terms = {
        n: b.reliability * BRANCH_W[n] * logit(b.p_phish) for n, b in branches.items() if b.usable
    }
    cross_terms = {
        "brand_domain_mismatch": CROSS_W["brand_domain_mismatch"] * cross["brand_domain_mismatch"],
        "cred_request": CROSS_W["cred_request"] * cross["cred_request"],
        "action_mismatch": CROSS_W["action_mismatch"] * cross["action_mismatch"],
        "link_deception": CROSS_W["link_deception"] * cross["link_deception"],
    }
    z = BIAS + sum(branch_terms.values()) + sum(cross_terms.values())
    return z, branch_terms, cross_terms


def uncertainty_signals(branches: dict[str, Branch]) -> tuple[float, float]:
    usable = [b for b in branches.values() if b.usable]
    coverage = sum(b.reliability for b in usable) / len(BRANCHES)
    logits = [logit(b.p_phish) for b in usable if b.reliability >= RELIABLE_R]
    # Conflict = opposite verdicts, so it is the confidence of the WEAKER side:
    # +3.5 vs -3.9 -> 3.5 ; -5.5 vs -1.1 (both say safe) -> 0. Differences in
    # confidence between agreeing branches are not disagreement.
    disagreement = min(max(logits), -min(logits)) if len(logits) >= 2 and max(logits) > 0 > min(logits) else 0.0
    return coverage, disagreement


# ----------------------------------------------------------------- decision ----
def decide(p: float, coverage: float, disagreement: float, cross: dict,
           branches: dict[str, Branch], floor_hit: bool) -> tuple[str, list[str]]:
    reasons: list[str] = []
    low_cov = coverage < MIN_COVERAGE
    conflict = disagreement > MAX_DISAGREEMENT

    if p >= T_HIGH:
        if low_cov and not floor_hit:  # a clear attack signature may warn despite thin coverage
            return "uncertain", ["low_coverage"]
        return "warn", []

    if low_cov:
        reasons.append("low_coverage")
    if conflict:
        reasons.append("branch_disagreement")
    vis = branches.get("visual")
    if cross["cred_request"] and vis and vis.usable and float(vis.claims.get("brand_conf", 0.0)) < BRAND_CONF_MIN:
        reasons.append("unseen_brand")  # credential form but no confident reference-brand match
    if p > T_LOW and not reasons:
        reasons.append("gray_zone")
    return ("allow", []) if not reasons else ("uncertain", reasons)


# -------------------------------------------------------------- explanations ----
def explain(branches: dict[str, Branch], cross: dict, branch_terms: dict, cross_terms: dict) -> list[dict]:
    items: list[tuple[float, dict]] = []

    def render(etype: str, fields: dict) -> str:
        return EVIDENCE[etype][1].format(**{k: clean(v) for k, v in fields.items()})

    for n, b in branches.items():
        if not b.usable:
            continue
        total_strength = sum(e.strength for e in b.evidence if e.verified) or 1.0
        for e in b.evidence:
            if not e.verified:  # never explain from unverified items
                continue
            contrib = branch_terms[n] * e.strength / total_strength
            items.append((contrib, {"evidence_id": e.id, "type": e.type, "locator": e.locator,
                                    "text": render(e.type, e.fields), "contribution": round(contrib, 3)}))

    if cross["brand_domain_mismatch"]:  # synthesised by fusion from branch claims
        f = {"claimed_brand": cross["consensus_brand"], "observed_domain": cross["domain"] or "unknown"}
        c = cross_terms["brand_domain_mismatch"]
        items.append((c, {"evidence_id": "x_bdm", "type": "brand_domain_mismatch", "locator": {"kind": "none"},
                          "text": render("brand_domain_mismatch", f), "contribution": round(c, 3)}))

    items = [it for it in items if it[0] > 0]  # only evidence pushing toward 'phishing'
    items.sort(key=lambda t: t[0], reverse=True)
    return [d for _, d in items[:TOP_K]]


# ---------------------------------------------------------------- entry point ----
def fuse(request: dict) -> dict:
    """FusionRequest -> FusionResponse (dicts). Raises SchemaError on request-level faults."""
    if not isinstance(request, dict):
        raise SchemaError("request must be an object")
    if str(request.get("schema_version", "")).split(".")[0] != SCHEMA_VERSION.split(".")[0]:
        raise SchemaError("unsupported schema_version")

    seen: set[str] = set()
    branches: dict[str, Branch] = {}
    for raw in request.get("branches", []):
        b = parse_branch(raw)
        if b.name in seen:
            raise SchemaError(f"duplicate branch: {b.name}")
        seen.add(b.name)
        branches[b.name] = b

    summary = [{"branch": n, "status": b.status, "p_phish": b.p_phish, "used": b.usable,
                **({"error": b.error} if b.error else {})} for n, b in branches.items()]
    base = {"schema_version": SCHEMA_VERSION, "request_id": request.get("request_id"),
            "branch_summary": summary}

    if not any(b.usable for b in branches.values()):
        return {**base, "decision": "uncertain", "p_fused": None, "explanations": [],
                "uncertainty": {"reasons": ["no_usable_branches"], "coverage": 0.0, "disagreement": 0.0},
                "diagnostics": {"method": "baseline_logodds"}}

    cross = cross_modal(branches)
    z, branch_terms, cross_terms = score(branches, cross)
    floor_hit = cross["brand_domain_mismatch"] and cross["cred_request"]
    if floor_hit:
        z = max(z, logit(FLOOR_P))
    p = sigmoid(z / TEMPERATURE)

    coverage, disagreement = uncertainty_signals(branches)
    decision, reasons = decide(p, coverage, disagreement, cross, branches, floor_hit)

    return {**base, "decision": decision, "p_fused": round(p, 4),
            "uncertainty": {"reasons": reasons, "coverage": round(coverage, 3),
                            "disagreement": round(disagreement, 3)},
            "explanations": explain(branches, cross, branch_terms, cross_terms),
            "diagnostics": {"method": "baseline_logodds", "rule_floor": floor_hit,
                            "z": round(z, 3), "consensus_brand": cross["consensus_brand"]}}
