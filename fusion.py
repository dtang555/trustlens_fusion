"""TrustLens fusion service prototype (schema v0.1.0, fusion v0.2).

Stdlib only. Takes branch outputs (visual / url / dom / text), validates them,
computes cross-modal features, fuses them with a transparent log-odds baseline,
and returns warn / allow / uncertain with explanations built only from verified
detector evidence.

All weights, thresholds and the temperature below are PLACEHOLDERS. They must be
fit / calibrated on the development set before any results are reported. The output is
a PRELIMINARY RISK SCORE, never a calibrated probability.

v0.2 changes
  * Params: every tunable value is one object, so thresholds / weights can be swept and
    modules ablated without editing code (defaults = the original placeholders).
  * Source groups: modules that arrive from ONE upstream result (e.g. Branch B's URL, DOM
    and text) are correlated, not independent. A branch output may carry an optional
    `source` id (default: its own name) and a `combine` rule:
      "noisy_or"  the modules share one accumulating score (Branch B): the source is scored ONCE
                  from 1 - prod(1 - p_m), which reproduces the upstream combined score exactly, and a
                  module with no findings adds nothing instead of voting "safe";
      "mean"      EQUAL weights: the source score is the plain average of its usable modules' scores; a
                  missing or errored module is simply not counted (it is not in the denominator);
      "logodds"   (default) independent-style modules, summed log-odds discounted within a source
                  by 1 / (1 + (n-1) * rho).
    Coverage and disagreement are measured per source either way.
  * Separate coverage floors for ALLOW (min_coverage) and WARN (min_coverage_warn): missing
    evidence must block a safe verdict more readily than it blocks a warning.
  * Optional conflict_blocks_warn: reliable sources that contradict each other, with no
    rule-floor hit, give `uncertain` instead of `warn`.
  * Unseen-brand rule is ownership-based: a credential FORM on a domain no known brand owns, with no
    confident brand identification from any module. It no longer depends on the visual module, and a
    genuine brand domain is never "unseen" just because logo detection failed.
  * Output field renamed p_fused -> risk_score, labelled "preliminary risk score".
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
MIN_COVERAGE = 0.50     # coverage needed to ALLOW (mean availability over independent sources)
MIN_COVERAGE_WARN = 0.30  # coverage needed to WARN without a rule-floor hit
MAX_DISAGREEMENT = 1.0  # strength of the weaker side when reliable branches give opposite verdicts
RELIABLE_R = 0.5        # branches below this are ignored for disagreement
BRAND_CONF_MIN = 0.60   # visual brand confidence needed to call a brand "matched"
RHO = 0.5               # correlation between modules from the same source (0 = independent, 1 = one voice)
CONFLICT_BLOCKS_WARN = False
TOP_K = 3
SCORE_LABEL = "preliminary risk score"
CALIBRATION_STATUS = "uncalibrated"


@dataclass(frozen=True)
class Params:
    """Tunable fusion parameters. Defaults are the placeholder values above."""
    bias: float = BIAS
    branch_w: dict = field(default_factory=lambda: dict(BRANCH_W))
    cross_w: dict = field(default_factory=lambda: dict(CROSS_W))
    floor_p: float = FLOOR_P
    temperature: float = TEMPERATURE
    t_low: float = T_LOW
    t_high: float = T_HIGH
    min_coverage: float = MIN_COVERAGE
    min_coverage_warn: float = MIN_COVERAGE_WARN
    max_disagreement: float = MAX_DISAGREEMENT
    reliable_r: float = RELIABLE_R
    brand_conf_min: float = BRAND_CONF_MIN
    rho: float = RHO
    source_w: dict = field(default_factory=lambda: {"branch_b": 1.0})  # weight of a noisy-OR source (default 1.0)
    source_p_floor: float = 0.02    # a noisy-OR source with no findings is weak evidence of safety, not certainty
    source_p_ceiling: float = 0.99
    conflict_blocks_warn: bool = CONFLICT_BLOCKS_WARN
    # unseen-brand rule: "v0.1" any credential evidence + visual confidence; "form" needs a credential FORM +
    # visual confidence; "ownership" (default) needs a credential form on a domain no known brand owns with no
    # confident brand identification from ANY module, so it does not depend on the visual module being present
    unseen_brand_rule: str = "ownership"
    calibration_status: str = CALIBRATION_STATUS


DEFAULT = Params()

# Evidence registry: type -> (required fields, explanation template)
EVIDENCE: dict[str, list[tuple[tuple[str, ...], str]]] = {
    "visual_impersonation": [(
        ("claimed_brand", "similarity"),
        "Page visually resembles {claimed_brand} (similarity {similarity}).")],
    "brand_domain_mismatch": [(
        ("claimed_brand", "observed_domain"),
        "Page appears to be {claimed_brand} but is hosted on {observed_domain}, "
        "which is not a {claimed_brand} domain.")],
    "credential_solicitation": [((), "Page asks you to enter sign-in credentials.")],
    # Two variants: the first that the evidence satisfies is used. Branch B currently reports only a count.
    "misleading_link_destination": [
        (("displayed_domain", "actual_domain"),
         "A link shows {displayed_domain} but actually goes to {actual_domain}."),
        (("count",), "{count} link(s) show one address but actually go to a different one.")],
    "form_action_mismatch": [(
        ("page_domain", "action_domain"),
        "The form on this page submits to {action_domain}, not {page_domain}.")],
    "urgency_language": [(("phrase_class",), "Page uses pressuring language ({phrase_class}).")],
    "punycode_domain": [(("domain",), "The domain {domain} uses disguised (punycode) characters.")],
    "hidden_input": [(("count",), "The page contains {count} hidden form fields.")],
}


def _template(etype: str, fields: dict) -> str | None:
    """First template whose required fields are all present, else None."""
    for required, template in EVIDENCE[etype]:
        if all(k in fields for k in required):
            return template
    return None


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
    source: str = ""  # upstream result this module came from (default: its own name)
    combine: str = "logodds"  # how modules of one source combine: "logodds" | "noisy_or" | "mean"

    @property
    def usable(self) -> bool:
        return self.status in USABLE and self.p_phish is not None and self.reliability is not None


def parse_branch(raw: Any) -> Branch:
    """Validate one branch output. Bad branches become status='error', never raise."""
    name = raw.get("branch") if isinstance(raw, dict) else None
    if name not in BRANCHES:
        raise SchemaError(f"unknown branch: {clean(name)}")
    src = raw.get("source")
    src = clean(src) if isinstance(src, str) and src.strip() else name
    comb = raw.get("combine") if raw.get("combine") in ("logodds", "noisy_or", "mean") else "logodds"
    try:
        status = raw.get("status")
        if status not in STATUSES:
            raise ValueError("bad status")
        b = Branch(name=name, status=status, source=src, combine=comb, latency_ms=int(raw.get("latency_ms", 0) or 0))
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
        return Branch(name=name, status="error", error=clean(exc), source=src, combine=comb)


def _parse_evidence(e: Any, branch: str, i: int) -> Evidence | None:
    """Unknown types / malformed items are dropped (and counted), not passed through."""
    try:
        if e["type"] not in EVIDENCE or not _prob(e["strength"]) or not isinstance(e["verified"], bool):
            return None
        loc = e.get("locator") or {"kind": "none"}
        if loc.get("kind") not in LOCATOR_KINDS:
            return None
        fields = dict(e.get("fields", {}))
        if _template(e["type"], fields) is None:
            return None
        return Evidence(str(e.get("id", f"{branch}{i}")), e["type"], float(e["strength"]),
                        branch, loc, fields, e["verified"])
    except (KeyError, TypeError, AttributeError, ValueError):
        return None


# ------------------------------------------------------ cross-modal layer ----
def cross_modal(branches: dict[str, Branch], P: Params = DEFAULT) -> dict:
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

    support = votes.get(consensus, 0.0) if consensus else 0.0
    return {
        "consensus_brand": consensus,
        "brand_support": support,       # summed confidence behind the consensus brand
        "domain_owner": owner,          # known brand that genuinely owns the page's domain, if any
        "url_usable": url is not None,
        "domain": domain,
        "brand_domain_mismatch": bool(consensus and url and owner != consensus),
        "cred_request": count("credential_solicitation") > 0,
        # an actual credential FORM (reported by the DOM module), not merely "sign in" wording in text
        "cred_form": any(e.type == "credential_solicitation" and e.source_branch == "dom" for e in all_ev),
        "action_mismatch": count("form_action_mismatch") > 0,
        "link_deception": min(count("misleading_link_destination"), 3),
    }


# ------------------------------------------------------------------ scoring ----
def source_groups(branches: dict[str, Branch]) -> dict[str, list[str]]:
    """source id -> member modules, over the four canonical modules. A module absent from the
    request is its own source, so independent requests behave exactly as in fusion v0.1."""
    groups: dict[str, list[str]] = {}
    for n in BRANCHES:
        b = branches.get(n)
        groups.setdefault(b.source if b else n, []).append(n)
    return groups


def source_summary(members: list[str], branches: dict[str, Branch], P: Params = DEFAULT) -> dict | None:
    """One source's usable modules reduced to a single verdict (log-odds), or None if none is usable.
    Missing / errored modules are never counted, whatever the rule.

    mean      p = (sum of p_m) / (number of USABLE modules)   equal weights; clamped to [source_p_floor, source_p_ceiling]
    noisy_or  p = 1 - prod(1 - p_m)                            same clamp
    logodds   reliability-weighted mean of the members' log-odds"""
    used = [branches[n] for n in members if n in branches and branches[n].usable]
    if not used:
        return None
    r = sum(b.reliability for b in used) / len(used)
    kinds = {b.combine for b in used}
    if len(kinds) == 1 and kinds <= {"noisy_or", "mean"}:
        kind = kinds.pop()
        raw = (sum(b.p_phish for b in used) / len(used) if kind == "mean"
               else 1.0 - math.prod(1.0 - b.p_phish for b in used))
        p = min(max(raw, P.source_p_floor), P.source_p_ceiling)
        return {"kind": kind, "used": used, "reliability": r, "p": p, "verdict": logit(p)}
    total_r = sum(b.reliability for b in used)
    verdict = sum(b.reliability * logit(b.p_phish) for b in used) / total_r if total_r > 0 else 0.0
    return {"kind": "logodds", "used": used, "reliability": r, "p": None, "verdict": verdict}


def score(branches: dict[str, Branch], cross: dict, P: Params = DEFAULT) -> tuple[float, dict, dict]:
    """Weighted log-odds stack with masking and per-source handling of correlated modules.
    Returns (z, branch_terms, cross_terms).

    Modules from one source share evidence, so adding their log-odds as if independent double counts.
      mean / noisy_or sources are scored ONCE (reliability x source weight x logit of the combined score); that term
        is shared out EQUALLY over the member modules that have findings (p_m > 0), so each Branch B output carries
        the same weight in the explanations.
      logodds sources: each module term is reliability x module weight x logit(p), and the sum over the source is
        scaled by 1 / (1 + (n - 1) * rho): rho = 0 keeps v0.1 behaviour, rho = 1 counts the source once (its mean)."""
    branch_terms: dict[str, float] = {}
    for src, members in source_groups(branches).items():
        info = source_summary(members, branches, P)
        if info is None:
            continue
        used = info["used"]
        if info["kind"] in ("noisy_or", "mean"):
            term = info["reliability"] * P.source_w.get(src, 1.0) * info["verdict"]
            # every module that contributed to the source score gets an EQUAL share of its term; a module
            # with no findings (p = 0) adds nothing to the noisy-OR, so it gets no share
            active = [b for b in used if b.p_phish > 0] or used
            for b in used:
                branch_terms[b.name] = term / len(active) if b in active else 0.0
        else:
            f = 1.0 / (1.0 + (len(used) - 1) * P.rho)
            for b in used:
                branch_terms[b.name] = b.reliability * P.branch_w[b.name] * logit(b.p_phish) * f
    cross_terms = {k: P.cross_w[k] * cross[k] for k in
                   ("brand_domain_mismatch", "cred_request", "action_mismatch", "link_deception")}
    z = P.bias + sum(branch_terms.values()) + sum(cross_terms.values())
    return z, branch_terms, cross_terms


def uncertainty_signals(branches: dict[str, Branch], P: Params = DEFAULT) -> tuple[float, float]:
    """(coverage, disagreement), both measured per SOURCE, not per module.

    coverage     = mean over sources of (sum of usable members' reliability / members in source).
                   Three modules of one source therefore count once, not three times.
    disagreement = confidence of the weaker side when reliable sources give opposite verdicts.
    """
    groups = source_groups(branches)
    availability, verdicts = [], []
    for members in groups.values():
        info = source_summary(members, branches, P)
        availability.append(sum(branches[n].reliability for n in members if n in branches and branches[n].usable) / len(members))
        if info is not None and info["reliability"] >= P.reliable_r:
            verdicts.append(info["verdict"])
    coverage = sum(availability) / len(groups)
    # Conflict = opposite verdicts, so it is the confidence of the WEAKER side:
    # +3.5 vs -3.9 -> 3.5 ; -5.5 vs -1.1 (both say safe) -> 0.
    disagreement = min(max(verdicts), -min(verdicts)) if len(verdicts) >= 2 and max(verdicts) > 0 > min(verdicts) else 0.0
    return coverage, disagreement


# ----------------------------------------------------------------- decision ----
def unseen_brand(cross: dict, branches: dict[str, Branch], P: Params = DEFAULT) -> bool:
    """True when a credential page cannot be tied to any known brand (see Params.unseen_brand_rule)."""
    if P.unseen_brand_rule in ("v0.1", "form"):
        cred = cross["cred_request"] if P.unseen_brand_rule == "v0.1" else cross["cred_form"]
        vis = branches.get("visual")
        return bool(cred and vis and vis.usable and float(vis.claims.get("brand_conf", 0.0)) < P.brand_conf_min)
    # "ownership": a genuine brand domain verifies the brand without any logo detection; a confident brand claim on
    # an unowned domain is a brand-domain MISMATCH (handled by the cross-modal term), not an unseen brand
    return bool(cross["cred_form"] and cross["url_usable"] and cross["domain_owner"] is None
                and cross["brand_support"] < P.brand_conf_min)


def decide(p: float, coverage: float, disagreement: float, cross: dict,
           branches: dict[str, Branch], floor_hit: bool, P: Params = DEFAULT) -> tuple[str, list[str]]:
    reasons: list[str] = []
    conflict = disagreement > P.max_disagreement

    if p >= P.t_high:
        if coverage < P.min_coverage_warn and not floor_hit:  # a clear attack signature may warn on thin coverage
            return "uncertain", ["low_coverage"]
        if conflict and P.conflict_blocks_warn and not floor_hit:
            return "uncertain", ["branch_disagreement"]
        return "warn", []

    if coverage < P.min_coverage:
        reasons.append("low_coverage")
    if conflict:
        reasons.append("branch_disagreement")
    if unseen_brand(cross, branches, P):
        reasons.append("unseen_brand")  # credential form but no confident brand identification
    if p > P.t_low and not reasons:
        reasons.append("gray_zone")
    return ("allow", []) if not reasons else ("uncertain", reasons)


# -------------------------------------------------------------- explanations ----
def explain(branches: dict[str, Branch], cross: dict, branch_terms: dict, cross_terms: dict) -> list[dict]:
    items: list[tuple[float, dict]] = []

    def render(etype: str, fields: dict) -> str:
        return _template(etype, fields).format(**{k: clean(v) for k, v in fields.items()})

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
def fuse(request: dict, params: Params | None = None) -> dict:
    """FusionRequest -> FusionResponse (dicts). Raises SchemaError on request-level faults.
    The score is a PRELIMINARY RISK SCORE (uncalibrated) unless `params` says otherwise."""
    P = params or DEFAULT
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

    summary = [{"branch": n, "status": b.status, "p_phish": b.p_phish, "used": b.usable, "source": b.source,
                **({"error": b.error} if b.error else {})} for n, b in branches.items()]
    base = {"schema_version": SCHEMA_VERSION, "request_id": request.get("request_id"),
            "branch_summary": summary, "score_label": SCORE_LABEL, "calibration_status": P.calibration_status}

    if not any(b.usable for b in branches.values()):
        return {**base, "decision": "uncertain", "risk_score": None, "explanations": [],
                "uncertainty": {"reasons": ["no_usable_branches"], "coverage": 0.0, "disagreement": 0.0},
                "diagnostics": {"method": "baseline_logodds"}}

    cross = cross_modal(branches, P)
    z, branch_terms, cross_terms = score(branches, cross, P)
    floor_hit = cross["brand_domain_mismatch"] and cross["cred_request"]
    if floor_hit and P.floor_p > 0:  # floor_p = 0 switches the rule floor off (ablation)
        z = max(z, logit(P.floor_p))
    p = sigmoid(z / P.temperature)

    coverage, disagreement = uncertainty_signals(branches, P)
    decision, reasons = decide(p, coverage, disagreement, cross, branches, floor_hit, P)

    return {**base, "decision": decision, "risk_score": round(p, 4),
            "uncertainty": {"reasons": reasons, "coverage": round(coverage, 3),
                            "disagreement": round(disagreement, 3)},
            "explanations": explain(branches, cross, branch_terms, cross_terms),
            "diagnostics": {"method": "baseline_logodds", "rule_floor": floor_hit, "z": round(z, 3),
                            "consensus_brand": cross["consensus_brand"], "temperature": P.temperature,
                            "rho": P.rho, "source_groups": source_groups(branches),
                            "source_scores": {src: {"combine": i["kind"], "score": round(i["p"], 4)}
                                              for src, m in source_groups(branches).items()
                                              if (i := source_summary(m, branches, P)) and i["p"] is not None},
                            "branch_terms": {k: round(v, 3) for k, v in branch_terms.items()},
                            "cross_terms": {k: round(v, 3) for k, v in cross_terms.items()}}}
