"""Branch B -> shared evidence format (fusion schema v0.1.0, Derek Tang).

to_shared(result, request_id=None, page_id=None, latency_ms=0) takes the output of
url_html_text_branch.analyze() and returns three branch objects, one each for the
"url", "dom" and "text" branches that fusion expects:

{"schema_version", "request_id", "page_id", "branch", "status", "p_phish",
 "reliability", "claims", "features", "evidence", "missing_flags", "latency_ms"}

- Evidence with a fusion type is converted (type, strength, locator, fields,
  verified). Branch B evidence with no fusion type yet stays in "features"
  (id -> weight), so fusion does not drop it but it still counts toward p_phish.
- All three objects carry "source": "branch_b": they come from ONE analysis of one
  page, so fusion must not treat them as three independent opinions.
- page_id defaults to the fixture's data-page-id when the page is a test fixture.
- p_phish is the noisy-OR of that modality's weights, clamped to [0.05, 0.99]:
  a branch that found nothing is "probably fine", not "certainly fine".
  These are PLACEHOLDERS until fusion is calibrated on the development set.
"""
from url_html_text_branch import combine

SCHEMA_VERSION = "0.1.0"
MODALITY_TO_BRANCH = {"url": "url", "html": "dom", "text": "text"}
P_FLOOR, P_CEIL = 0.05, 0.99
URL_RELIABILITY = 0.9


def _fusion_item(e, res):
    """Branch B evidence item -> fusion evidence item, or None if fusion has no type for it."""
    d, c = e["detail"], res["claims"]
    page_domain = c["domain"] or "unknown"
    base = {"id": e["id"], "strength": e["weight"], "verified": True}
    i = e["id"]
    if i in ("html.password_form", "text.credential_request"):
        # text alone ("sign in") is not a credential request unless a password is asked for
        if i == "text.credential_request" and not any(x["id"] == "html.password_form" for x in res["evidence"]):
            return None
        loc = {"kind": "dom_path", "value": "form input[type=password]"} if i.startswith("html") else {"kind": "none"}
        return {**base, "type": "credential_solicitation", "locator": loc, "fields": {}}
    if i == "html.cross_domain_form":
        return {**base, "type": "form_action_mismatch", "locator": {"kind": "dom_path", "value": "form[action]"},
                "fields": {"page_domain": page_domain, "action_domain": d["action_domain"]}}
    if i == "html.mismatched_link":
        shown, actual = (d.get("pairs") or [["unknown", "unknown"]])[0]
        return {**base, "type": "misleading_link_destination", "locator": {"kind": "dom_path", "value": "a[href]"},
                "fields": {"displayed_domain": shown, "actual_domain": actual, "count": d["count"]}}
    if i == "text.urgency":
        return {**base, "type": "urgency_language", "locator": {"kind": "none"},
                "fields": {"phrase_class": ", ".join(d["terms"][:3])}}
    if i == "url.idn_host":
        return {**base, "type": "punycode_domain", "locator": {"kind": "url_span", "value": d["ascii"]},
                "fields": {"domain": d["ascii"]}}
    if i in ("url.brand_in_domain", "url.typosquat", "text.brand_claim_mismatch"):
        # When the page claims a brand, fusion builds this explanation itself from
        # claims.brand + claims.domain_owner_brand; sending it too would duplicate it.
        if c["brand"]:
            return None
        return {**base, "type": "brand_domain_mismatch",
                "locator": {"kind": "url_span", "value": d["domain"]} if i.startswith("url") else {"kind": "none"},
                "fields": {"claimed_brand": d["brand"], "observed_domain": d["domain"]}}
    return None


def to_shared(res, request_id=None, page_id=None, latency_ms=0):
    c = res["claims"]
    if page_id is None and res.get("fixture"):
        page_id = res["fixture"]["page_id"]
    out = []
    for modality, branch in MODALITY_TO_BRANCH.items():
        items = [e for e in res["evidence"] if e["modality"] == modality]
        if modality == "url":
            status = "missing" if "url" in res["missing"] else "ok"
            reliability = URL_RELIABILITY
            claims = {"domain": c["domain"], "domain_owner_brand": c["domain_owner_brand"]}
            flags = ["url.local_unscored"] if status == "missing" else []
        else:
            status = "missing" if "html" in res["missing"] else "ok"
            reliability = res["confidence"]
            claims = {"brand": c["brand"], "brand_conf": c["brand_conf"]} if c["brand"] else {}
            flags = [m for m in res["missing"] if m in ("limited_visible_text", "ocr_text")]
        evidence, features = [], {}
        for e in items:
            f = _fusion_item(e, res)
            if f is None:
                features[e["id"]] = e["weight"]
            else:
                evidence.append(f)
        obj = {"schema_version": SCHEMA_VERSION, "request_id": request_id, "page_id": page_id,
               "branch": branch, "source": "branch_b", "status": status, "claims": claims, "features": features,
               "evidence": evidence, "missing_flags": flags, "latency_ms": latency_ms,
               "p_phish": None, "reliability": None}
        if status == "ok":
            p = combine([e["weight"] for e in items])
            obj["p_phish"] = round(min(max(p, P_FLOOR), P_CEIL), 4)
            obj["reliability"] = reliability
        out.append(obj)
    return out
