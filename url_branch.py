"""Rule-based URL branch (stand-in values, til branch b is complete).

Takes a raw URL string and returns a BranchOutput dict in the shared schema.
Fully offline: no WHOIS, no reputation APIs. Weights are PLACEHOLDERS.

    python url_branch.py "https://www.paypa1-login.xyz/signin"

Known limits: registered-domain extraction uses a tiny built-in list of
multi-part suffixes (co.uk, com.au, ...). Swap in a full public-suffix list
(e.g. the tldextract offline snapshot) before reporting results.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import sys
import time
from collections import Counter
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_VERSION = "url-rules-0.1"

LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
MULTI_SUFFIX = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.nz", "co.jp", "co.in",
                "com.br", "com.mx", "com.cn", "co.za", "com.sg", "com.hk"}
RISKY_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "zip", "icu", "work", "buzz", "rest", "cyou"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly"}
SUSPICIOUS_TOKENS = ("login", "signin", "secure", "verify", "account", "update", "support", "wallet",
                     "auth", "billing", "confirm")

# Placeholder rule weights (log-odds). Fit/replace with a trained classifier later.
W = {"bias": -2.5, "owned": -3.0, "leet": 2.5, "brand_token": 1.5, "punycode": 2.0, "userinfo": 1.5,
     "ip": 1.5, "shortener": 0.7, "risky_tld": 0.8, "token": 0.6, "hyphens": 0.4, "depth": 0.4, "long": 0.3}


def load_registry(path: str | None = None) -> dict[str, set[str]]:
    with open(path or os.path.join(HERE, "brand_registry.json"), encoding="utf-8") as f:
        raw = json.load(f)
    return {slug: set(v["domains"]) for slug, v in raw.items() if not slug.startswith("_")}


def registered_domain(host: str) -> str | None:
    labels = host.split(".")
    if len(labels) < 2:
        return None
    if ".".join(labels[-2:]) in MULTI_SUFFIX and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def find_brand(host: str, reg: str, registry: dict[str, set[str]]) -> tuple[str | None, bool]:
    """Return (brand slug, matched_only_after_leet_normalisation) for a brand that this host
    mimics but does not own. TLD label is ignored."""
    labels = host.split(".")[:-1]
    best: tuple[str, bool] | None = None
    for slug, domains in registry.items():
        if reg in domains:
            continue
        for label in labels:
            raw = label.replace("-", "")
            norm = label.translate(LEET).replace("-", "")
            if len(slug) >= 4:
                plain, leet = slug in raw, slug in norm
            else:  # short slugs (rbc, td, bmo): exact token match only, to avoid noise
                plain = slug in re.split(r"-", label)
                leet = slug in re.split(r"-", label.translate(LEET))
            if plain:
                return slug, False
            if leet and best is None:
                best = (slug, True)
    return best if best else (None, False)


def _error(flag: str, t0: float) -> dict:
    return {"branch": "url", "status": "error", "p_phish": None, "reliability": None, "features": {},
            "claims": {}, "evidence": [], "missing_flags": [flag], "input_quality": {"parsed": False},
            "model_version": MODEL_VERSION, "latency_ms": int((time.perf_counter() - t0) * 1000)}


def analyze(url: str, registry: dict[str, set[str]] | None = None) -> dict:
    t0 = time.perf_counter()
    registry = registry or load_registry()
    raw = (url or "").strip()
    if not raw or len(raw) > 2048:
        return _error("url.unparseable", t0)
    try:
        parts = urlsplit(raw if "://" in raw else "http://" + raw)
        host = parts.hostname
    except ValueError:
        return _error("url.unparseable", t0)
    if not host:
        return _error("url.unparseable", t0)
    try:  # internationalised hosts are analysed in their punycode form (a safe ASCII string)
        host = host.rstrip(".").encode("idna").decode("ascii") if not host.isascii() else host.rstrip(".")
    except UnicodeError:
        return _error("url.unparseable", t0)

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    reg = host if is_ip else registered_domain(host)
    if reg is None:
        return _error("url.unparseable", t0)

    owner = next((slug for slug, doms in registry.items() if reg in doms), None)
    has_punycode = any(lbl.startswith("xn--") for lbl in host.split("."))
    has_userinfo = "@" in parts.netloc
    shortener = reg in SHORTENERS
    tld = host.rsplit(".", 1)[-1]
    risky_tld = (not is_ip) and tld in RISKY_TLDS
    depth = 0 if is_ip else max(len(host.split(".")) - len(reg.split(".")), 0)
    hyphens = host.count("-")
    tokens = sum(1 for t in SUSPICIOUS_TOKENS if t in host)
    brand, leet = (None, False) if (owner or is_ip) else find_brand(host, reg, registry)
    sld = reg.split(".")[0]

    if owner:  # genuine brand domain: other lexical cues are not held against it
        z = W["bias"] + W["owned"]
    else:
        z = (W["bias"] + W["leet"] * (brand is not None and leet) + W["brand_token"] * (brand is not None and not leet)
             + W["punycode"] * has_punycode + W["userinfo"] * has_userinfo + W["ip"] * is_ip
             + W["shortener"] * shortener + W["risky_tld"] * risky_tld + W["token"] * min(tokens, 2)
             + W["hyphens"] * (hyphens >= 2) + W["depth"] * (depth >= 3) + W["long"] * (len(raw) > 75))
    p = 1 / (1 + math.exp(-z))

    features = {
        "url.length": len(raw), "url.subdomain_depth": depth, "url.hyphens": hyphens,
        "url.digit_ratio": round(sum(c.isdigit() for c in sld) / max(len(sld), 1), 3),
        "url.entropy": round(entropy(sld), 3), "url.has_punycode": has_punycode, "url.is_ip": is_ip,
        "url.has_userinfo": has_userinfo, "url.is_shortener": shortener, "url.risky_tld": risky_tld,
        "url.suspicious_tokens": tokens, "url.brand_token": brand is not None and not leet,
        "url.leet_swap": brand is not None and leet, "url.owned_by_brand": owner is not None,
    }
    evidence = []
    if has_punycode:
        start = raw.find(host)
        evidence.append({"id": "url_puny", "type": "punycode_domain", "strength": 0.8, "verified": True,
                         "locator": {"kind": "url_span", "value": [max(start, 0), max(start, 0) + len(host)]},
                         "fields": {"domain": reg}})

    return {"branch": "url", "status": "partial" if shortener else "ok", "p_phish": round(p, 4),
            "reliability": 0.6 if shortener else 0.9, "features": features,
            "claims": {"domain": reg, "domain_owner_brand": owner, "brand_in_domain": brand},
            "evidence": evidence, "missing_flags": ["url.shortener_unresolved"] if shortener else [],
            "input_quality": {"parsed": True}, "model_version": MODEL_VERSION,
            "latency_ms": int((time.perf_counter() - t0) * 1000)}


if __name__ == "__main__":
    print(json.dumps(analyze(sys.argv[1] if len(sys.argv) > 1 else ""), indent=2))
