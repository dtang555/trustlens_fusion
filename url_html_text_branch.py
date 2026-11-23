"""
TrustLens - Branch B: URL, HTML/DOM and visible-text analysis (Stacy Nwankwo).

Pure standard library, fully offline. Input values typed into forms are never
read (only structure: tag/type/action), so no credentials can be collected.

analyze(url, html=None, ocr_text=None, intended_url=None) -> dict:
{
  "branch": "url_html_text", "risk_score": 0..1, "confidence": 0..1,
  "label_hint": "safe" | "uncertain" | "suspicious",   # advisory only; fusion decides
  "missing": [...],                                    # missing-data indicators
  "evidence": [{"id","modality","weight","description","detail"}...],
  "analyzed_url": "...",   # the URL the URL/domain rules were run on
  "url_source": "page" | "manifest" | "fixture_meta" | "local_unscored",
  "claims": {"brand", "brand_conf", "domain", "domain_owner_brand"}
}

Locally hosted test fixtures (MCR II/III): a fixture served from localhost declares
the URL it imitates with the team fixture attributes on its root element
  <html data-page-id="P02" data-intended-url="https://..." data-claimed-brand="...">
(Daniel's corpus format; the older <meta name="trustlens:intended-url"> tag is still
read), or the corpus inventory passes it as intended_url. The URL rules then run on that URL
instead of localhost. The meta tag is only honoured when the page really is served
locally; on a public host it is reported as evidence (a page should never carry it).
shared_adapter.to_shared() converts the result to the fusion schema (v0.1.0).
"""
import re
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qs, unquote
from difflib import SequenceMatcher

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc"}
SUSPICIOUS_TLDS = {"top", "xyz", "click", "zip", "country", "gq", "tk", "ml", "cf", "ga",
                   "work", "support", "rest", "loan", "icu", "cam"}
TWO_PART_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "com.au", "co.nz", "co.jp", "com.br",
                     "co.in", "com.mx", "co.za", "com.cn"}
# Curated reference set (extend as the offline corpus grows).
BRANDS = {
    "paypal":    {"domains": {"paypal.com"}},
    "microsoft": {"domains": {"microsoft.com", "live.com", "microsoftonline.com", "office.com"}},
    "google":    {"domains": {"google.com", "gmail.com", "youtube.com"}},
    "apple":     {"domains": {"apple.com", "icloud.com"}},
    "amazon":    {"domains": {"amazon.com", "amazon.ca", "amazon.co.uk"}},
    "netflix":   {"domains": {"netflix.com"}},
    "rbc":       {"domains": {"rbc.com", "rbcroyalbank.com"}},
    "td":        {"domains": {"td.com", "tdcanadatrust.com"}},
    "facebook":  {"domains": {"facebook.com", "fb.com"}},
}
CRED_TERMS = ["password", "passcode", "verify your account", "confirm your identity",
              "social insurance", "ssn", "card number", "cvv", "security code", "pin",
              "sign in", "log in", "login"]
URGENCY_TERMS = ["urgent", "immediately", "within 24 hours", "suspended", "locked",
                 "final notice", "act now", "expires", "unauthorized", "limited time",
                 "verify now", "will be closed"]
SENSITIVE_URL_WORDS = ["login", "signin", "verify", "secure", "account", "update", "confirm", "banking"]
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
        "param", "source", "track", "wbr"}
INTENDED_META = "trustlens:intended-url"
LOCAL_HOSTS = {"localhost", "0.0.0.0", "::1"}
URL_LIKE = re.compile(r"(https?://|www\.)\S+|\b[\w-]+(\.[\w-]+)+\.(com|ca|net|org|io|co|uk)\b", re.I)


# ----------------------------------------------------------------- URL helpers
def host_of(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""

def is_ip(host):
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host)) or (":" in host)

def registered_domain(host):
    if not host or is_ip(host):
        return host
    p = host.split(".")
    if len(p) <= 2:
        return host
    if ".".join(p[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(p[-3:])
    return ".".join(p[-2:])

def is_local(url):
    """True for pages served from this machine (local test server or file)."""
    if url.lower().startswith("file:"):
        return True
    host = host_of(url)
    return (host in LOCAL_HOSTS or host.endswith(".localhost")
            or bool(re.fullmatch(r"127(\.\d{1,3}){3}", host)))

def _norm_leet(s):
    return s.replace("0", "o").replace("1", "l").replace("3", "e").replace("5", "s").replace("rn", "m").replace("vv", "w")

def _is_brand_domain(rd, brand):
    return rd in BRANDS[brand]["domains"]


# ------------------------------------------------------------------- HTML parse
class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.title = ""
        self.in_title = False
        self.visible, self.hidden_text, self.scripts = [], [], []
        self.forms, self.links, self.iframes, self.inputs = [], [], [], []
        self.meta_refresh = None
        self.intended_url = None
        self.fixture_id = None      # data-page-id (test metadata only)
        self.fixture_brand = None   # data-claimed-brand (test label, never used as evidence)
        self._form = None
        self._link = None

    def _hidden(self):
        return any(h for _, h in self.stack)

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        st = a.get("style", "").replace(" ", "").lower()
        own_hidden = ("hidden" in a or "display:none" in st or "visibility:hidden" in st
                      or bool(re.search(r"opacity:0(?![.\d])", st)) or "font-size:0" in st
                      or bool(re.search(r"(left|top):-\d{3,}", st)))
        hidden = own_hidden or self._hidden()
        if a.get("data-intended-url", "").strip() and self.intended_url is None:
            self.intended_url = a["data-intended-url"].strip()
            self.fixture_id = a.get("data-page-id", "").strip() or None
            self.fixture_brand = a.get("data-claimed-brand", "").strip() or None
        if tag not in VOID:
            self.stack.append((tag, own_hidden))
        if tag == "title":
            self.in_title = True
        elif tag == "form":
            self._form = {"action": a.get("action", "").strip(), "hidden": hidden, "password": False, "n_inputs": 0}
            self.forms.append(self._form)
        elif tag == "input":
            t = a.get("type", "text").lower()
            self.inputs.append((t, hidden))
            if self._form is not None:
                self._form["n_inputs"] += 1
                if t == "password":
                    self._form["password"] = True
        elif tag == "a":
            self._link = {"href": a.get("href", "").strip(), "text": "", "hidden": hidden}
        elif tag == "iframe":
            tiny = a.get("width") in ("0", "1") or a.get("height") in ("0", "1")
            self.iframes.append({"src": a.get("src", ""), "hidden": hidden or tiny})
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh = a.get("content", "")
        elif tag == "meta" and a.get("name", "").lower() == INTENDED_META and self.intended_url is None:
            self.intended_url = a.get("content", "").strip() or None

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        if tag == "title":
            self.in_title = False
        elif tag == "form":
            self._form = None
        elif tag == "a" and self._link is not None:
            self.links.append(self._link)
            self._link = None
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        names = {t for t, _ in self.stack}
        if self.in_title:
            self.title += data
        elif "script" in names:
            self.scripts.append(data)
        elif "style" in names:
            pass
        else:
            (self.hidden_text if self._hidden() else self.visible).append(data)
            if self._link is not None:
                self._link["text"] += data


def parse_html(html):
    p = _Page()
    p.feed(html)
    p.close()
    return p


def visible_text(html):
    """Text a user would actually see (hidden/script/style content removed)."""
    return re.sub(r"\s+", " ", " ".join(parse_html(html).visible)).strip()


# --------------------------------------------------------------------- analysis
def _ev(out, id_, modality, weight, description, **detail):
    out.append({"id": id_, "modality": modality, "weight": round(weight, 3),
                "description": description, "detail": detail})

def url_evidence(url):
    ev = []
    host, parsed = host_of(url), urlparse(url)
    rd = registered_domain(host)
    labels = host.split(".") if host else []
    if is_ip(host):
        _ev(ev, "url.ip_host", "url", 0.5, "URL uses a raw IP address instead of a domain", host=host)
    if "@" in parsed.netloc:
        _ev(ev, "url.at_symbol", "url", 0.4, "URL contains '@', which can hide the real destination")
    if rd in SHORTENERS:
        _ev(ev, "url.shortener", "url", 0.3, "Shortened link hides the final destination", domain=rd)
    if len(url) > 100:
        _ev(ev, "url.long", "url", 0.15, "Unusually long URL", length=len(url))
    if len(labels) - len(rd.split(".")) >= 3:
        _ev(ev, "url.many_subdomains", "url", 0.2, "Excessive subdomain depth", host=host)
    if labels and labels[-1] in SUSPICIOUS_TLDS:
        _ev(ev, "url.suspicious_tld", "url", 0.2, "Top-level domain frequently abused", tld=labels[-1])
    if parsed.scheme == "http":
        _ev(ev, "url.no_https", "url", 0.1, "Page is not served over HTTPS")
    if host.count("-") >= 3:
        _ev(ev, "url.hyphens", "url", 0.15, "Many hyphens in hostname", host=host)
    if any(l.startswith("xn--") for l in labels) or any(ord(c) > 127 for c in host):
        try:
            safe = host.encode("idna").decode("ascii")
        except UnicodeError:
            safe = "<unencodable>"
        _ev(ev, "url.idn_host", "url", 0.25, "Internationalized hostname (possible homograph); shown as safe ASCII string", ascii=safe)
    if len(re.findall(r"%[0-9a-fA-F]{2}", url)) >= 5:
        _ev(ev, "url.encoded_chars", "url", 0.15, "Heavy percent-encoding (obfuscation)")
    if any(re.match(r"https?://", unquote(v[0]), re.I) for v in parse_qs(parsed.query).values() if v):
        _ev(ev, "url.embedded_redirect", "url", 0.25, "URL carries another URL in its query (open redirect pattern)")
    if any(w in (host + parsed.path).lower() for w in SENSITIVE_URL_WORDS):
        _ev(ev, "url.sensitive_words", "url", 0.05, "Login/verification keywords in URL")
    # brand impersonation in domain
    sld_labels = re.split(r"[.\-]", host.replace(rd, "") + "." + rd.split(".")[0]) if host else []
    for brand in BRANDS:
        if _is_brand_domain(rd, brand):
            continue
        if brand in host and len(brand) > 3:
            _ev(ev, "url.brand_in_domain", "url", 0.6, f"Brand '{brand}' appears in a domain it does not own", brand=brand, domain=rd)
            break
        core = rd.split(".")[0]
        if len(brand) > 3 and core != brand and SequenceMatcher(None, _norm_leet(core), brand).ratio() >= 0.85:
            _ev(ev, "url.typosquat", "url", 0.6, f"Domain closely imitates '{brand}'", brand=brand, domain=rd)
            break
    return ev

def html_evidence(url, page):
    ev = []
    rd = registered_domain(host_of(url))
    for f in page.forms:
        act = f["action"]
        if f["password"]:
            _ev(ev, "html.password_form", "html", 0.1, "Page requests a password")
        if act.lower().startswith("javascript:"):
            _ev(ev, "html.js_form_action", "html", 0.2, "Form submits via script rather than a visible destination")
        elif act and not act.startswith(("#", "/")) and "://" in act:
            ard = registered_domain(host_of(act))
            if ard and ard != rd and f["password"]:
                _ev(ev, "html.cross_domain_form", "html", 0.5, "Credential form submits to a different domain", action_domain=ard)
            if act.lower().startswith("http://") and f["password"]:
                _ev(ev, "html.insecure_form", "html", 0.4, "Credential form submits over plain HTTP")
        if f["hidden"]:
            _ev(ev, "html.hidden_form", "html", 0.3, "Form is hidden from the user")
    n_mis, pairs = 0, []
    for l in page.links:
        href, txt = l["href"], l["text"].strip()
        m = URL_LIKE.search(txt)
        if m and href.lower().startswith("http"):
            shown = registered_domain(host_of(m.group(0) if "://" in m.group(0) else "http://" + m.group(0)))
            actual = registered_domain(host_of(href))
            if shown and actual and shown != actual:
                n_mis += 1
                if len(pairs) < 3:
                    pairs.append([shown, actual])
    if n_mis:
        _ev(ev, "html.mismatched_link", "html", min(0.45 + 0.1 * (n_mis - 1), 0.7),
            "Displayed link text differs from the real destination", count=n_mis, pairs=pairs)
    # Links inside the page that go through a URL shortener hide where they lead
    short = sorted({registered_domain(host_of(l["href"])) for l in page.links
                    if l["href"].lower().startswith("http") and registered_domain(host_of(l["href"])) in SHORTENERS})
    if short:
        n_short = sum(1 for l in page.links if l["href"].lower().startswith("http")
                      and registered_domain(host_of(l["href"])) in SHORTENERS)
        _ev(ev, "html.shortened_link", "html", min(0.15 + 0.05 * (n_short - 1), 0.3),
            "Links go through a URL shortener, hiding the real destination", count=n_short, domains=short)
    if sum(1 for l in page.links if l["hidden"]) >= 3:
        _ev(ev, "html.hidden_links", "html", 0.2, "Several links are hidden from view")
    nulls = sum(1 for l in page.links if l["href"] in ("", "#") or l["href"].lower().startswith("javascript:"))
    if len(page.links) >= 3 and nulls / len(page.links) >= 0.5:
        _ev(ev, "html.null_links", "html", 0.15, "Most links go nowhere (cloned page pattern)")
    if page.meta_refresh and "url=" in page.meta_refresh.lower():
        _ev(ev, "html.meta_refresh", "html", 0.2, "Automatic redirect via meta refresh")
    if re.search(r"(window|document|top)\.location(\.href)?\s*=|location\.replace\(", " ".join(page.scripts)):
        _ev(ev, "html.js_redirect", "html", 0.2, "Script-based redirect")
    # Hidden cross-domain iframes: reported once for the whole page. Ad, analytics
    # and chat widgets use them on most large legitimate sites, so they only count
    # strongly when the page also asks for a password.
    hidden_frames = sorted({registered_domain(host_of(fr["src"])) for fr in page.iframes
                            if fr["hidden"] and fr["src"].startswith("http")} - {"", rd})
    if hidden_frames:
        if any(t == "password" for t, _ in page.inputs):
            _ev(ev, "html.hidden_iframe", "html", 0.3, "Invisible cross-domain iframe on a page that asks for a password",
                domains=hidden_frames)
        else:
            _ev(ev, "html.hidden_iframe", "html", 0.05, "Invisible cross-domain iframe (common for ads/analytics)",
                domains=hidden_frames)
    return ev

def text_evidence(url, page, text):
    ev = []
    low = text.lower()
    rd = registered_domain(host_of(url))
    creds = [t for t in CRED_TERMS if t in low]
    if creds:
        _ev(ev, "text.credential_request", "text", min(0.05 + 0.03 * len(creds), 0.15), "Text solicits credentials or sensitive data", terms=creds)
    urg = [t for t in URGENCY_TERMS if t in low]
    if urg:
        _ev(ev, "text.urgency", "text", min(0.1 + 0.1 * len(urg), 0.4), "Urgent or threatening language", terms=urg)
    # brand claim vs. domain: only when a password is requested and the page never
    # points to the brand's own domain (keeps SSO / "Sign in with X" pages safe).
    has_pw = any(t == "password" for t, _ in page.inputs)
    target_domains = {registered_domain(host_of(l["href"])) for l in page.links if l["href"].startswith("http")}
    target_domains |= {registered_domain(host_of(f["action"])) for f in page.forms if "://" in f["action"]}
    title = page.title.lower()
    for brand, info in BRANDS.items():
        if rd in info["domains"]:
            continue
        mentions = len(re.findall(r"\b" + re.escape(brand) + r"\b", low))
        if (brand in title or mentions >= 2) and has_pw and not (target_domains & info["domains"]):
            _ev(ev, "text.brand_claim_mismatch", "text", 0.5, f"Page claims to be '{brand}' but is hosted on '{rd}'", brand=brand, domain=rd)
            break
    return ev

def brand_owner(rd):
    return next((b for b, info in BRANDS.items() if rd in info["domains"]), None)

def claimed_brand(page, text):
    """Brand the page presents itself as, only for pages that ask for a password
    (a 'Sign in with Microsoft' link on an SSO page is not a claim)."""
    if not any(t == "password" for t, _ in page.inputs):
        return None, 0.0
    low, title = text.lower(), page.title.lower()
    for brand in BRANDS:
        in_title = brand in title
        mentions = len(re.findall(r"\b" + re.escape(brand) + r"\b", low))
        if in_title or mentions >= 2:
            return brand, (0.8 if in_title else 0.6)
    return None, 0.0

def combine(weights):
    """Noisy-OR: independent weak signals accumulate, no single one is required."""
    p = 1.0
    for w in weights:
        p *= (1 - w)
    return 1 - p

def resolve_target(url, page, intended_url=None):
    """Which URL the URL/domain rules run on, and why."""
    if intended_url:
        return intended_url, "manifest"
    if page is not None and page.intended_url and is_local(url):
        return page.intended_url, "fixture_meta"
    if is_local(url):
        return url, "local_unscored"
    return url, "page"

def analyze(url, html=None, ocr_text=None, safe_below=0.3, suspicious_at=0.5, intended_url=None):
    page = parse_html(html) if html else None
    target, source = resolve_target(url, page, intended_url)
    missing, ev = [], []
    if source == "local_unscored":
        missing.append("url")  # localhost itself is never URL evidence
    else:
        ev += url_evidence(target)
    conf = 1.0
    text = ocr_text or ""
    claim, claim_conf = None, 0.0
    if html:
        text = (visible_text(html) + " " + text).strip()
        ev += html_evidence(target, page)
        ev += text_evidence(target, page, text)
        claim, claim_conf = claimed_brand(page, text)
        if page.intended_url and not is_local(url):
            _ev(ev, "html.fixture_tag_on_public_page", "html", 0.3,
                "Page carries a test-fixture URL tag but is served from a public host", declared=page.intended_url)
        if len(text.split()) < 30:
            missing.append("limited_visible_text")
            conf -= 0.2
            if page.forms or page.inputs:
                _ev(ev, "text.limited_with_form", "text", 0.1, "Very little visible text but page contains inputs")
    else:
        missing += ["html", "visible_text"]
        conf = 0.4
    if not ocr_text:
        missing.append("ocr_text")
    score = round(combine([e["weight"] for e in ev]), 3)
    hint = "suspicious" if score >= suspicious_at else ("safe" if score < safe_below else "uncertain")
    ev.sort(key=lambda e: -e["weight"])
    rd = registered_domain(host_of(target)) if source != "local_unscored" else None
    return {"branch": "url_html_text", "risk_score": score, "confidence": round(max(conf, 0.1), 2),
            "label_hint": hint, "missing": missing, "evidence": ev,
            "analyzed_url": target, "url_source": source,
            "fixture": ({"page_id": page.fixture_id, "claimed_brand": page.fixture_brand}
                        if page is not None and page.fixture_id else None),
            "claims": {"brand": claim, "brand_conf": claim_conf, "domain": rd,
                       "domain_owner_brand": brand_owner(rd) if rd else None}}
