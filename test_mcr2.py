"""MCR II tests (Stacy Nwankwo): local fixtures + intended URL, shared-format adapter,
and Week 6-7 cases (dynamic forms, hidden elements, URL obfuscation)."""
import unittest
from url_html_text_branch import analyze, is_local
from shared_adapter import to_shared
from test_branch import LEGIT, PHISH, SSO

PAD_TEXT = "<p>" + "Account services information and support content. " * 8 + "</p>"
PHISH_URL = "http://paypal-secure-login.evil-site.xyz/login"
LEGIT_URL = "https://www.paypal.com/signin"

def tag(url):
    return f'<meta name="trustlens:intended-url" content="{url}">'

def ids(r): return {e["id"] for e in r["evidence"]}

def by_branch(shared): return {b["branch"]: b for b in shared}

class IntendedUrl(unittest.TestCase):
    def test_fixture_on_localhost_scores_like_intended_url(self):
        served = analyze("http://localhost:8000/unit-phish/page.html", tag(PHISH_URL) + PHISH)
        direct = analyze(PHISH_URL, PHISH)
        self.assertEqual(served["url_source"], "fixture_meta")
        self.assertEqual(served["analyzed_url"], PHISH_URL)
        self.assertEqual(served["risk_score"], direct["risk_score"])
        self.assertEqual(ids(served), ids(direct))
        self.assertIn("url.brand_in_domain", ids(served))

    def test_legit_fixture_on_localhost_scores_like_intended_url(self):
        served = analyze("http://127.0.0.1:8000/unit-legit/page.html", tag(LEGIT_URL) + LEGIT)
        self.assertEqual(served["risk_score"], analyze(LEGIT_URL, LEGIT)["risk_score"])
        self.assertNotIn("url.no_https", ids(served))

    def test_localhost_without_tag_is_never_url_evidence(self):
        r = analyze("http://localhost:8000/legit.html", LEGIT)
        self.assertEqual(r["url_source"], "local_unscored")
        self.assertIn("url", r["missing"])
        self.assertFalse([i for i in ids(r) if i.startswith("url.")])

    def test_manifest_intended_url_wins(self):
        r = analyze("http://localhost:8000/x.html", LEGIT, intended_url=LEGIT_URL)
        self.assertEqual((r["url_source"], r["analyzed_url"]), ("manifest", LEGIT_URL))

    def test_tag_on_public_host_is_ignored_and_flagged(self):
        # a real phishing page cannot use the fixture tag to pose as paypal.com
        r = analyze(PHISH_URL, tag(LEGIT_URL) + PHISH)
        self.assertEqual(r["url_source"], "page")
        self.assertEqual(r["analyzed_url"], PHISH_URL)
        self.assertIn("html.fixture_tag_on_public_page", ids(r))

    def test_local_hosts(self):
        for u in ("http://localhost/a", "http://127.0.0.1:8000/", "file:///tmp/p.html", "http://app.localhost/"):
            self.assertTrue(is_local(u), u)
        for u in ("https://www.paypal.com/", "http://203.0.113.9/", "http://localhost.evil.com/"):
            self.assertFalse(is_local(u), u)

def daniel_page(pid, url, brand, body):
    """A fixture in Daniel's corpus format (data attributes on <html>)."""
    return (f'<!DOCTYPE html><html lang="en" data-page-id="{pid}" data-intended-url="{url}" '
            f'data-claimed-brand="{brand}"><head><title>Test Fixture</title></head><body>{body}</body></html>')

class DanielFixtureFormat(unittest.TestCase):
    def test_data_attributes_give_intended_url_and_id(self):
        h = daniel_page("P02", PHISH_URL, "PayPal", PHISH)
        served = analyze("http://localhost:8000/test_pages/P02.html", h)
        self.assertEqual((served["url_source"], served["analyzed_url"]), ("fixture_meta", PHISH_URL))
        self.assertEqual(served["fixture"], {"page_id": "P02", "claimed_brand": "PayPal"})
        self.assertIn("url.brand_in_domain", ids(served))

    def test_fixture_id_flows_into_shared_format(self):
        h = daniel_page("P01", LEGIT_URL, "PayPal", LEGIT)
        for b in to_shared(analyze("http://127.0.0.1:8000/test_pages/P01.html", h), request_id="r1"):
            self.assertEqual((b["page_id"], b["source"]), ("P01", "branch_b"))

    def test_claimed_brand_label_is_not_evidence(self):
        # data-claimed-brand is a test label, so it must not create a brand claim by itself
        h = daniel_page("P09", "https://shop.example/", "PayPal", PAD_TEXT + "<form><input type=password></form>")
        r = analyze("http://localhost:8000/test_pages/P09.html", h)
        self.assertIsNone(r["claims"]["brand"])
        self.assertNotIn("text.brand_claim_mismatch", ids(r))

    def test_data_attributes_on_public_host_are_ignored_and_flagged(self):
        r = analyze(PHISH_URL, daniel_page("P02", LEGIT_URL, "PayPal", PHISH))
        self.assertEqual((r["url_source"], r["analyzed_url"]), ("page", PHISH_URL))
        self.assertIn("html.fixture_tag_on_public_page", ids(r))

class SharedAdapter(unittest.TestCase):
    def test_phish_maps_to_fusion_types(self):
        s = by_branch(to_shared(analyze(PHISH_URL, PHISH), request_id="tab1-nav1", page_id="unit-phish"))
        self.assertEqual(set(s), {"url", "dom", "text"})
        for b in s.values():
            self.assertEqual((b["schema_version"], b["request_id"], b["page_id"], b["status"]),
                             ("0.1.0", "tab1-nav1", "unit-phish", "ok"))
            self.assertEqual(b["source"], "branch_b")
            self.assertTrue(0.05 <= b["p_phish"] <= 0.99)
            for e in b["evidence"]:
                self.assertTrue(e["verified"]); self.assertIn("kind", e["locator"])
        dom = {e["type"]: e for e in s["dom"]["evidence"]}
        self.assertEqual(dom["form_action_mismatch"]["fields"],
                         {"page_domain": "evil-site.xyz", "action_domain": "other-site.xyz"})
        self.assertEqual(dom["misleading_link_destination"]["fields"]["displayed_domain"], "paypal.com")
        self.assertEqual(dom["misleading_link_destination"]["fields"]["actual_domain"], "evil-site.xyz")
        self.assertIn("credential_solicitation", dom)
        self.assertEqual(s["url"]["claims"], {"domain": "evil-site.xyz", "domain_owner_brand": None})
        self.assertEqual(s["text"]["claims"]["brand"], "paypal")
        # evidence fusion has no type for stays as features, not dropped
        self.assertIn("url.suspicious_tld", s["url"]["features"])

    def test_legit_claims_match_owner(self):
        s = by_branch(to_shared(analyze(LEGIT_URL, LEGIT)))
        self.assertEqual(s["url"]["claims"]["domain_owner_brand"], "paypal")
        self.assertEqual(s["dom"]["claims"]["brand"], "paypal")
        self.assertFalse([e for b in s.values() for e in b["evidence"] if e["type"] == "brand_domain_mismatch"])

    def test_sso_page_claims_no_brand(self):
        s = by_branch(to_shared(analyze("https://portal.acme.com/", SSO)))
        self.assertEqual(s["text"]["claims"], {})
        # "Sign in" text without a password field is not a credential request
        self.assertFalse([e for e in s["text"]["evidence"] if e["type"] == "credential_solicitation"])

    def test_missing_branches(self):
        s = by_branch(to_shared(analyze("http://localhost:8000/x.html", None)))
        self.assertEqual({k: v["status"] for k, v in s.items()}, {"url": "missing", "dom": "missing", "text": "missing"})
        self.assertIsNone(s["url"]["p_phish"])

class Week67Cases(unittest.TestCase):
    def test_dynamic_form_needs_rendered_html(self):
        # raw HTML: the password field is only created by script, so static parsing can't see it
        raw = "<p>Sign in to continue.</p><div id=f></div><script>f.innerHTML='<input type=password>'</script>"
        self.assertNotIn("html.password_form", ids(analyze("https://a.com/", raw)))
        # the extension sends the rendered DOM (document.documentElement.outerHTML), where it exists
        rendered = "<p>Sign in to continue.</p><div id=f><form action='http://x.top/p'><input type=password></form></div>"
        self.assertTrue({"html.password_form", "html.cross_domain_form", "html.insecure_form"} <= ids(analyze("https://a.com/", rendered)))

    def test_hidden_links(self):
        h = "".join(f"<a href='http://e{i}.com' style='display:none'>x</a>" for i in range(3))
        self.assertIn("html.hidden_links", ids(analyze("https://a.com/", h)))

    def test_url_obfuscation(self):
        u = "https://secure-login.example.com/%61%63%63%6f%75%6e%74/" + "a" * 90
        self.assertTrue({"url.encoded_chars", "url.long"} <= ids(analyze(u)))

class ShortenedAndLimitedText(unittest.TestCase):
    def test_shortened_links_inside_page(self):
        h = PAD_TEXT + "<a href='https://bit.ly/3xYz'>Verify here</a><a href='https://tinyurl.com/abc'>Help</a>"
        e = [x for x in analyze("https://a.com/", h)["evidence"] if x["id"] == "html.shortened_link"]
        self.assertEqual(len(e), 1)
        self.assertEqual(e[0]["detail"], {"count": 2, "domains": ["bit.ly", "tinyurl.com"]})
        self.assertEqual(e[0]["weight"], 0.2)

    def test_normal_links_not_shortened(self):
        h = PAD_TEXT + "<a href='https://www.paypal.com/help'>Help</a><a href='/about'>About</a>"
        self.assertNotIn("html.shortened_link", ids(analyze("https://a.com/", h)))

    def test_shortened_link_alone_stays_safe(self):
        # one shortened link on a normal page is evidence, not a verdict
        r = analyze("https://blog.example.org/post", PAD_TEXT + "<a href='https://bit.ly/x'>slides</a>")
        self.assertEqual(r["label_hint"], "safe")

    def test_logo_and_form_only(self):
        h = "<img src='logo.png' alt=''><form action='/s'><input type='email'><input type='password'><button>Next</button></form>"
        r = analyze("https://a.com/", h)
        self.assertIn("limited_visible_text", r["missing"])
        self.assertEqual(r["confidence"], 0.8)
        self.assertIn("text.limited_with_form", ids(r))

    def test_mostly_hidden_text_counts_as_limited(self):
        hidden = "<div style='display:none'>" + "Lots of legitimate looking filler text here. " * 20 + "</div>"
        r = analyze("https://a.com/", "<p>Sign in</p>" + hidden + "<form><input type='password'></form>")
        self.assertIn("limited_visible_text", r["missing"])
        self.assertIn("text.limited_with_form", ids(r))

    def test_little_text_without_form_has_no_form_evidence(self):
        r = analyze("https://a.com/", "<h1>Coming soon</h1>")
        self.assertIn("limited_visible_text", r["missing"])
        self.assertNotIn("text.limited_with_form", ids(r))

    def test_enough_text_not_limited(self):
        r = analyze("https://a.com/", PAD_TEXT + "<form><input type='password'></form>")
        self.assertNotIn("limited_visible_text", r["missing"])
        self.assertEqual(r["confidence"], 1.0)

if __name__ == "__main__":
    unittest.main()
