import unittest
from url_html_text_branch import analyze, visible_text, registered_domain

LEGIT = """<html><head><title>Sign in to PayPal</title></head><body><h1>Welcome back</h1>
<p>Log in to your PayPal account to send money, pay bills and manage your balance securely
with our trusted payments platform used by millions of customers around the world every day.
Enter your email and password below to continue to your dashboard and view recent activity.</p>
<form action="/signin" method="post"><input type="email"><input type="password"></form>
<a href="https://www.paypal.com/help">Help</a></body></html>"""
PHISH = """<html><head><title>PayPal - Verify</title></head><body>
<p>URGENT: your PayPal account has been suspended. Verify now within 24 hours or it will be closed.
Enter your password and card number to confirm your identity.</p>
<form action="http://collect.other-site.xyz/p.php"><input type="text"><input type="password"></form>
<a href="http://evil-site.xyz/x">www.paypal.com/security</a></body></html>"""
SSO = """<html><head><title>Acme Intranet</title></head><body><p>Welcome to the Acme employee portal.
Use your Microsoft work account to continue. Microsoft single sign-on keeps your data safe. Contact IT for help
if you cannot access the portal or need to reset multi-factor authentication for your device today.</p>
<a href="https://login.microsoftonline.com/acme">Sign in with Microsoft</a></body></html>"""

def ids(r): return {e["id"] for e in r["evidence"]}

class T(unittest.TestCase):
    def test_legit_login_is_safe(self):
        r = analyze("https://www.paypal.com/signin", LEGIT)
        self.assertLess(r["risk_score"], 0.3); self.assertEqual(r["label_hint"], "safe")
    def test_phish_is_suspicious(self):
        r = analyze("http://paypal-secure-login.evil-site.xyz/login", PHISH)
        self.assertGreaterEqual(r["risk_score"], 0.9)
        self.assertTrue({"html.cross_domain_form", "html.mismatched_link", "text.brand_claim_mismatch",
                         "url.brand_in_domain", "text.urgency"} <= ids(r))
    def test_sso_page_not_flagged_as_brand_claim(self):
        r = analyze("https://portal.acme.com/", SSO)
        self.assertNotIn("text.brand_claim_mismatch", ids(r)); self.assertEqual(r["label_hint"], "safe")
    def test_ip_at_shortener(self):
        self.assertIn("url.ip_host", ids(analyze("http://192.168.1.5/login")))
        self.assertIn("url.at_symbol", ids(analyze("https://paypal.com@evil.com/")))
        self.assertIn("url.shortener", ids(analyze("https://bit.ly/3abc")))
    def test_typosquat_and_subdomain_brand(self):
        self.assertIn("url.typosquat", ids(analyze("https://paypa1.com/")))
        self.assertIn("url.brand_in_domain", ids(analyze("https://paypal.com.evil.net/")))
        self.assertEqual(analyze("https://www.paypal.com/")["evidence"] and
                         [e for e in analyze("https://www.paypal.com/")["evidence"] if e["id"].startswith("url.brand")], [])
    def test_idn_reported_as_safe_ascii(self):
        r = analyze("https://pаypal.com/")  # Cyrillic 'а'
        e = [x for x in r["evidence"] if x["id"] == "url.idn_host"][0]
        self.assertTrue(e["detail"]["ascii"].isascii())
    def test_embedded_redirect(self):
        self.assertIn("url.embedded_redirect", ids(analyze("https://x.com/r?u=http%3A%2F%2Fevil.com")))
    def test_hidden_content_not_visible(self):
        h = "<p>Hello</p><div style='display:none'>SECRET</div><script>var x=1</script><span hidden>no</span>"
        self.assertEqual(visible_text(h), "Hello")
    def test_hidden_form_and_iframe(self):
        h = "<form style='display:none' action='/a'><input type='password'></form><iframe src='http://evil.com/x' width='0'></iframe>"
        r = analyze("https://a.com/", h); self.assertTrue({"html.hidden_form", "html.hidden_iframe"} <= ids(r))
    def test_tracking_iframes_without_password_stay_weak(self):
        # adidas.ca false alarm: ad/analytics iframes on a shop page with no password field
        frames = ("<iframe src='https://insight.adsrvr.org/track' style='display:none'></iframe>"
                  "<iframe src='https://1.fls.doubleclick.net/a' width='0'></iframe>")
        shop = "<p>" + "New arrivals, shoes and clothing for every sport. Sign in for offers. " * 6 + "</p>"
        r = analyze("https://www.shop.ca/en/lifestyle", shop + frames)
        e = [x for x in r["evidence"] if x["id"] == "html.hidden_iframe"]
        self.assertEqual(len(e), 1); self.assertEqual(e[0]["detail"]["domains"], ["adsrvr.org", "doubleclick.net"])
        self.assertEqual(r["label_hint"], "safe")
        login = analyze("https://www.shop.ca/login", shop + frames + "<form><input type='password'></form>")
        self.assertEqual([x["weight"] for x in login["evidence"] if x["id"] == "html.hidden_iframe"], [0.3])
    def test_url_only_lowers_confidence(self):
        r = analyze("https://example.com/"); self.assertIn("html", r["missing"]); self.assertLessEqual(r["confidence"], 0.4)
    def test_limited_text_flagged(self):
        r = analyze("https://a.com/", "<form><input type='password'></form>")
        self.assertIn("limited_visible_text", r["missing"])
    def test_registered_domain(self):
        self.assertEqual(registered_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(registered_domain("www.paypal.com"), "paypal.com")
    def test_redirects(self):
        r = analyze("https://a.com/", "<meta http-equiv='refresh' content='0;url=http://b.com'><script>window.location='http://b.com'</script>")
        self.assertTrue({"html.meta_refresh", "html.js_redirect"} <= ids(r))
if __name__ == "__main__": unittest.main()
