"""Build the small controlled evaluation corpus from REAL Branch B output.

    python build_corpus.py [folder containing url_html_text_branch.py and test_branch.py]

Pages:
  * 9 samples copied from Student B's evaluate.py (added_by: student_b)
  * 1 little-text legitimate login and 4 unseen-brand pages added by Student C (brand not in Branch B's or the visual reference
    set), 2 phishing-style and 2 legitimate, to exercise the unseen-brand path.
Each page records the ground-truth label, the brand the page visibly shows (what a logo
detector would see), and Branch B's real analyze() output plus its processing time.
Writes corpus/branch_b_outputs.json. Re-run whenever Branch B changes. Needs only Branch B's
module, not the browser: pages are inline HTML, nothing is fetched.
"""
import json
import os
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else HERE)

from test_branch import LEGIT, PHISH, SSO  # noqa: E402  (Student B's fixtures)
from url_html_text_branch import analyze  # noqa: E402  (Student B's module)

PAD = "<p>" + "Account services information and support content. " * 8 + "</p>"
PW = "<form action='{a}'><input type='password'></form>"

# (name, url, html, label 1=phishing-style, group, shown_brand, unseen_brand, added_by)
PAGES = [
    ("paypal legit", "https://www.paypal.com/signin", LEGIT, 0, "legit", "paypal", False, "student_b"),
    ("acme sso", "https://portal.acme.com/", SSO, 0, "legit", None, False, "student_b"),
    ("plain blog", "https://blog.example.org/post", "<h1>Hi</h1>" + PAD, 0, "legit", None, False, "student_b"),
    ("bank legit login", "https://www.rbcroyalbank.com/login",
     "<title>RBC Sign in</title>" + PAD + PW.format(a="/auth"), 0, "legit", "rbc", False, "student_b"),
    ("phish classic", "http://paypal-secure-login.evil-site.xyz/login", PHISH, 1, "phish", "paypal", False, "student_b"),
    ("phish ip host", "http://203.0.113.9/rbc/login",
     "<title>RBC Sign in</title>" + PAD + PW.format(a="post.php"), 1, "phish", "rbc", False, "student_b"),
    ("phish typosquat", "https://paypa1.com/signin",
     "<title>PayPal</title>" + PAD + PW.format(a="/x"), 1, "phish", "paypal", False, "student_b"),
    ("phish shortened + hidden form", "https://bit.ly/3xYz",
     "<form style='display:none' action='http://a.top/c'><input type='password'></form>", 1, "phish", None, False, "student_b"),
    ("evasive: clean domain, no brand text", "https://secure-docs.example.net/view",
     PAD + PW.format(a="/s"), 1, "evasive", None, False, "student_b"),
    # --- added by Student C: a legitimate login with very little text (Branch B confidence drops to 0.8)
    ("legit short login (little text)", "https://www.td.com/login",
     "<title>TD Sign in</title>" + PW.format(a="/auth"), 0, "legit", "td", False, "student_c"),
    # --- added by Student C: brands outside every reference set
    ("unseen-brand phish A", "https://wealthsimple-secure.verify-account.top/login",
     "<title>Wealthsimple Sign in</title>" + PAD + PW.format(a="http://collect.other-site.xyz/p"), 1, "unseen_brand",
     "wealthsimple", True, "student_c"),
    ("unseen-brand phish B", "https://questrade-login.example-portal.net/signin",
     "<title>Questrade Login</title>" + PAD + PW.format(a="/submit"), 1, "unseen_brand", "questrade", True, "student_c"),
    ("unseen-brand legit A", "https://www.wealthsimple.com/login",
     "<title>Wealthsimple Sign in</title>" + PAD + PW.format(a="/auth"), 0, "unseen_brand", "wealthsimple", True, "student_c"),
    ("unseen-brand legit B", "https://www.questrade.com/login",
     "<title>Questrade Login</title>" + PAD + PW.format(a="/auth"), 0, "unseen_brand", "questrade", True, "student_c"),
]

VISUAL_REFERENCE = ["paypal", "microsoft", "google", "apple", "amazon", "netflix", "rbc", "td", "facebook"]


def timed(url, html, runs=7):
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        result = analyze(url, html)
        times.append((time.perf_counter() - t0) * 1000)
    return result, statistics.median(times)


if __name__ == "__main__":
    pages = []
    for name, url, html, label, group, shown, unseen, who in PAGES:
        result, ms = timed(url, html)
        pages.append({"name": name, "url": url, "label": label, "group": group, "shown_brand": shown,
                      "unseen_brand": unseen, "added_by": who, "branch_b_ms": round(ms, 3), "branch_b": result})
    out = {"meta": {"source": "Student B url_html_text_branch.analyze() on inline HTML pages",
                    "n": len(pages), "n_phishing": sum(p["label"] for p in pages),
                    "note": "Small controlled corpus for threshold-sensitivity and ablation work. Not large enough "
                            "to support a calibration claim."},
           "visual_reference": VISUAL_REFERENCE, "pages": pages}
    os.makedirs(os.path.join(HERE, "corpus"), exist_ok=True)
    with open(os.path.join(HERE, "corpus", "branch_b_outputs.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    print(f"{len(pages)} pages ({out['meta']['n_phishing']} phishing-style)")
    for p in pages:
        r = p["branch_b"]
        print(f"  {p['label']} {p['group']:<12} {r['risk_score']:.3f} conf={r['confidence']} {r['label_hint']:<10} {p['name']}")
