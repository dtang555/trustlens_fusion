"""Capture REAL Branch B output as fixtures.   python capture_branch_b_fixture.py

Needs Student B's url_html_text_branch.py and test_branch.py in this folder (the same files
used for the unit tests). Overwrites branch_b_fixtures/*.json with analyze() output for the
phishing-style and legitimate pages defined in test_branch.py.
"""
import json
import os

from test_branch import LEGIT, PHISH
from url_html_text_branch import analyze

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = {
    "phishing_paypal_branch_b.json": ("http://paypal-secure-login.evil-site.xyz/login", PHISH, "test_branch.PHISH"),
    "legit_paypal_branch_b.json": ("https://www.paypal.com/signin", LEGIT, "test_branch.LEGIT"),
}

if __name__ == "__main__":
    os.makedirs(os.path.join(HERE, "branch_b_fixtures"), exist_ok=True)
    for name, (url, html, source) in CASES.items():
        out = {"_source": f"url_html_text_branch.analyze(url, html) on {source}", "url": url, "result": analyze(url, html)}
        with open(os.path.join(HERE, "branch_b_fixtures", name), "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        print(f"{name}: risk={out['result']['risk_score']} hint={out['result']['label_hint']} "
              f"rules={len(out['result']['evidence'])}")
