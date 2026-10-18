"""Build bundle/ from the demo scenarios.

visual / dom / text outputs are still SYNTHETIC (copied from demo.py).
The url branch is REAL: each page gets a raw URL in <page>.url.txt that
url_branch.py analyses, replacing the hand-typed URL output.

    python make_sample_bundle.py [folder]     # default: bundle/
"""
import json
import os
import sys

from demo import SCENARIOS

URLS = {
    "phishing_paypal": "https://www.paypa1-login.xyz/signin?session=8f2a",
    "legit_sso_microsoft": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    "thin_input": "https://example-shop.top/",
    "unseen_brand_login": "https://smallbank-example.ca/login",
}


def build(folder: str) -> str:
    os.makedirs(folder, exist_ok=True)
    for name, request in SCENARIOS:
        for b in request["branches"]:
            if b["branch"] == "url":
                with open(os.path.join(folder, f"{name}.url.txt"), "w", encoding="utf-8") as f:
                    f.write(URLS[name] + "\n")
            else:
                with open(os.path.join(folder, f"{name}.{b['branch']}.json"), "w", encoding="utf-8") as f:
                    json.dump(b, f, indent=2)
    return folder


if __name__ == "__main__":
    print("wrote", build(sys.argv[1] if len(sys.argv) > 1 else "bundle"))
