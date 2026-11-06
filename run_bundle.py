"""File-based integration runner (offline test bundle).

Folder layout (one set of files per page id):

    <page>.visual.json   BranchOutput from Student A
    <page>.url.json      BranchOutput from the URL branch   -- or --
    <page>.url.txt       raw URL string -> analysed by url_branch.py (stand-in)
    <page>.dom.json      BranchOutput from Student B
    <page>.text.json     BranchOutput from Student B

Missing files are simply absent branches. Unreadable / mismatched files become
status="error" branches (fault injection), so fusion degrades instead of crashing.
Writes <folder>/out/<page>.request.json and <page>.response.json.

    python run_bundle.py bundle/
    python run_bundle.py bundle/ --page phishing_paypal
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

import url_branch
from fusion import SCHEMA_VERSION, SchemaError, fuse

PATTERN = re.compile(r"^(?P<page>.+)\.(?P<branch>visual|url|dom|text)\.(?P<ext>json|txt)$")


def discover(folder: str) -> dict[str, dict[str, str]]:
    pages: dict[str, dict[str, str]] = {}
    for name in sorted(os.listdir(folder)):
        m = PATTERN.match(name)
        if not m:
            continue
        files = pages.setdefault(m["page"], {})
        if m["branch"] in files and files[m["branch"]].endswith(".json"):
            continue  # a .json output wins over a .txt stand-in
        if m["branch"] != "url" and m["ext"] == "txt":
            continue  # raw-text input only makes sense for the URL branch
        files[m["branch"]] = os.path.join(folder, name)
    return pages


def _error_branch(branch: str, flag: str) -> dict:
    return {"branch": branch, "status": "error", "p_phish": None, "reliability": None,
            "missing_flags": [flag], "model_version": "n/a", "latency_ms": 0}


def load_branch(branch: str, path: str) -> dict:
    try:
        if path.endswith(".txt"):
            with open(path, encoding="utf-8") as f:
                return url_branch.analyze(f.read())
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, UnicodeDecodeError):
        return _error_branch(branch, "file.unreadable")
    except json.JSONDecodeError:
        return _error_branch(branch, "file.invalid_json")
    if not isinstance(data, dict) or data.get("branch") != branch:
        return _error_branch(branch, "file.branch_mismatch")
    return data


def run_page(page: str, files: dict[str, str]) -> tuple[dict, dict]:
    request = {"schema_version": SCHEMA_VERSION, "request_id": page,
               "branches": [load_branch(b, p) for b, p in files.items()]}
    try:
        response = fuse(request)
    except SchemaError as exc:  # same fallback D's middleware must use: never default to allow
        response = {"schema_version": SCHEMA_VERSION, "request_id": page, "decision": "uncertain",
                    "risk_score": None, "explanations": [], "branch_summary": [],
                    "uncertainty": {"reasons": ["fusion_unavailable"], "coverage": 0.0, "disagreement": 0.0},
                    "error": str(exc)}
    return request, response


def run_folder(folder: str, only: str | None = None, write: bool = True) -> dict[str, tuple[dict, dict]]:
    results = {}
    out_dir = os.path.join(folder, "out")
    if write:
        os.makedirs(out_dir, exist_ok=True)
    for page, files in discover(folder).items():
        if only and page != only:
            continue
        request, response = run_page(page, files)
        results[page] = (request, response)
        if write:
            for suffix, obj in (("request", request), ("response", response)):
                with open(os.path.join(out_dir, f"{page}.{suffix}.json"), "w", encoding="utf-8") as f:
                    json.dump(obj, f, indent=2)
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder")
    ap.add_argument("--page", help="run a single page id")
    args = ap.parse_args()
    if not os.path.isdir(args.folder):
        print(f"not a folder: {args.folder}")
        return 2
    results = run_folder(args.folder, args.page)
    if not results:
        print("no branch files found (expected <page>.<visual|url|dom|text>.json / .url.txt)")
        return 1
    for page, (_, r) in results.items():
        p = r["risk_score"]
        print(f"\n=== {page}: {r['decision'].upper()}  (risk_score={p}) ===")
        if r["uncertainty"]["reasons"]:
            print("  reasons:", ", ".join(r["uncertainty"]["reasons"]))
        print("  branches:", ", ".join(f"{b['branch']}={b['status']}" for b in r["branch_summary"]) or "none")
        for x in r["explanations"]:
            print(f"  - [{x['contribution']:+.2f}] {x['text']}")
    print(f"\nWrote request/response JSON to {os.path.join(args.folder, 'out')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
