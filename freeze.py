"""Freeze (or verify) one corpus, one configuration, and one code version for evaluation.

    python freeze.py            write freeze/frozen_config.json and freeze/MANIFEST.json
    python freeze.py --check    verify the working tree still matches the freeze (exit 1 on any drift)

What is frozen:
  * corpus  - corpus/branch_b_outputs.json (a snapshot of Branch B output; Branch B itself is not needed to re-run)
  * config  - fusion.DEFAULT (every Params field), SCHEMA_VERSION, brand_registry.json
  * code    - SHA-256 of every tracked .py at the repo root and the Branch B fixtures, plus the git tag that names them
  * results - SHA-256 of eval_results.json with the timing section ("cost") removed, since timing is not reproducible

Hashes are taken over LF-normalised bytes so a CRLF checkout on Windows hashes the same as an LF one.
"""
from __future__ import annotations

import dataclasses
import glob
import hashlib
import json
import os
import platform
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FREEZE_DIR = os.path.join(HERE, "freeze")
MANIFEST = os.path.join(FREEZE_DIR, "MANIFEST.json")
CONFIG = os.path.join(FREEZE_DIR, "frozen_config.json")
FREEZE_ID = "eval-freeze-v1"

CORPUS = "corpus/branch_b_outputs.json"
CONFIG_FILES = ["brand_registry.json"]
RESULTS = "eval_results.json"
NONDETERMINISTIC_RESULT_KEYS = ("cost",)  # wall-clock timings


def _rel(path: str) -> str:
    return os.path.relpath(path, HERE).replace(os.sep, "/")


def sha256_file(rel: str) -> str:
    with open(os.path.join(HERE, rel), "rb") as f:
        return hashlib.sha256(f.read().replace(b"\r\n", b"\n")).hexdigest()


def sha256_obj(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def code_files() -> list[str]:
    files = glob.glob(os.path.join(HERE, "*.py")) + glob.glob(os.path.join(HERE, "branch_b_fixtures", "*.json"))
    return sorted(_rel(p) for p in files)


def current_config() -> dict:
    import fusion
    return {"schema_version": fusion.SCHEMA_VERSION, "params": dataclasses.asdict(fusion.DEFAULT)}


def results_fingerprint() -> str:
    with open(os.path.join(HERE, RESULTS), encoding="utf-8") as f:
        r = json.load(f)
    for k in NONDETERMINISTIC_RESULT_KEYS:
        r.pop(k, None)
    return sha256_obj(r)


def build_manifest() -> dict:
    with open(os.path.join(HERE, CORPUS), encoding="utf-8") as f:
        meta = json.load(f)["meta"]
    cfg = current_config()
    return {
        "freeze_id": FREEZE_ID,
        "git_tag": FREEZE_ID,
        "corpus": {"path": CORPUS, "sha256": sha256_file(CORPUS), "n": meta["n"], "n_phishing": meta["n_phishing"],
                   "source": meta["source"]},
        "config": {"path": _rel(CONFIG), "sha256": sha256_obj(cfg),
                   "files": {p: sha256_file(p) for p in CONFIG_FILES}},
        "code": {p: sha256_file(p) for p in code_files()},
        "results": {"path": RESULTS, "sha256_excluding": list(NONDETERMINISTIC_RESULT_KEYS),
                    "sha256": results_fingerprint()},
        "environment": {"python": platform.python_version(), "platform": platform.platform(terse=True),
                        "note": "fusion/evaluation use only the standard library; matplotlib is optional (figure only)"},
    }


def check() -> list[str]:
    """Return a list of drift messages; empty means the working tree matches the freeze."""
    with open(MANIFEST, encoding="utf-8") as f:
        m = json.load(f)
    with open(CONFIG, encoding="utf-8") as f:
        frozen_cfg = json.load(f)
    problems = []
    if sha256_file(CORPUS) != m["corpus"]["sha256"]:
        problems.append(f"corpus changed: {CORPUS}")
    if sha256_obj(frozen_cfg) != m["config"]["sha256"]:
        problems.append(f"frozen config file edited: {_rel(CONFIG)}")
    if current_config() != frozen_cfg:
        cur = current_config()
        diff = sorted(k for k in set(cur["params"]) | set(frozen_cfg["params"])
                      if cur["params"].get(k) != frozen_cfg["params"].get(k))
        problems.append(f"fusion.DEFAULT / SCHEMA_VERSION differ from frozen config (params: {diff or 'schema_version'})")
    for p, h in m["config"]["files"].items():
        if not os.path.exists(os.path.join(HERE, p)) or sha256_file(p) != h:
            problems.append(f"config file changed: {p}")
    now = set(code_files())
    for p, h in m["code"].items():
        if p not in now:
            problems.append(f"code file removed: {p}")
        elif sha256_file(p) != h:
            problems.append(f"code changed: {p}")
    for p in sorted(now - set(m["code"])):
        problems.append(f"code file added: {p}")
    if results_fingerprint() != m["results"]["sha256"]:
        problems.append(f"{RESULTS} differs from frozen results (re-run evaluate_fusion.py, or the evaluation drifted)")
    return problems


if __name__ == "__main__":
    if "--check" in sys.argv:
        drift = check()
        for d in drift:
            print("DRIFT:", d)
        print("freeze OK" if not drift else f"{len(drift)} difference(s) from {FREEZE_ID}")
        sys.exit(1 if drift else 0)
    os.makedirs(FREEZE_DIR, exist_ok=True)
    with open(CONFIG, "w", encoding="utf-8", newline="\n") as f:
        json.dump(current_config(), f, indent=1, sort_keys=True)
        f.write("\n")
    manifest = build_manifest()
    with open(MANIFEST, "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=1)
        f.write("\n")
    print(f"wrote {_rel(CONFIG)} and {_rel(MANIFEST)}: {len(manifest['code'])} code files, "
          f"corpus n={manifest['corpus']['n']}")
