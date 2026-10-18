# TrustLens fusion prototype (schema v0.1.0)

Stdlib-only Python 3.10+.

    python demo.py [--json]            # 4 synthetic scenarios (all branches hand-written)
    python make_sample_bundle.py bundle   # writes a sample bundle (URL branch = real, others synthetic)
    python run_bundle.py bundle           # file-based integration: bundle -> fusion -> bundle/out/*.json
    python url_branch.py "<url>"          # rule-based URL branch on one URL
    python test_fusion.py                 # 14 fusion tests
    python test_integration.py            # 15 URL-branch / bundle / contract / fault-injection tests

## Files
- `fusion.py`        validation, cross-modal features, log-odds baseline, decision, explanations
- `url_branch.py`    rule-based URL branch (stand-in for Student B's); emits a real BranchOutput
- `brand_registry.json`  STUB shared registry: brand slug -> legitimate registered domains
- `run_bundle.py`    reads `<page>.<visual|url|dom|text>.json` (or `<page>.url.txt`), calls fusion, writes request/response JSON
- `make_sample_bundle.py`, `demo.py`  sample / synthetic inputs
- `bundle/`          sample bundle; `bundle/out/` holds the example request/response JSON to share with A, B, D

## How teammates plug in
Drop a BranchOutput JSON named `<page>.<branch>.json` into a bundle folder and run `run_bundle.py`.
Unreadable / mismatched / schema-violating files become `status: error` branches; fusion never crashes and
never defaults to `allow` (request-level failure -> `uncertain`, reason `fusion_unavailable`).

## Status
Real: URL branch (rules), fusion, file-based runner. Still synthetic: visual, DOM, text outputs.
Weights, thresholds, temperature, URL rule weights and the brand registry are placeholders.
Not yet: cascade, learned fuser, calibration tooling, HTTP wrapper, real A/B branches.
