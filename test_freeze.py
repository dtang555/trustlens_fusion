"""Fails if the corpus, configuration, code, or deterministic results drift from freeze/MANIFEST.json.

To change any of them on purpose, make the change, re-run evaluate_fusion.py, then run freeze.py
and tag the new commit with a new freeze id.
"""
import freeze


def test_working_tree_matches_freeze():
    assert freeze.check() == []
