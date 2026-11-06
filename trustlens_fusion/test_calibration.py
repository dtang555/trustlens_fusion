"""Calibration tooling tests.  Run: python test_calibration.py   (also works under pytest)"""
import random

import calibration as C


def _overconfident(n, factor, seed):
    """True logits z ~ N(0, 2); labels ~ Bernoulli(sigmoid(z)); the 'model' reports factor * z."""
    rng = random.Random(seed)
    zs = [rng.gauss(0, 2) for _ in range(n)]
    ys = [1 if rng.random() < C.sigmoid(z) else 0 for z in zs]
    return [factor * z for z in zs], ys


def test_fit_recovers_known_temperature():
    z, y = _overconfident(6000, 3.0, seed=1)
    fit = C.fit_temperature(z, y)
    assert fit["identifiable"] and not fit["separable"] and not fit["at_boundary"]
    assert abs(fit["T"] - 3.0) < 0.4, fit["T"]


def test_fitting_reduces_log_loss_and_ece():
    z, y = _overconfident(6000, 3.0, seed=2)
    fit = C.fit_temperature(z, y)
    assert fit["nll_after"] < fit["nll_before"]
    assert C.ece(C.probs(z, fit["T"]), y) < C.ece(C.probs(z), y)


def test_ece_is_zero_when_bins_match_exactly():
    p = [0.2] * 10 + [0.8] * 10
    y = [1, 1] + [0] * 8 + [1] * 8 + [0, 0]
    assert abs(C.ece(p, y, n_bins=5)) < 1e-12


def test_brier_known_values():
    assert C.brier([1.0, 0.0], [1, 0]) == 0.0
    assert C.brier([0.5, 0.5], [1, 0]) == 0.25


def test_bins_account_for_every_page_and_include_score_of_one():
    p = [0.0, 0.19, 0.2, 0.55, 0.99, 1.0]
    bins = C.reliability_bins(p, [0, 0, 0, 1, 1, 1], n_bins=5)
    assert sum(b["n"] for b in bins) == len(p) and bins[-1]["n"] == 2


def test_single_class_is_not_fitted():
    fit = C.fit_temperature([1.0, 2.0, 3.0], [1, 1, 1])
    assert fit["T"] == 1.0 and fit["identifiable"] is False


def test_separable_data_is_flagged_and_runs_to_the_boundary():
    fit = C.fit_temperature([5.0, 6.0, -5.0, -6.0], [1, 1, 0, 0])
    assert fit["separable"] and fit["at_boundary"] and abs(fit["T"] - C.T_MIN) < 1e-2


def test_bootstrap_interval_narrows_with_more_data():
    def width(n):
        z, y = _overconfident(n, 1.0, seed=3)
        lo, hi = C.bootstrap_ci(lambda a, b: C.ece(a, b), C.probs(z), y, n_boot=300, seed=0)
        return hi - lo
    assert width(40) > width(3000)


def test_leave_one_out_gives_one_heldout_probability_per_page():
    z, y = _overconfident(60, 2.0, seed=4)
    held = C.leave_one_out(z, y)
    assert len(held) == 60 and all(0.0 < p < 1.0 for p in held)


def test_auc_known_values():
    assert C.auc([0.9, 0.8, 0.2, 0.1], [1, 1, 0, 0]) == 1.0
    assert C.auc([0.5, 0.5], [1, 0]) == 0.5
    assert C.auc([0.9, 0.8], [1, 1]) is None


def test_small_corpus_makes_no_calibration_claim():
    z, y = _overconfident(13, 1.0, seed=5)
    s = C.summarize(z, y, n_boot=100)
    assert s["claim_supported"] is False and "not as calibration" in s["claim_note"]
    z, y = _overconfident(3000, 1.0, seed=6)
    assert C.summarize(z, y, n_boot=50)["claim_supported"] is True


if __name__ == "__main__":
    tests = [(n, f) for n, f in globals().items() if n.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {name}  {exc!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(failed)
