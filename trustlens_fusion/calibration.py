"""Calibration measurements for the fused risk score (stdlib only).

Works on LOGITS (fusion's `diagnostics.z`), not on rounded scores, so confident predictions do
not saturate. Everything here is a MEASUREMENT tool: with a corpus of a dozen pages it can show
that calibration cannot yet be assessed, and it says so (`summarize()["claim_supported"]`).

    temperature scaling   p = sigmoid(z / T), T fitted by minimising log loss
    ECE / Brier / log loss, reliability bins, bootstrap CIs, leave-one-out evaluation
"""
from __future__ import annotations

import math
import random

T_MIN, T_MAX = 0.2, 5.0     # search range for T; an optimum on a boundary is reported, not trusted
MIN_N_FOR_CLAIM = 200       # below this no calibration claim is made (illustrative rule of thumb)
MIN_PER_CLASS = 30


def sigmoid(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-z)) if z >= 0 else math.exp(z) / (1.0 + math.exp(z))


def probs(logits: list[float], T: float = 1.0) -> list[float]:
    return [sigmoid(z / T) for z in logits]


def _softplus(x: float) -> float:
    return x + math.log1p(math.exp(-x)) if x > 0 else math.log1p(math.exp(x))


def log_loss(logits: list[float], labels: list[int], T: float = 1.0) -> float:
    """Mean negative log-likelihood of the labels under sigmoid(z / T)."""
    return sum(_softplus(-(2 * y - 1) * z / T) for z, y in zip(logits, labels)) / len(labels)


def brier(p: list[float], labels: list[int]) -> float:
    return sum((a - y) ** 2 for a, y in zip(p, labels)) / len(labels)


def reliability_bins(p: list[float], labels: list[int], n_bins: int = 5) -> list[dict]:
    """Equal-width bins. A score of exactly 1.0 falls in the last bin. Empty bins are kept (n = 0)."""
    bins = [{"lo": i / n_bins, "hi": (i + 1) / n_bins, "n": 0, "sum_p": 0.0, "pos": 0} for i in range(n_bins)]
    for a, y in zip(p, labels):
        b = bins[min(int(a * n_bins), n_bins - 1)]
        b["n"] += 1
        b["sum_p"] += a
        b["pos"] += y
    out = []
    for b in bins:
        n = b["n"]
        out.append({"lo": b["lo"], "hi": b["hi"], "n": n,
                    "mean_score": b["sum_p"] / n if n else None,
                    "frac_positive": b["pos"] / n if n else None,
                    "gap": abs(b["sum_p"] / n - b["pos"] / n) if n else None})
    return out


def ece(p: list[float], labels: list[int], n_bins: int = 5) -> float:
    """Expected calibration error: sample-weighted mean |mean score - fraction positive| per bin."""
    total = len(labels)
    return sum(b["n"] / total * b["gap"] for b in reliability_bins(p, labels, n_bins) if b["n"])


def fit_temperature(logits: list[float], labels: list[int]) -> dict:
    """Fit T by minimising log loss over a = 1/T in [1/T_MAX, 1/T_MIN] (the loss is convex in a).

    Returns T plus honesty flags:
      identifiable  False if only one class is present (nothing to fit; T = 1)
      separable     True if every positive scores above every negative; log loss then keeps
                    falling as the scores get more extreme, so T just runs to the search limit
      at_boundary   the optimum sits on the edge of the search range
    """
    n_pos = sum(labels)
    if n_pos == 0 or n_pos == len(labels):
        return {"T": 1.0, "identifiable": False, "separable": False, "at_boundary": False,
                "nll_before": log_loss(logits, labels), "nll_after": log_loss(logits, labels)}
    pos = [z for z, y in zip(logits, labels) if y]
    neg = [z for z, y in zip(logits, labels) if not y]
    separable = min(pos) > max(neg)

    lo, hi = 1.0 / T_MAX, 1.0 / T_MIN
    f = lambda a: log_loss(logits, labels, 1.0 / a)  # noqa: E731
    g = (math.sqrt(5) - 1) / 2
    x1, x2 = hi - g * (hi - lo), lo + g * (hi - lo)
    f1, f2 = f(x1), f(x2)
    for _ in range(80):
        if f1 < f2:
            hi, x2, f2 = x2, x1, f1
            x1 = hi - g * (hi - lo)
            f1 = f(x1)
        else:
            lo, x1, f1 = x1, x2, f2
            x2 = lo + g * (hi - lo)
            f2 = f(x2)
    a = (lo + hi) / 2
    T = 1.0 / a
    return {"T": T, "identifiable": True, "separable": separable,
            "at_boundary": abs(T - T_MIN) < 1e-3 or abs(T - T_MAX) < 1e-3,
            "nll_before": log_loss(logits, labels), "nll_after": log_loss(logits, labels, T)}


def leave_one_out(logits: list[float], labels: list[int]) -> list[float]:
    """Held-out probabilities: each page is scored with a T fitted WITHOUT it (honest on small N)."""
    out = []
    for i in range(len(logits)):
        rest_z, rest_y = logits[:i] + logits[i + 1:], labels[:i] + labels[i + 1:]
        T = fit_temperature(rest_z, rest_y)["T"]
        out.append(sigmoid(logits[i] / T))
    return out


def bootstrap_ci(metric, p: list[float], labels: list[int], n_boot: int = 1000, seed: int = 0,
                 alpha: float = 0.05) -> tuple[float, float]:
    """Percentile bootstrap interval for metric(p, labels). Seeded, so reports are reproducible."""
    rng = random.Random(seed)
    n = len(labels)
    vals = []
    for _ in range(n_boot):
        idx = [rng.randrange(n) for _ in range(n)]
        vals.append(metric([p[i] for i in idx], [labels[i] for i in idx]))
    vals.sort()
    return vals[int(alpha / 2 * n_boot)], vals[min(int((1 - alpha / 2) * n_boot), n_boot - 1)]


def auc(scores: list[float], labels: list[int]) -> float | None:
    """Probability a random positive outranks a random negative (ties count half). Threshold-free."""
    pos = [s for s, y in zip(scores, labels) if y]
    neg = [s for s, y in zip(scores, labels) if not y]
    if not pos or not neg:
        return None
    wins = sum(1.0 if a > b else 0.5 if a == b else 0.0 for a in pos for b in neg)
    return wins / (len(pos) * len(neg))


def summarize(logits: list[float], labels: list[int], n_bins: int = 5, n_boot: int = 1000, seed: int = 0) -> dict:
    """Everything needed for a reliability / calibration table, plus an explicit claim check."""
    n, n_pos = len(labels), sum(labels)
    p = probs(logits)
    fit = fit_temperature(logits, labels)
    held_out = leave_one_out(logits, labels)
    lo, hi = bootstrap_ci(lambda a, b: ece(a, b, n_bins), p, labels, n_boot, seed)
    supported = n >= MIN_N_FOR_CLAIM and min(n_pos, n - n_pos) >= MIN_PER_CLASS
    return {
        "n": n, "n_positive": n_pos, "n_negative": n - n_pos,
        "raw": {"ece": ece(p, labels, n_bins), "brier": brier(p, labels), "log_loss": log_loss(logits, labels),
                "ece_95ci": [lo, hi], "bins": reliability_bins(p, labels, n_bins)},
        "temperature_fit": fit,
        "leave_one_out": {"ece": ece(held_out, labels, n_bins), "brier": brier(held_out, labels)},
        "auc": auc(p, labels),
        "claim_supported": supported,
        "claim_note": ("Enough pages to support a calibration claim." if supported else
                       f"n={n} ({n_pos} phishing) is below the {MIN_N_FOR_CLAIM} pages / {MIN_PER_CLASS} per class "
                       "needed; report these as measurements and threshold sensitivity, not as calibration."),
    }


def bins_text(bins: list[dict]) -> str:
    rows = ["  score range   n   mean score   fraction phishing"]
    for b in bins:
        ms = "-" if b["n"] == 0 else f"{b['mean_score']:.2f}"
        fp = "-" if b["n"] == 0 else f"{b['frac_positive']:.2f}"
        rows.append(f"  {b['lo']:.1f} - {b['hi']:.1f}   {b['n']:>2}   {ms:>10}   {fp:>17}")
    return "\n".join(rows)
