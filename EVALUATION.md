# TrustLens fusion: small-corpus evaluation (preliminary)

Corpus: **14 pages** (7 phishing-style, 7 legitimate). Branch B output is real; the visual module is either missing (`real_only`) or simulated (`sim_visual`, brand claim only, no phishing verdict). Every score below is a **preliminary risk score**, not a calibrated probability. The corpus is far too small to support a calibration claim, so this document reports threshold sensitivity, ablations and measurements only.

## Key findings (computed from the tables below)

1. **With the visual module missing, fusion warns on 3/7 phishing pages and Branch B alone (score at or above 0.5) on 5/7.** Fusion routes 4 more phishing pages to uncertain and allows 0, so flagged recall (warn + uncertain) is 1.00 against 0.71 for Branch B. It also sends 3 of 7 legitimate pages to uncertain and warns on 0.
2. **The rule floor and cross-modal terms carry most of the warnings.** Of 3 warnings, removing the floor removes 2 and removing the cross-modal terms as well removes 3 (phish ip host, phish typosquat, phish classic).
3. **How Branch B's three modules are combined changes outcomes.** Equal-weight mean (current): 3 warns, 0 missed, AUC 0.86. Noisy-OR (earlier default): 4 warns, 0 missed, AUC 0.86. Discounted log-odds votes (earliest): 3 warns, 0 missed. Mean and noisy-OR differ on 1 page(s): phish shortened + hidden form. Averaging dilutes one strongly suspicious module with weaker ones, where noisy-OR lets evidence accumulate; in exchange the mean cannot be inflated by many weak signals, and a missing module is not counted.
4. **Knife-edge pages** (score within 0.03 of the allow or warn threshold): none. 2 warning(s) score exactly at the rule-floor value (0.9), so a warn threshold of 0.9 or higher removes them: phish ip host, phish typosquat.
5. **2 of 7 phishing pages score at or below the allow threshold (0.2), so the score alone cannot tell them from legitimate pages** (evasive: clean domain, no brand text, unseen-brand phish B). Their decisions: uncertain. Only the uncertain state (unseen brand) catches them.
6. **The allow-coverage threshold sits on the edge when the visual module is missing.** With two sources the best attainable coverage is 0.5, so a Branch B confidence below 1.0 forces uncertain. Lowering it to 0.4 changes 1 decision; raising it to 0.6 changes 4 decisions.
7. **Unseen brands are caught by the uncertain state, at a cost.** 2 of 2 unseen-brand phishing pages are flagged, and 2 of 2 legitimate unseen-brand logins also become uncertain. The rule no longer depends on the visual module (2 flagged without it). Adding a brand to the visual reference WITHOUT its domains in the shared registry gives 2 false warns on the genuine pages; adding both gives 0.
8. **Single-module loss** (decisions changed per dropped module): real_only: visual 0, url 7, dom 6, text 7; sim_visual: visual 1, url 6, dom 8, text 0. At most 4 phishing pages become allow. **The text module's importance depends on the configuration.** With a simulated visual module it changes 0 decisions; with the visual module missing it changes 7, because 3 warnings lose the brand-domain mismatch (Branch B's text rule is then the only brand claim) and 7 pages fall below the coverage floor.
9. **A confidently wrong visual module** produced 0 wrong final verdicts; 5 pages were newly routed to uncertain and 7 carry a disagreement flag. `conflict_blocks_warn` changes 0 of 14 decisions relative to the default.
10. **No calibration claim is possible.** ECE 0.235 has a 95% bootstrap interval of 0.072 to 0.437 on 14 pages; the fitted temperature (2.66) is an in-sample figure, not a result.
11. **Processing cost is negligible:** fusion takes a median 0.04 ms per page (7% of the Branch B + adapter + fusion pipeline).

## 1. Per-page results

| Page | Label | Branch B score | Branch B hint | Fusion, visual missing | Fusion, simulated visual | Uncertainty reasons (sim) |
| --- | --- | --- | --- | --- | --- | --- |
| paypal legit | legit | 0.239 | safe | allow (0.034) | allow (0.034) | - |
| acme sso | legit | 0.080 | safe | allow (0.010) | allow (0.010) | - |
| plain blog | legit | 0.000 | safe | allow (0.003) | allow (0.003) | - |
| bank legit login | legit | 0.145 | safe | allow (0.019) | allow (0.019) | - |
| phish classic | phishing | 0.992 | suspicious | warn (0.973) | warn (0.973) | - |
| phish ip host | phishing | 0.808 | suspicious | warn (0.900) | warn (0.900) | - |
| phish typosquat | phishing | 0.829 | suspicious | warn (0.900) | warn (0.900) | - |
| phish shortened + hidden form | phishing | 0.881 | suspicious | uncertain (0.423) | uncertain (0.423) | unseen_brand |
| evasive: clean domain, no brand text | phishing | 0.145 | safe | uncertain (0.019) | uncertain (0.019) | unseen_brand |
| legit short login (little text) | legit | 0.231 | safe | uncertain (0.051) | allow (0.051) | - |
| unseen-brand phish A | phishing | 0.795 | suspicious | uncertain (0.323) | uncertain (0.323) | unseen_brand |
| unseen-brand phish B | phishing | 0.145 | safe | uncertain (0.019) | uncertain (0.019) | unseen_brand |
| unseen-brand legit A | legit | 0.145 | safe | uncertain (0.019) | uncertain (0.019) | unseen_brand |
| unseen-brand legit B | legit | 0.145 | safe | uncertain (0.019) | uncertain (0.019) | unseen_brand |

- **real_only**: warn on 3/7 phishing, allow on 0, uncertain on 4; false warns 0, uncertain on 3 legitimate. Flagged recall (warn + uncertain) 1.00, AUC 0.86.
- **sim_visual**: warn on 3/7 phishing, allow on 0, uncertain on 4; false warns 0, uncertain on 2 legitimate. Flagged recall (warn + uncertain) 1.00, AUC 0.86.
- **Branch B alone** (score at or above 0.5): AUC 0.86.

## 2. Threshold sensitivity (the main result at this corpus size)

One parameter varied at a time around the defaults. Cells show warn / allow / uncertain counts, then missed phishing (FN) and false warns (FP), then `flips` = pages whose decision differs from the default configuration.

**t_high (warn at or above)**

| value | visual missing | simulated visual |
| --- | --- | --- |
| 0.5 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 0.6 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 0.7 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 0.8 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 0.9 | 1/4/9, FN 0, FP 0, flips 2 | 1/5/8, FN 0, FP 0, flips 2 |
| 0.95 | 1/4/9, FN 0, FP 0, flips 2 | 1/5/8, FN 0, FP 0, flips 2 |

**t_low (allow at or below)**

| value | visual missing | simulated visual |
| --- | --- | --- |
| 0.05 | 3/4/7, FN 0, FP 0, flips 0 | 3/4/7, FN 0, FP 0, flips 1 |
| 0.1 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 0.2 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 0.3 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 0.4 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |

**min_coverage (to allow)**

| value | visual missing | simulated visual |
| --- | --- | --- |
| 0.3 | 3/5/6, FN 0, FP 0, flips 1 | 3/5/6, FN 0, FP 0, flips 0 |
| 0.4 | 3/5/6, FN 0, FP 0, flips 1 | 3/5/6, FN 0, FP 0, flips 0 |
| 0.5 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 0.6 | 3/0/11, FN 0, FP 0, flips 4 | 3/5/6, FN 0, FP 0, flips 0 |

**min_coverage_warn**

| value | visual missing | simulated visual |
| --- | --- | --- |
| 0.0 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 0.2 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 0.3 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 0.4 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 0.5 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |

**max_disagreement**

| value | visual missing | simulated visual |
| --- | --- | --- |
| 0.5 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 1.0 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 2.0 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 3.0 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |

**bias**

| value | visual missing | simulated visual |
| --- | --- | --- |
| -3.0 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| -2.5 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| -2.0 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| -1.5 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| -1.0 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| -0.5 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 0.0 | 4/3/7, FN 0, FP 0, flips 2 | 4/3/7, FN 0, FP 0, flips 3 |

**Branch B source weight**

| value | visual missing | simulated visual |
| --- | --- | --- |
| 0.5 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 1.0 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 1.5 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 2.0 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |
| 3.0 | 3/4/7, FN 0, FP 0, flips 0 | 3/5/6, FN 0, FP 0, flips 0 |

**Cost surface over t_high x t_low** (lower is better). The best thresholds depend on the assumed costs, and many settings tie, which is expected at this corpus size.

- real_only, cost A (miss 10, false warn 3, uncertain 1): minimum cost 7 (default 7); 20 of 25 (t_high, t_low) cells tie, e.g. (0.5, 0.05); (0.5, 0.1); (0.5, 0.2); (0.5, 0.3); (0.5, 0.4).
- real_only, cost B (miss 10, false warn 1, uncertain 2): minimum cost 14 (default 14); 20 of 25 (t_high, t_low) cells tie, e.g. (0.5, 0.05); (0.5, 0.1); (0.5, 0.2); (0.5, 0.3); (0.5, 0.4).
- sim_visual, cost A (miss 10, false warn 3, uncertain 1): minimum cost 6 (default 6); 16 of 25 (t_high, t_low) cells tie, e.g. (0.5, 0.1); (0.5, 0.2); (0.5, 0.3); (0.5, 0.4); (0.6, 0.1).
- sim_visual, cost B (miss 10, false warn 1, uncertain 2): minimum cost 12 (default 12); 16 of 25 (t_high, t_low) cells tie, e.g. (0.5, 0.1); (0.5, 0.2); (0.5, 0.3); (0.5, 0.4); (0.6, 0.1).

**Branch B alone, threshold sweep:**

| threshold | recall | false-positive rate | missed | false warn |
| --- | --- | --- | --- | --- |
| 0.3 | 0.71 | 0.00 | 2 | 0 |
| 0.4 | 0.71 | 0.00 | 2 | 0 |
| 0.5 | 0.71 | 0.00 | 2 | 0 |
| 0.6 | 0.71 | 0.00 | 2 | 0 |
| 0.7 | 0.71 | 0.00 | 2 | 0 |
| 0.8 | 0.57 | 0.00 | 3 | 0 |
| 0.9 | 0.14 | 0.00 | 6 | 0 |

## 3. Modality ablations

**real_only**

| config | warn on phishing | missed | uncertain (phish / legit) | false warn | precision | recall | AUC | flips vs full | cost A | cost B |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| full system | 3/7 | 0 | 4 / 3 | 0 | 1.00 | 0.43 | 0.86 | 0 | 7 | 14 |
| drop URL module | 0/7 | 0 | 7 / 7 | 0 | n/a | 0.00 | 0.86 | 7 | 14 | 28 |
| drop DOM module | 1/7 | 0 | 6 / 7 | 0 | 1.00 | 0.14 | 0.80 | 6 | 13 | 26 |
| drop text module | 0/7 | 0 | 7 / 7 | 0 | n/a | 0.00 | 0.88 | 7 | 14 | 28 |
| drop visual module | 3/7 | 0 | 4 / 3 | 0 | 1.00 | 0.43 | 0.86 | 0 | 7 | 14 |
| visual only (drop all Branch B) | 0/7 | 0 | 7 / 7 | 0 | n/a | 0.00 | 0.50 | 7 | 14 | 28 |
| no cross-modal terms, no rule floor | 0/7 | 0 | 7 / 3 | 0 | n/a | 0.00 | 0.86 | 3 | 10 | 20 |
| no rule floor | 1/7 | 0 | 6 / 3 | 0 | 1.00 | 0.14 | 0.86 | 2 | 9 | 18 |
| Branch B combined by noisy-OR (earlier default) | 4/7 | 0 | 3 / 3 | 0 | 1.00 | 0.57 | 0.86 | 1 | 6 | 12 |
| Branch B modules as discounted log-odds votes (rho = 0.5) | 3/7 | 0 | 4 / 3 | 0 | 1.00 | 0.43 | 0.86 | 0 | 7 | 14 |
| Branch B modules as independent log-odds votes (rho = 0) | 3/7 | 0 | 4 / 3 | 0 | 1.00 | 0.43 | 0.86 | 0 | 7 | 14 |
| no uncertain state (binary at 0.5) | 3/7 | 4 | 0 / 0 | 0 | 1.00 | 0.43 | 0.86 | 7 | 40 | 40 |
| v0.1 unseen-brand rule (credential wording + visual) | 3/7 | 2 | 2 / 1 | 0 | 1.00 | 0.43 | 0.86 | 4 | 23 | 26 |
| v0.2 unseen-brand rule (credential form + visual) | 3/7 | 2 | 2 / 1 | 0 | 1.00 | 0.43 | 0.86 | 4 | 23 | 26 |
| conflict blocks warn | 3/7 | 0 | 4 / 3 | 0 | 1.00 | 0.43 | 0.86 | 0 | 7 | 14 |

**sim_visual**

| config | warn on phishing | missed | uncertain (phish / legit) | false warn | precision | recall | AUC | flips vs full | cost A | cost B |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| full system | 3/7 | 0 | 4 / 2 | 0 | 1.00 | 0.43 | 0.86 | 0 | 6 | 12 |
| drop URL module | 1/7 | 4 | 2 / 0 | 0 | 1.00 | 0.14 | 0.86 | 6 | 42 | 44 |
| drop DOM module | 1/7 | 4 | 2 / 0 | 0 | 1.00 | 0.14 | 0.80 | 8 | 42 | 44 |
| drop text module | 3/7 | 0 | 4 / 2 | 0 | 1.00 | 0.43 | 0.88 | 0 | 6 | 12 |
| drop visual module | 3/7 | 0 | 4 / 3 | 0 | 1.00 | 0.43 | 0.86 | 1 | 7 | 14 |
| visual only (drop all Branch B) | 0/7 | 0 | 7 / 7 | 0 | n/a | 0.00 | 0.50 | 8 | 14 | 28 |
| no cross-modal terms, no rule floor | 0/7 | 2 | 5 / 2 | 0 | n/a | 0.00 | 0.86 | 3 | 27 | 34 |
| no rule floor | 1/7 | 0 | 6 / 2 | 0 | 1.00 | 0.14 | 0.86 | 2 | 8 | 16 |
| Branch B combined by noisy-OR (earlier default) | 4/7 | 0 | 3 / 2 | 0 | 1.00 | 0.57 | 0.86 | 1 | 5 | 10 |
| Branch B modules as discounted log-odds votes (rho = 0.5) | 3/7 | 0 | 4 / 2 | 0 | 1.00 | 0.43 | 0.86 | 0 | 6 | 12 |
| Branch B modules as independent log-odds votes (rho = 0) | 3/7 | 0 | 4 / 2 | 0 | 1.00 | 0.43 | 0.86 | 0 | 6 | 12 |
| no uncertain state (binary at 0.5) | 3/7 | 4 | 0 / 0 | 0 | 1.00 | 0.43 | 0.86 | 6 | 40 | 40 |
| v0.1 unseen-brand rule (credential wording + visual) | 3/7 | 0 | 4 / 3 | 0 | 1.00 | 0.43 | 0.86 | 1 | 7 | 14 |
| v0.2 unseen-brand rule (credential form + visual) | 3/7 | 0 | 4 / 2 | 0 | 1.00 | 0.43 | 0.86 | 0 | 6 | 12 |
| conflict blocks warn | 3/7 | 0 | 4 / 2 | 0 | 1.00 | 0.43 | 0.86 | 0 | 6 | 12 |

## 4. Missing-module and contradictory-module behaviour

Each module removed in turn. `lost brand mismatch` = changed pages that lost the brand-domain mismatch term; `low coverage` = changed pages that fell below the coverage floor.

**real_only**

| module removed | decisions changed | phishing now allowed | legitimate now warned | lost brand mismatch | low coverage |
| --- | --- | --- | --- | --- | --- |
| visual | 0 | 0 | 0 | 0 | 0 |
| url | 7 | 0 | 0 | 3 | 7 |
| dom | 6 | 0 | 0 | 0 | 6 |
| text | 7 | 0 | 0 | 3 | 7 |

**sim_visual**

| module removed | decisions changed | phishing now allowed | legitimate now warned | lost brand mismatch | low coverage |
| --- | --- | --- | --- | --- | --- |
| visual | 1 | 0 | 0 | 0 | 1 |
| url | 6 | 4 | 0 | 2 | 0 |
| dom | 8 | 4 | 0 | 0 | 0 |
| text | 0 | 0 | 0 | 0 | 0 |

Contradiction injection (simulated visual): the visual module is replaced by a confidently wrong verdict (0.05 on phishing, 0.95 on legitimate).

| setting | decisions changed | wrong final verdicts (allow on phishing / warn on legit) | newly uncertain | disagreement flagged |
| --- | --- | --- | --- | --- |
| default (a high score still warns) | 5 | 0 | 5 | 7 |
| conflict_blocks_warn | 5 | 0 | 5 | 7 |

## 5. Unseen-brand cases

**v0.1 rule (credential wording + visual confidence)**

| page | label | decision | risk score | reasons |
| --- | --- | --- | --- | --- |
| unseen-brand phish A | phishing | uncertain | 0.323 | unseen_brand |
| unseen-brand phish B | phishing | uncertain | 0.019 | unseen_brand |
| unseen-brand legit A | legit | uncertain | 0.019 | unseen_brand |
| unseen-brand legit B | legit | uncertain | 0.019 | unseen_brand |

**v0.2 rule (credential form + visual confidence)**

| page | label | decision | risk score | reasons |
| --- | --- | --- | --- | --- |
| unseen-brand phish A | phishing | uncertain | 0.323 | unseen_brand |
| unseen-brand phish B | phishing | uncertain | 0.019 | unseen_brand |
| unseen-brand legit A | legit | uncertain | 0.019 | unseen_brand |
| unseen-brand legit B | legit | uncertain | 0.019 | unseen_brand |

**current rule (credential form, no brand owns the domain, no module identifies a brand)**

| page | label | decision | risk score | reasons |
| --- | --- | --- | --- | --- |
| unseen-brand phish A | phishing | uncertain | 0.323 | unseen_brand |
| unseen-brand phish B | phishing | uncertain | 0.019 | unseen_brand |
| unseen-brand legit A | legit | uncertain | 0.019 | unseen_brand |
| unseen-brand legit B | legit | uncertain | 0.019 | unseen_brand |

**current rule, visual module missing**

| page | label | decision | risk score | reasons |
| --- | --- | --- | --- | --- |
| unseen-brand phish A | phishing | uncertain | 0.323 | unseen_brand |
| unseen-brand phish B | phishing | uncertain | 0.019 | unseen_brand |
| unseen-brand legit A | legit | uncertain | 0.019 | unseen_brand |
| unseen-brand legit B | legit | uncertain | 0.019 | unseen_brand |

**brand added to visual reference ONLY**

| page | label | decision | risk score | reasons |
| --- | --- | --- | --- | --- |
| unseen-brand phish A | phishing | warn | 0.900 | - |
| unseen-brand phish B | phishing | warn | 0.900 | - |
| unseen-brand legit A | legit | warn | 0.900 | - |
| unseen-brand legit B | legit | warn | 0.900 | - |

**brand added to visual reference AND shared registry**

| page | label | decision | risk score | reasons |
| --- | --- | --- | --- | --- |
| unseen-brand phish A | phishing | warn | 0.900 | - |
| unseen-brand phish B | phishing | warn | 0.900 | - |
| unseen-brand legit A | legit | allow | 0.019 | - |
| unseen-brand legit B | legit | allow | 0.019 | - |

## 6. Reliability and calibration measurements (illustrative only)

**real_only** (n = 14, 7 phishing)

- ECE 0.235 (95% bootstrap interval 0.072 to 0.437), Brier 0.196, log loss 0.737, AUC 0.86.
- Temperature fit: T = 2.66, separable data: False, at search boundary: False. Leave-one-out ECE 0.328, Brier 0.198.
- Calibration claim supported: **False**. n=14 (7 phishing) is below the 200 pages / 30 per class needed; report these as measurements and threshold sensitivity, not as calibration.

```
  score range   n   mean score   fraction phishing
  0.0 - 0.2    9         0.02                0.22
  0.2 - 0.4    1         0.32                1.00
  0.4 - 0.6    1         0.42                1.00
  0.6 - 0.8    0            -                   -
  0.8 - 1.0    3         0.92                1.00
```

**sim_visual** (n = 14, 7 phishing)

- ECE 0.235 (95% bootstrap interval 0.072 to 0.437), Brier 0.196, log loss 0.737, AUC 0.86.
- Temperature fit: T = 2.66, separable data: False, at search boundary: False. Leave-one-out ECE 0.328, Brier 0.198.
- Calibration claim supported: **False**. n=14 (7 phishing) is below the 200 pages / 30 per class needed; report these as measurements and threshold sensitivity, not as calibration.

```
  score range   n   mean score   fraction phishing
  0.0 - 0.2    9         0.02                0.22
  0.2 - 0.4    1         0.32                1.00
  0.4 - 0.6    1         0.42                1.00
  0.6 - 0.8    0            -                   -
  0.8 - 1.0    3         0.92                1.00
```

**branch_b_alone** (n = 14, 7 phishing)

- ECE 0.169 (95% bootstrap interval 0.064 to 0.342), Brier 0.126, log loss 0.408, AUC 0.86.
- Temperature fit: T = 1.09, separable data: False, at search boundary: False. Leave-one-out ECE 0.182, Brier 0.150.
- Calibration claim supported: **False**. n=14 (7 phishing) is below the 200 pages / 30 per class needed; report these as measurements and threshold sensitivity, not as calibration.

```
  score range   n   mean score   fraction phishing
  0.0 - 0.2    7         0.12                0.29
  0.2 - 0.4    2         0.23                0.00
  0.4 - 0.6    0            -                   -
  0.6 - 0.8    1         0.80                1.00
  0.8 - 1.0    4         0.88                1.00
```

## 7. Processing cost

| measure | value |
| --- | --- |
| fusion call, median / p95 / max (ms) | 0.038 / 0.057 / 0.201 |
| Branch B to shared-format adapter, median (ms) | 0.006 |
| Branch B analysis, median (ms, from Student B's module) | 0.481 |
| fusion share of the Branch B + adapter + fusion pipeline | 7.3% |
| peak memory, fusing all pages (KiB) | 10 |
| calls timed | 4200 |

Python on the development machine, not the browser. Visual and browser overheads are not included.

## 8. How each module contributes to the risk assessment (simulated visual)

Mean discounted log-odds term per module, and the mean drop in risk score when that module is removed.

| module | mean term (phishing) | mean term (legit) | score drop if removed (phishing) | score drop if removed (legit) |
| --- | --- | --- | --- | --- |
| visual | 0.00 | 0.00 | 0.000 | 0.000 |
| url | -0.48 | -1.02 | 0.225 | -0.003 |
| dom | -0.48 | -1.02 | 0.213 | 0.011 |
| text | -0.00 | -0.90 | -0.044 | -0.002 |

| cross-modal term | mean (phishing) | mean (legit) |
| --- | --- | --- |
| brand_domain_mismatch | 0.86 | 0.00 |
| cred_request | 1.00 | 0.86 |
| action_mismatch | 0.43 | 0.00 |
| link_deception | 0.07 | 0.00 |

The simulated visual module supplies brand claims only (its own term is zero), so its effect enters through the cross-modal brand-domain mismatch term.
