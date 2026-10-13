# Synthetic evaluation — ClonePeek v0.2.0

**This is not real-world malware detection accuracy.** These 12 examples were intentionally constructed to exercise known rules and expose gaps; results cannot be generalized to arbitrary open-source repositories.

## Reproduce

From the source checkout (Python 3.10+):

```bash
python -m pip install -e .
python -m evaluation.evaluate
python -m evaluation.evaluate --format json
python -m unittest discover -s tests
```

Fixtures are version-controlled in [`evaluation/cases.json`](../evaluation/cases.json). Each case contains a single simulated configuration, an independently chosen `high_risk` label, and a human-readable rationale. The runner builds temporary directories and calls the *passive scanner*—none of the fixture commands runs. All network strings use the reserved `.invalid` domain. The threshold treats only `high` and `critical` ClonePeek findings as predicted high-risk.

## Fixed-fixture results

| Outcome | Count |
| --- | ---: |
| True positive | 6 |
| False positive | 1 |
| False negative | 1 |
| True negative | 4 |
| Precision (6 / 7) | 85.7% |
| Recall (6 / 7) | 85.7% |

The **false positive** is a benign VS Code `folderOpen` `echo hello` task; the risk of automatic execution is real, but a manual reviewer would not call that command malicious. The **false negative** is a plausible malicious indirect script launched through `sh ./scripts/setup.sh`: ClonePeek inventories the lifecycle entry point but does not inspect the shell script it invokes. A medium finding is still returned, but this synthetic high-risk classification is missed.

These limitations make clear why **a clean or medium report is not a safety guarantee**. Synthetic scores may fall sharply on new datasets, different platforms, and unfamiliar malicious behaviors. Do not market this score as real-world accuracy. Future work: collect consented, labeled, representative benign and malicious configurations; version the corpus and publish per-rule confidence intervals where the sample permits.
