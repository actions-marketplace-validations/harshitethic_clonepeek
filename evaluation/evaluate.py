"""Reproducible *synthetic fixture* evaluation, not a field accuracy claim."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from clonepeek.scanner import scan


def evaluate() -> dict:
    cases = json.loads((Path(__file__).parent / "cases.json").read_text(encoding="utf-8"))
    outcomes = []
    for case in cases:
        with TemporaryDirectory(prefix="clonepeek-fixture-") as work:
            path = Path(work) / case["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(case["content"], encoding="utf-8")
            findings, _, skipped = scan(Path(work))
            predicted = any(f.severity in ("high", "critical") for f in findings)
            if skipped:
                raise RuntimeError("Fixture unexpectedly skipped: " + case["id"])
            outcomes.append({"id": case["id"], "expected_high_risk": case["high_risk"],
                             "predicted_high_risk": predicted, "rules": [f.rule for f in findings],
                             "severities": [f.severity for f in findings], "why": case["why"]})
    tp = sum(c["expected_high_risk"] and c["predicted_high_risk"] for c in outcomes)
    fp = sum(not c["expected_high_risk"] and c["predicted_high_risk"] for c in outcomes)
    fn = sum(c["expected_high_risk"] and not c["predicted_high_risk"] for c in outcomes)
    tn = len(outcomes) - tp - fp - fn
    return {"disclaimer": "Hand-authored synthetic fixtures, not real-world detection accuracy",
            "cases": len(outcomes), "threshold": "high",
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "outcomes": outcomes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()
    report = evaluate()
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print("SYNTHETIC FIXTURES ONLY — not field detection accuracy")
        print("Cases: {cases} | TP {tp} | FP {fp} | FN {fn} | TN {tn}".format(**report))
        print("High-risk precision: {:.1%} | Recall: {:.1%}".format(report["precision"], report["recall"]))
        for case in report["outcomes"]:
            if case["expected_high_risk"] != case["predicted_high_risk"]:
                print("MISS: {} — {}".format(case["id"], case["why"]))


if __name__ == "__main__":
    main()
