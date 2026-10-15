# Public configuration smoke test — 2026-10-15

This is an **individual external integration smoke test**, not a labeled dataset, independent security review, or real-world precision/recall estimate.

We read a public Cursor hook configuration from the **official [cursor/cookbook](https://github.com/cursor/cookbook)** repository. The published source is [hooks/.cursor/hooks.json](https://github.com/cursor/cookbook/blob/main/hooks/.cursor/hooks.json). No script in the repository was executed or imported. The downloaded configuration was stored inside a temporary directory and inspected with ClonePeek's ordinary CLI.

- Public configuration SHA-256 at inspection: `2abaee648ab024cfd00192e4f1bef8275abcf40b3cbcb82ce42f6a7c19887473`
- File bytes: `1234`
- Recognized files scanned: `1`
- `cursor-hook-command` findings: `7`
- Severity: 7 medium, 0 high, 0 critical
- Source lines reported: `6, 12, 18, 26, 33, 40, 47`
- Events represented: `beforeSubmitPrompt`, `beforeShellExecution`, `afterShellExecution`, `afterFileEdit`, `stop`

This is the expected behavior: these hooks *can* run commands when triggered, but their mere presence is not evidence of malicious intent.

## Reproduce safely

Using the public raw file directly and only inspecting its text:

```bash
mkdir -p /tmp/clonepeek-cookbook/hooks/.cursor
curl --fail --location --silent --show-error \
  https://raw.githubusercontent.com/cursor/cookbook/main/hooks/.cursor/hooks.json \
  --output /tmp/clonepeek-cookbook/hooks/.cursor/hooks.json
clonepeek /tmp/clonepeek-cookbook --format json
```

The upstream file can change. If the SHA-256 or findings change, record the new upstream revision and repeat the review before interpreting the results. This command performs a download from GitHub; **the ClonePeek scan itself makes no network requests**.

The 51-case hand-authored fixture benchmark in [EVALUATION.md](EVALUATION.md) measures something different and must not be described as field validation. Further evaluation requires consented independent samples and labels with reviewed false positives and false negatives.
