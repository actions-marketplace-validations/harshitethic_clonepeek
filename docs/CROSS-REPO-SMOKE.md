# Real cross-repository GitHub Action smoke test — October 15, 2026

**Scope:** A maintainer-operated integration run from **[RepoPilot](https://github.com/harshitethic/RepoPilot)**, a *different public GitHub repository*. This demonstrates that another repository can call the immutable ClonePeek v0.5.0 GitHub Action and inspect **two real upstream configuration snapshots**. It is **not** validation by an independent third-party developer, a malware verdict, or a statistical estimate of recall/precision.

## Verified artifacts

- [Passing consumer workflow run](https://github.com/harshitethic/RepoPilot/actions/runs/38728091966) — checks out three separate repositories and runs the v0.5.0 composite action from immutable commit `65adee2b786e0c686b010f4f8f30b4e692759a95`.
- [Merged consumer integration PR #24](https://github.com/harshitethic/RepoPilot/pull/24) and [full workflow source](https://github.com/harshitethic/RepoPilot/blob/main/.github/workflows/clonepeek-consumer.yml).
- The consumer repository's existing backend/frontend CI **4/4 succeeded**, as did its **2/2 CodeQL security-analysis jobs** on this PR. This is separate from the ClonePeek action results.

## Upstream file integrity and observed findings

| Public repository (immutable commit) | File and verified Git blob SHA-1 | Observed read-only result |
| --- | --- | --- |
| [cursor/cookbook](https://github.com/cursor/cookbook/tree/6733ef81a7dc3cb2a6c1f524ff586ebecc703204) (`6733ef81a7dc3cb2a6c1f524ff586ebecc703204`) | `hooks/.cursor/hooks.json`, `f9f5625c535d1bc84c782ce0c7caaa23fdca08b0` | **7 medium** `cursor-hook-command` findings; command lines 6, 12, 18, 26, 33, 40, 47 |
| [Cowboy-59/YappChat](https://github.com/Cowboy-59/YappChat/tree/6e704eb3208926d61e4d045a2a013818613b8ce4) (`6e704eb3208926d61e4d045a2a013818613b8ce4`) | `.vscode/tasks.json`, `98ed671fc22b14d5bfab780ffdc9f803d7c7ee35` | **2 high** `vscode-folder-open` findings; tasks declare `runOn: folderOpen` on lines 16 and 30 and `node` commands on lines 7 and 21 |

The workflow itself asserts the blob hashes using the standard Git blob algorithm (`SHA1("blob " + length + NUL + contents)`). It checks the scanner's version, selected rule, severity, finding count, source path, positive line numbers, and reusable Action outputs. The Cursor hooks were recognized as **execution surfaces**, not suspicious or malicious behavior. YappChat's ordinary folder-open tasks merit review before trusting the workspace; their high severity is a **trigger classification, not an allegation of malware**.

The RepoPilot self-scan also ran with `fail-on: none`. No specific count or security verdict about the rest of RepoPilot is inferred from this check. No third-party scripts, npm installs, editor tasks, agent hooks, or launch configurations were executed.

## Reproduce using the public workflow

Use the same file as the tested [RepoPilot workflow](https://github.com/harshitethic/RepoPilot/blob/main/.github/workflows/clonepeek-consumer.yml). It requires `permissions: contents: read`, checks out the two pinned upstream repositories using `actions/checkout@v4` with **sparse checkout of only the relevant configuration files**, and sets `persist-credentials: false`. Each checkout is audited with:

```yaml
- uses: harshitethic/clonepeek@65adee2b786e0c686b010f4f8f30b4e692759a95
  with:
    path: public-samples/cursor-cookbook
    fail-on: none
    format: json
    output: ${{ runner.temp }}/clonepeek-cursor.json
```

The actual tested workflow includes a corresponding YappChat scan and validations. JSON reports are written to runner-temporary paths and **not uploaded as artifacts or printed as source snippets**. The GitHub Action performs no network calls during scanning; the surrounding checkout/setup steps do use GitHub's network. No code from the checked-out targets is imported or executed.

## What this does and does not prove

**Proved for these snapshots:** the released v0.5.0 action can be invoked as an external consumer; GitHub Action metadata and report outputs work; the pinned source files are read-only inputs; the documented Cursor and VS Code configurations produce the expected class and number of findings; the consumer's CI passes.

**Not proved:** broad detection accuracy, a malware verdict, safe-to-open assurance for either repository, reachability of every reported hook, general handling of large or untrusted live mounts, popularity, genuine third-party adoption, or independent maintainer review.

The [51-case hand-authored synthetic evaluation](EVALUATION.md) is a separate benchmark; its accuracy figures must **not** be combined with these two public configuration smoke tests. For independent external feedback, see [the open validation issue](https://github.com/harshitethic/clonepeek/issues/14).
