# ClonePeek launch kit

**Verified as of 2026-10-15:** [v0.4.1 latest release](https://github.com/harshitethic/clonepeek/releases/tag/v0.4.1) published with wheel/source assets; [main-branch CI](https://github.com/harshitethic/clonepeek/actions) green on merge commit `dfb64678`; [v0.4.1 technical discussion](https://github.com/harshitethic/clonepeek/discussions/11) published; and [public Cursor cookbook config smoke test](REAL-WORLD-VALIDATION.md) previously completed. Public smoke testing is not real-world accuracy evaluation. **The external-community posts below are still drafts, not submitted posts or proof of adoption.**

## Positioning

**Name:** ClonePeek  
**Tagline:** Know what runs before you open a repo.  
**One-liner:** An offline, dependency-light CLI that inventories configuration-based execution paths in unfamiliar repositories—before you open them in an editor, install packages, or connect an AI agent.

**Audience:** developers who clone unknown repositories, open-source maintainers, security reviewers, hackathon participants, and users of coding agents.

**Differentiator:** Explain **trigger → command → evidence → review action**. ClonePeek is not a malware scanner, sandbox, provenance system, or replacement for in-depth security review.




## v0.5.0 action release — verified October 15, 2026

- **Public release:** [ClonePeek v0.5.0](https://github.com/harshitethic/clonepeek/releases/tag/v0.5.0), source archive and wheel uploaded; release points to merge commit `65adee2`.
- **New adoption path:** `uses: harshitethic/clonepeek@v0.5.0` within GitHub Actions. See [GitHub Action guide](GITHUB-ACTION.md) and the [live composite-action test workflow](../.github/workflows/composite-action.yml).
- **Proven compatibility:** 3/3 actual composite-action matrix jobs passed on Ubuntu/macOS/Windows; 6/6 main-branch Python suite jobs passed on Python 3.10 and 3.13. 64 local tests passing.
- **Safety position:** no scanned project code execution, report-only default, optional thresholds/baselines, action summary lists counts and not source excerpts. The complete report may still expose sensitive source.
- **GitHub Marketplace status:** NOT published there. The owner must first review/accept GitHub's Marketplace Developer Agreement; no agent should accept contracts on the owner's behalf. This is separate from the public GitHub release and installable action.
- **Organic traction:** Do not confuse tests, discussion announcements or version releases with external stars, forks, downloads, or reviews. Current adoption should be measured from subsequent GitHub analytics and genuine user feedback.

Suggested one-sentence announcement: **"ClonePeek is a free GitHub Action and local CLI that shows npm, editor, and AI-agent hooks that might execute when you trust an unfamiliar repository—without running the repo's code."** Link the tiny non-executing demo and disclose first-hop limitations. Share once in each relevant community only when authenticated and within its guidelines; don't solicit fake stars.

## v0.4.1 current release and launch materials

- **Published tag:** [ClonePeek v0.4.1](https://github.com/harshitethic/clonepeek/releases/tag/v0.4.1), with wheel and source archive.
- **Live announcement:** [ClonePeek v0.4.1: what runs inside an npm or coding-agent hook?](https://github.com/harshitethic/clonepeek/discussions/11)
- **Reproducible demo:** `clonepeek examples/indirect-script` reports a risky command in the referenced `scripts/setup.sh:4` and links back to npm's `postinstall` event. The example never executes any script.
- **Patch fix:** `--changed-since HEAD` inspects tracked changed, explicitly referenced `.sh` files even when the parent config is unchanged. Dynamic and untracked references remain unsupported.
- **Quality gates:** 55 unit tests and the six-matrix Linux/macOS/Windows CI jobs passed; both relevant main-branch workflow runs completed successfully.
- **Actual adoption:** Last public check still showed **0 stars and 0 forks**. Do not represent own release/announcement activity as genuine adoption.

**Show HN update:** "Show HN: ClonePeek – inspect shell scripts triggered by npm and AI-agent hooks". Explain the exact read-only semantics and the known blind spots, not a vague malware-detection claim. Link to the v0.4.1 tag and the concrete demo.

**External posting status:** A prior Hacker News submission attempt was blocked by login, and DEV redirected to authentication. Neither external submission has been verified as posted. These are prepared materials, not evidence of external traffic.

## v0.3.0 announcement proof and current angle

- **GitHub announcement (posted):** https://github.com/harshitethic/clonepeek/discussions/8
- **Public release (posted):** https://github.com/harshitethic/clonepeek/releases/tag/v0.3.0
- **Demo:** [real CLI output](../assets/demo-output.txt), [rendered terminal preview](../assets/terminal-demo.svg), and `examples/agent-hooks` in source.
- **Independent-format smoke test (completed):** The public `cursor/cookbook` hook config yielded seven medium command-hook entries; [method and checksum](REAL-WORLD-VALIDATION.md).
- **Cross-platform CI (passed):** 43 unit tests, matrix of Ubuntu, Windows and macOS with Python 3.10/3.13.
- **User adoption (not established):** a public GitHub project does not imply stars, forks, followers, a Trending ranking or verified real-world threat-detection performance.

**Suggested Show HN title:** Show HN: ClonePeek – see what commands run when opening a repo or starting an AI agent

**Relevant framing:** A repository can contain benign or dangerous code that fires on lifecycle events rather than a deliberate `run` command. The demonstration inventories `.cursor/hooks.json`, `.claude/settings.json`, VS Code folder-open tasks, npm lifecycle entries and other activation surfaces without executing them. The code is open-source and installable with `uvx`. The relevant question is whether the inventory is accurate, not whether a heuristic can call a repo malicious. Share the known misses and request concrete harmless reproductions.

**Suggested Reddit framing:** Ask a developer-security community which *unexpected first-run code execution trigger* they have encountered; show the actual CLI finding and link the source only where community rules allow project self-promotion. Do not cross-post identical promotional copy or request stars.

**Suggested technical article framing:** Reproduce a Cursor project-hook setup using the official Cursor cookbook file and scan it offline, then show the known limitations. An article written for DEV should contribute substantial independent technical substance and comply with its disclosure and AI-assistance guidelines rather than act as a product backlink.

## Show HN draft

**Title:** Show HN: ClonePeek – find hidden commands before opening an unfamiliar repo

I built ClonePeek after looking at attacks that use seemingly routine repository configuration to run code when a developer opens a folder or installs dependencies.

It is a small Python CLI with no runtime dependencies. Point it at a local source tree and it looks for VS Code folder-open tasks, npm lifecycle hooks, devcontainers, Cursor and Claude Code command hooks, and local MCP process launch configs. It does not run any of those commands or send your source to a server. The output explains which trigger can run the command, shows evidence, and suggests what to review.

Try it with the deliberately suspicious sample:

```bash
uvx --from git+https://github.com/harshitethic/clonepeek@v0.3.0 clonepeek /path/to/repo
```

It can emit JSON or SARIF for automation. I intentionally kept v0.1 scope narrow and the threat model explicit: no transitive shell-script analysis or guarantees that a repository is safe. I would appreciate real-world examples that cause false positives and recommendations for the next execution surface worth modeling.

Repo: https://github.com/harshitethic/clonepeek

## Dev.to draft

**Title:** Before opening that GitHub repo, check what it might run

**Suggested tags:** security, opensource, python, devtools

The surprising part of using unfamiliar open-source code is that *running a command* isn't the only way for execution to start. Editor automation, package lifecycle hooks, development containers, and AI-agent tooling all have configuration-based entry points. A legitimate project might use these productively; a malicious project can abuse them.

ClonePeek does a **read-only inventory** of these entry points. It prints the responsible file, activation trigger, suspicious command evidence and a review action. The first version is dependency-light, runs locally, and offers JSON and SARIF for CI.

**Demo:**

```bash
git clone https://github.com/harshitethic/clonepeek.git
cd clonepeek
PYTHONPATH=src python -m clonepeek examples/suspicious
```

The example contains a non-resolving `.invalid` URL and is never executed by the scanner.

The limitation matters: static pattern recognition is not proof that code is malicious, or that unflagged code is safe. It won't inspect every shell script your project might call.

Repository: https://github.com/harshitethic/clonepeek

**Question:** Which repository execution surfaces have surprised you most, and what should be covered next?

## Reddit draft (only after reading subreddit rules)

**Title:** I made a local CLI that inventories hidden run-on-open / install commands in GitHub repositories

I wanted a quick way to review unfamiliar repos *before* opening them in my editor. I wrote ClonePeek, a stdlib-only Python CLI that statically checks VS Code folder-open tasks, npm lifecycle scripts, devcontainer commands and local MCP-server process settings. It reports file/trigger/command evidence and can emit JSON or SARIF. No telemetry and it never executes the repo.

It is an alpha with published tests and explicit false-negative limitations, not an AV replacement. There is a deliberately suspicious example you can run offline. I'd love precise false-positive reports or interesting benign fixtures.

Source + demo: https://github.com/harshitethic/clonepeek

**Moderation:** do not post to unrelated subreddits; respect self-promotion limits; do not repost identical messages across multiple communities. Start with one relevant community where tools are welcome and actually answer comments.

## GitHub announcement / pinned issue draft

**Title:** ClonePeek v0.1: help validate real-world execution triggers

The current v0.3.0 release covers editor folder-open tasks, npm lifecycle scripts, devcontainer lifecycle hooks/features, Cursor and Claude Code hooks, and local MCP launch configurations. Tests run on Linux, macOS and Windows, Python 3.10 and 3.13. Please try it on a repository you are comfortable reviewing and report missed triggers, reproducible false positives, and cross-platform fixture cases. Do not submit secrets or live malicious endpoints.

## Adoption checklist

1. Verify public installation and matrix CI; preserve stable output fixtures.
2. Publish a signed or clearly identified tag/release **only after checks** and upload matching source and wheel artifacts.
3. Record a real terminal screencast (< 45 seconds) or authentic asciinema output; avoid mocked claims.
4. Submit Show HN **once**, only when the demo and link actually work; participate in discussion.
5. Publish a useful explanatory Dev.to article and a context-appropriate community post (if permitted), not duplicate marketing copy.
6. Label concrete good-first-issues after reproducing a bug or documenting a genuinely useful feature.
7. Track verified weekly GitHub stars, forks, unique external issues and README-to-install feedback; adjust based on adoption rather than artificial metrics.

## Near-term engineering gates

- Coverage: add fixtures for Windows shell quoting, suspicious commands embedded in structured values, and benign install scripts.
- Correctness: benchmark on a manually labeled corpus and report actual false-positive/false-negative rates.
- Security: audit JSONC parsing, exception/report behavior, max-size and symlink defenses, and whether any input could lead to code execution.
- Workflow: add versioned snapshots for text/JSON/SARIF and a separate release workflow with least-privilege permissions.
- Documentation: show the before/after reviewer workflow, add FAQ for why warnings can be benign, and expose compatibility notes.
