# ClonePeek launch kit

**Status:** source repository public; GitHub release/tag, community submissions, traction, and external security validation are independent milestones. Do not claim them until verified. This file contains drafts, not evidence that a post was submitted.

## Positioning

**Name:** ClonePeek  
**Tagline:** Know what runs before you open a repo.  
**One-liner:** An offline, dependency-light CLI that inventories configuration-based execution paths in unfamiliar repositories—before you open them in an editor, install packages, or connect an AI agent.

**Audience:** developers who clone unknown repositories, open-source maintainers, security reviewers, hackathon participants, and users of coding agents.

**Differentiator:** Explain **trigger → command → evidence → review action**. ClonePeek is not a malware scanner, sandbox, provenance system, or replacement for in-depth security review.

## Show HN draft

**Title:** Show HN: ClonePeek – find hidden commands before opening an unfamiliar repo

I built ClonePeek after looking at attacks that use seemingly routine repository configuration to run code when a developer opens a folder or installs dependencies.

It is a small Python CLI with no runtime dependencies. Point it at a local source tree and it looks for VS Code folder-open tasks, npm lifecycle hooks, devcontainer lifecycle commands/features, and local MCP process launch configs. It does not run any of those commands or send your source to a server. The output explains which trigger can run the command, shows evidence, and suggests what to review.

Try it with the deliberately suspicious sample:

```bash
uvx --from git+https://github.com/harshitethic/clonepeek clonepeek /path/to/repo
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

The first release candidate covers editor folder-open tasks, npm lifecycle scripts, devcontainer lifecycle hooks/features and local MCP launch configurations. Tests run on Linux, macOS and Windows, Python 3.10 and 3.13. Please try it on a repository you are comfortable reviewing and report missed triggers, reproducible false positives, and cross-platform fixture cases. Do not submit secrets or live malicious endpoints.

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
