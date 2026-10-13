# Opportunity research · October 14, 2026

Goal: a real developer problem with a quick demonstration, low setup cost and feasible independent engineering. These are subjective **comparative product scores**, not measured market forecasts; greater numbers are better. `/5` on usefulness (U), distinctiveness (D), adoption friction (A, 5 = very low), feasibility for focused v0.1 (F), and sharing potential (S). Security research references follow the table.

| Idea | U | D | A | F | S | Total /25 | Decision |
|---|---:|---:|---:|---:|---:|---:|---|
| Scan first-run repo execution surfaces | 5 | 4 | 5 | 5 | 4 | **23** | **Build** |
| AI agent skill injection scanner | 5 | 2 | 4 | 4 | 5 | 20 | Crowded with Snyk Agent Scan / SkillGuard |
| Cross-platform `.env` drift checker | 4 | 2 | 5 | 5 | 3 | 19 | Existing dotenv drift tools |
| Local-first API record/replay | 5 | 2 | 3 | 3 | 4 | 17 | VCR and existing mock tooling |
| Agent session context packer | 4 | 1 | 5 | 4 | 5 | 19 | Competes with Repomix and Gitingest |
| GitHub workflow security checker | 5 | 1 | 4 | 4 | 3 | 17 | zizmor / actionlint coverage |
| One-command sanitized bug report | 4 | 3 | 4 | 4 | 4 | 19 | Useful, difficult guaranteed redaction |
| Git diff-to-test impact graph | 5 | 3 | 3 | 2 | 4 | 17 | High parser/monorepo complexity |
| Local dev-port ownership debugger | 4 | 2 | 5 | 4 | 3 | 18 | Lots of competing process tools |
| Dependency-license policy CLI | 4 | 2 | 3 | 4 | 2 | 15 | Mature ecosystem tools |
| Docs/API drift detector | 4 | 3 | 3 | 3 | 3 | 16 | Needs language-specific parse support |
| Agent tool permissions diff viewer | 5 | 3 | 3 | 3 | 4 | 18 | Attractive v0.2 expansion candidate |

## Evidence and decision

- GitHub Trending showed continued developer attention on agent-oriented tools and productivity layers: https://github.com/trending (dynamic ranking).
- Microsoft reported malicious developer-targeting Next.js repos using workspace execution paths: https://www.microsoft.com/en-us/security/blog/2026/02/24/c2-developer-targeting-campaign/
- VS Code issue documents `runOn: folderOpen` abuse: https://github.com/microsoft/vscode/issues/309406
- BindsNET advisory details editor-open execution: https://github.com/BindsNET/bindsnet/security/advisories/GHSA-6f2q-w3r8-xxhj
- Existing agent/security competitors: https://github.com/snyk/agent-scan , https://github.com/buzzicra/skillguard , https://github.com/zizmorcore/zizmor
- Existing broad security orchestration: https://github.com/lapointelabs/tripwire

Selection rationale: rather than clone broad scanners, answer one concrete question fast — **which configuration-based execution triggers exist before opening, installing, or connecting an agent to this repo?** Focus on transparent evidence and deterministic offline results. No claim of exclusive novelty or unverified demand.

## Roadmap, ordered by value

1. Capture representative legitimate/malicious fixtures; document per-rule false positives and false negatives.
2. Add GitHub Actions + shell hooks **with trigger semantics**, not a generic malware verdict.
3. Identify indirect script chains without executing any scripts.
4. Provide stable editor annotations and richer review commands.
5. Publish reproducible wheels from release tags, benchmark precision/recall against a versioned corpus.
6. Gather actual developer feedback before expanding rule categories.

Organic launch: one real demo on Show HN, a transparent comparison with broad scanners, and reproducible examples for security/devtools communities. **Do not mass-post, buy stars, fabricate benchmarks or claim that a scanner makes a repo safe.**
