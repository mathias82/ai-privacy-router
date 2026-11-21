# Hushavyr — Private AI Code Review & Security Scanner for VS Code

[![VS Marketplace](https://img.shields.io/visual-studio-marketplace/v/mathias82.hushavyr?label=VS%20Marketplace)](https://marketplace.visualstudio.com/items?itemName=mathias82.hushavyr)
[![Installs](https://img.shields.io/visual-studio-marketplace/i/mathias82.hushavyr)](https://marketplace.visualstudio.com/items?itemName=mathias82.hushavyr)
[![Rating](https://img.shields.io/visual-studio-marketplace/r/mathias82.hushavyr)](https://marketplace.visualstudio.com/items?itemName=mathias82.hushavyr&ssr=false#review-details)
[![CI](https://github.com/mathias82/Hushavyr/actions/workflows/ci.yml/badge.svg)](https://github.com/mathias82/Hushavyr/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Hushavyr is a **free, local AI code reviewer** and **security scanner** for VS Code. It runs **on your machine** with Ollama. It finds bugs, security vulnerabilities (OWASP Top 10, SQL injection, XSS, command injection), hardcoded secrets and vulnerable dependencies (CVEs). It can prove a fix with a failing test and open the pull request. Your code never goes to a cloud model.

**Works with:** Java, Kotlin, Python, JavaScript, TypeScript, Go, Rust, C#, PHP and Ruby.

## Why Hushavyr?

**Hushavyr** is a coined name built around **“hush”** — the idea of keeping something quiet, confidential, and protected. **“-avyr”** is a distinctive invented ending, not a word with an established dictionary meaning.

The name expresses the project's privacy-first philosophy: review and improve code locally, keep sensitive information under your control, and require explicit approval before sharing anything externally.

> **Private AI. Verified Code.**  
> *Your code stays yours.*

This is a brand interpretation, not a literal translation of an existing word.

## Install

1. Install **Hushavyr** from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=mathias82.hushavyr).
2. Run **Hushavyr: Setup** from the Command Palette. It installs or downloads Ollama, a local model and, if you agree, Semgrep, Gitleaks, Trivy, OSV-Scanner and, for the languages in your project, FindSecBugs, Bandit and gosec. Nothing is installed without asking you.
3. Open a project and type `@ai-privacy /review` in Chat.

## What it uses

All of these run on your machine. Setup installs the optional tools only if you agree.

| Tool | What it does in Hushavyr | Needed for |
| --- | --- | --- |
| [Ollama](https://ollama.com) + Qwen coder models | Local AI review, explanations, edits and fixes | `/review`, `/explain`, `/edit`, `/improve`, `/scan` |
| Built-in rules and data-flow tracking | Security rules for Java, Python, JS/TS, Go, Rust, C#, PHP and Ruby. Data-flow tracking follows request input to SQL, shell, eval, file and URL calls. No model needed | `/security`, `/scan`, CLI |
| Built-in secrets scanner | Hardcoded passwords, keys and tokens (values are hidden) | `/secrets`, `/scan`, `/pr` |
| [Semgrep](https://semgrep.dev) (optional) | Extra rules from the bundled Hushavyr rule pack | `/security`, `/scan`, CLI |
| [Gitleaks](https://github.com/gitleaks/gitleaks) (optional) | Secret detection; also blocks credentials before `/pr` | `/gitleaks`, `/scan`, `/pr` |
| [Trivy](https://trivy.dev) (optional) | CVEs in dependencies, plus checks whether your code calls the vulnerable function; SBOM export | `/dependencies`, `/scan` |
| [OSV-Scanner](https://google.github.io/osv-scanner/) (optional) | More dependency CVEs from a downloaded OSV.dev database; runs with `--offline`. A CVE Trivy already reports is shown once | `/dependencies`, `/scan`, CLI |
| [FindSecBugs](https://find-sec-bugs.github.io) on [SpotBugs](https://spotbugs.github.io) (optional) | Security bugs in compiled Java/Kotlin classes (`target/classes`, `build/classes/*/main`), mapped back to the source line | `/security`, `/scan`, CLI |
| [Bandit](https://bandit.readthedocs.io) (optional) | Python security checks; only medium/high severity and confidence, no `assert` or test findings | `/security`, `/scan`, CLI |
| [gosec](https://github.com/securego/gosec) (optional) | Go security checks for Go modules; no unchecked-error (G104) or test findings | `/security`, `/scan`, CLI |
| [Docker](https://www.docker.com) (optional) | Offline sandbox with no network that proves a fix: the test fails before the fix and passes after. Supports Java/Maven, Python/pytest, JS/TS and Go | **Prove with a failing test**, verified fix → PR |
| [GitHub CLI](https://cli.github.com) `gh` (optional) | Opens the pull request | `/pr`, `/improve` |
| VS Code Chat + Copilot (opt-in only) | Gets only the pseudonymized selection, and only after you approve | `/escalate`, `/auto` |

Output is SARIF 2.1.0, so GitHub code scanning and any other SARIF viewer can read it.

## Models and memory

Setup picks the model for your machine; you can change it in the `aiPrivacyRouter.ollamaModel` setting.

| Memory | Default model | Notes |
| --- | --- | --- |
| under 20 GB | `qwen2.5-coder:7b` | Fast; finds the obvious issues. Use `reviewDepth: fast` on 8 GB machines. |
| 20–30 GB | `qwen2.5-coder:14b` | Better reviews, slower. |
| 30 GB or more | `qwen3-coder:30b` | Best reviews. A mixture-of-experts model (about 3B active parameters), so it is faster than the 14b. |

**Hushavyr: Start Ollama** turns on flash attention and an 8-bit KV cache, which roughly halves context memory. The deterministic commands (`/security`, `/secrets`, `/dependencies`) need no model at all, `/review` results are cached, and `/scan-changed` skips files that did not change.

## Commands

Type `@ai-privacy` in VS Code Chat, then one of these commands:

| Command | What it does |
| --- | --- |
| `/review` | Finds bugs and security issues in the open file, and checks your team rules |
| `/explain` | Explains the open or selected code |
| `/edit` | Changes the open or selected code with the local model. Follow-ups like *"can you add them"* after `/explain` also work. You see a diff and nothing changes until you click **Apply**. You can also **Try another local model** or **Escalate** (opt-in, names removed). |
| `/improve` | Asks the local model for real improvements to the open file (bugs, safety, clarity), shows a diff and a summary, and after **Apply** offers to open a pull request |
| `/pr` | Commits your changes to a new branch, pushes it and opens a pull request (`gh`, or a GitHub link). Asks first and stops if it finds credentials. |
| `/review-changes` | Reviews your uncommitted changes |
| `/scan` | Reviews the whole project: AI, Semgrep, Gitleaks, the optional analyzers, built-in rules, data flow and CVEs |
| `/scan-changed` | Same as `/scan`, but only for files that changed since the last scan |
| `/security` | Fast project security scan without AI: rules, credentials, and request input that reaches SQL, shell, eval, files or URLs |
| `/secrets` · `/gitleaks` | Finds hardcoded passwords and keys (values are hidden) |
| `/dependencies` | Finds CVEs with Trivy and OSV-Scanner and shows whether your code calls the vulnerable function |
| `/test` | Runs the project tests |
| `/auto` | Sends a typed question that contains no code to the right model |
| `/escalate` | *Opt-in.* Sends only the selected function to a Copilot model, with names removed and after you approve it (see below) |

Quick fixes on findings:
- **Propose a local fix:** shows a diff, and nothing changes until you approve it.
- **Prove with a failing test:** runs a generated test in an offline Docker container (Java/Maven, Python/pytest, JavaScript/TypeScript, Go). The bug counts as confirmed only if that test fails.
- **Not a real issue:** hides the finding for the whole team.

## Team files (commit them)

| File | Purpose |
| --- | --- |
| `.hushavyr/rules.md` | Your team standards, e.g. "never log tokens". `/review` checks the code against them. |
| `.hushavyr/dismissed.json` | False positives hidden for everyone. Created by the *Not a real issue* quick fix. |
| `.hushavyr/ignore` | Paths that are never scanned, one per line (`src/test/`, `*.gen.ts`). Use it for intentionally vulnerable test fixtures. |

## CI

- **Project scan:** run `node dist/cli.js . --sarif hushavyr.sarif --fail-on high` and upload the SARIF to GitHub code scanning. See `.github/workflows/hushavyr-scan.yml`.
- **Benchmark:** results of the CLI scan on the public OWASP Benchmark for Java are in [docs/owasp-benchmark.md](docs/owasp-benchmark.md).
- **PR review:** copy `examples/hushavyr-pr-review.yml` into your workflows. It runs on a self-hosted runner with Ollama, reviews only the changed lines and comments on the PR.

## Hushavyr compared with cloud AI review

| | Hushavyr | Typical cloud AI code review |
| --- | --- | --- |
| Where your code goes | Stays on your machine (Ollama) | Sent to the vendor's servers |
| Price | Free, MIT licensed | Usually a subscription per seat |
| Works offline / air-gapped | Yes | No |
| Security scan without AI (rules, data flow, secrets, CVEs) | Yes | Varies |
| Proves a fix with a failing test | Yes, in an offline Docker sandbox | Rarely |
| Output for CI | SARIF, CLI exit codes, PR comments | Varies |

## FAQ

**Is Hushavyr a free GitHub Copilot alternative for code review?**
Yes, for code review and security. It works in the VS Code Chat as `@ai-privacy`, but the model runs locally with Ollama, so it is free and private. It does not replace Copilot's inline completions.

**Does my code leave my computer?**
No. Review, scanning and fixes run locally, and there is no telemetry. Only the opt-in `/escalate` sends anything: a selection with names replaced by tokens, and only after you approve the exact text.

**Which model should I use?**
Setup picks one for your RAM: `qwen2.5-coder:7b` under 20 GB, `14b` for 20–30 GB, and `qwen3-coder:30b` from 30 GB up. See [Models and memory](#models-and-memory).

**Can I use it without AI?**
Yes. `/security`, `/secrets` and `/dependencies` are deterministic and need no model. The `hushavyr-scan` CLI runs the same checks in CI and writes SARIF for GitHub code scanning.

**How accurate is it?**
On our synthetic benchmark the built-in rules find every planted issue with no false alarms. On the external [OWASP Benchmark for Java](docs/owasp-benchmark.md) we publish the full score per category. Findings are potential issues; check them before acting.

**Does it work in Cursor, VSCodium or Windsurf?**
The `@ai-privacy` chat commands need the VS Code Chat API (VS Code 1.90 or later), which other editors may not support. The Command Palette commands and the `hushavyr-scan` CLI work everywhere.

## Privacy

- Review and scanning run only on your machine. There is no automatic cloud fallback.
- `/escalate` is off unless you turn on `aiPrivacyRouter.cloudEscalation`. When it is on:
  - It sends only the selection, up to 4,000 characters.
  - Names, strings and comments are replaced with tokens such as `id1` or `s1`. The mapping stays on your machine.
  - It is blocked for secrets, personal data, `.env`/key files, ignored files and local-only workspaces.
  - You see the exact text before anything is sent, and every send is written to a local audit log.
  - The answer is a suggestion: verify it locally.
- Findings are potential issues. Check them before acting.
- No telemetry. **Hushavyr: Report an Issue** shows a redacted report (versions, OS, settings without endpoints or paths) and opens a GitHub issue only if you click it.

More details are in the [user guide](docs/guide.md). The stable API and versioning policy is in [docs/stability.md](docs/stability.md).

**Author:** Matthaios Stavrou · [GitHub](https://github.com/mathias82/Hushavyr)
