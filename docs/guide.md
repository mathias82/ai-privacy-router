# Hushavyr user guide

See the [live privacy and routing smoke test](privacy-smoke-test.md) for repeatable checks in VS Code.
For model evaluation, see the [Qwen and Sonnet review comparison](review-benchmark.md).

Hushavyr is a public preview for local-first AI assistance in VS Code. Use Ollama to review selected code or typed prompts. The optional Copilot route accepts explicitly approved public prompts from an isolated empty window.

The extension controls its own requests. For sensitive work, use a VS Code profile with independent Copilot features disabled. Live privacy checks across the router and that profile are still pending. Try the examples below with synthetic data.

Report security issues using the [security policy](../SECURITY.md).

## Principles
- Classify the entire outbound payload, not only the prompt.
- Local-only for sensitive or uncertain content.
- Never silently fall back to cloud.
- Cloud routing is disabled by default.
- Human overrides cannot bypass mandatory policy.
- No document contents or secrets in logs.

## Implementation
TypeScript classifier, local Ollama adapter, VS Code commands and tests. An optional, default-disabled Copilot route handles only explicitly reviewed public typed prompts in an isolated empty window.

## Install and smoke-test locally (macOS / VS Code)

Prerequisites: Node.js 22, VS Code 1.90+, and Ollama running **on the same machine as the VS Code extension host**.

```bash
git clone https://github.com/mathias82/Hushavyr.git
cd Hushavyr
npm ci
npm test
ollama pull qwen2.5-coder:7b
ollama serve  # only if Ollama is not already running
```

In another terminal:

```bash
npm run package:vsix -- --out hushavyr-0.0.10.vsix
code --install-extension hushavyr-0.0.10.vsix
```

Reload VS Code. Open a text file, select some text, open the Command Palette and run **Hushavyr: Ask Local Qwen About Selection**. Enter a short instruction and check that a Markdown answer opens. Also run **Hushavyr: Classify Selection** and **Hushavyr: Review Cloud Override (No Transfer)**.

For a negative test, stop Ollama and repeat the local command. It must show a local error, **not** fall back to a cloud model.

The Ollama endpoint defaults to `127.0.0.1:11434` and can be changed to another loopback HTTP origin with `aiPrivacyRouter.ollamaEndpoint`; in Remote SSH, containers, or WSL, this refers to the extension host, not necessarily your laptop. The default model can be changed in VS Code Settings under `aiPrivacyRouter.ollamaModel`.

**Important limitations:** Privacy detection is heuristic; no content is certified safe for cloud use. The override UI is a **review-only prototype**; it records local audit metadata but does not send anything to Sonnet. The VSIX is a preview package for manual installation. Do not test with actual company secrets or production personal data until the extension has been independently reviewed.


## Update an existing checkout safely

After this updater is present, run from the repository:

```bash
npm run update:local
npm ci --ignore-scripts
npm test
npm run package:vsix -- --out hushavyr-0.0.10.vsix
code --install-extension hushavyr-0.0.10.vsix --force
```

The updater fetches `origin/main`, requires a clean tracked working tree on `main`, and only fast-forwards. Colliding untracked files, including ignored files, move into a unique private backup directory under the repository's Git directory before the update. Unrelated untracked files stay in place. The printed backup path is outside the packaged working tree. No reset, clean, forced checkout, stash, commit or push is performed.

It stops for local commits that cannot fast-forward, tracked edits, another branch, or an in-progress merge/rebase/cherry-pick/revert. If an update fails before HEAD changes, it attempts to restore moved files to unoccupied original paths; otherwise backups remain at the reported location. Do not run another Git operation concurrently.

### First upgrade from a checkout without the updater

An old locally generated `package-lock.json` can prevent Git from adopting the newly tracked lockfile. Run this from the repository to preserve that specific file before pulling:

```bash
(
set -e
if [ -e package-lock.json ] && ! git ls-files --error-unmatch -- package-lock.json >/dev/null 2>&1; then
  backup_dir="$(mktemp -d "${TMPDIR:-/tmp}/hushavyr-lock.XXXXXX")"
  mv package-lock.json "$backup_dir/package-lock.json"
  printf 'Saved local lockfile: %s\n' "$backup_dir/package-lock.json"
fi
git pull --ff-only origin main
)
```

Stop if Git reports any other conflict or local edits; do not discard them. After a successful pull, use `npm ci --ignore-scripts`, then test, package, install the VSIX and reload VS Code. Previous in-repository `package-lock.local.*.bak` backups are now excluded from Git and VSIX packaging, but are not deleted. The tracked lockfile remains versioned for reproducible CI.

## One-command local AI startup (macOS)

After installing Ollama with `brew install ollama`, run from this repository:

```bash
npm run ai:start
```

This starts the local Ollama server if needed, downloads `qwen2.5-coder:7b` only if missing, and opens an interactive Qwen session. Type `/bye` to exit the chat; the server remains available to the VS Code extension.

To start the server and ensure the model is installed **without** opening an interactive session:

```bash
npm run ai:serve
```

You can override the model using `OLLAMA_MODEL=other-model npm run ai:start`. Keep the VS Code `aiPrivacyRouter.ollamaModel` setting consistent. The script contacts only the local Ollama endpoint, except that `ollama pull` downloads a missing model. Do not start a second server if one is already running.

## Local Qwen in VS Code Chat

Run `npm run ai:serve`, select code in an editor, open VS Code Chat and enter `@ai-privacy Find bugs in the selected Java code`. The `@ai-privacy` participant uses local Ollama and reports structured review findings in the Chat panel. Its ordinary requests stay local; the optional `/auto` public-prompt workflow below is the only Copilot route. If selection is not available, select the code again. Note: the last non-empty selection may be reused when switching focus; verify the selection before sending a new question.

### Sticky Chat mode

Use `@ai-privacy` once to select the local assistant. It is marked sticky, so subsequent turns in the same Chat conversation stay with this participant unless you switch agents. Use `/review` while this participant is active for code review. The configured local model defaults to `qwen2.5-coder:7b` via `aiPrivacyRouter.ollamaModel` and persists in VS Code Settings. VS Code does not expose this local Ollama model as a Copilot model-picker entry; `/ai-privacy` is not a global Chat slash command. Use `@ai-privacy` for the participant and `/review` for its command.


## Ollama / Copilot routing (0.0.4)

Default mode remains **local-only**. Use `@ai-privacy /auto <typed prompt>`, or **Hushavyr: Route Typed Prompt (Local by Default)**. Ordinary Chat, `/review`, selected-file commands and attached-source review remain local.

The router first checks privacy policy, then task complexity. Known sensitive patterns, uncertain project/file context, untrusted workspaces, mandatory-local policy and required-but-unavailable reviewer approval stay local. A simple typed task stays on Ollama. A complex typed prompt is only a **Copilot candidate**, not automatically classified public.

Copilot eligibility requires all of the following:
- Application setting `aiPrivacyRouter.routingMode` explicitly set to `hybrid-public-prompts`.
- A trusted empty window, no workspace folders and no open file/untitled documents. Internal Chat/output buffers are not included in requests.
- No attached context: attachments use the existing local path.
- A supported model selected through the official VS Code Copilot Language Model API.
- Per-request approval that every part of the exact payload is public and authorized for external processing.

The router never treats absence of a regex match as proof of public content. Without explicit public approval, no cloud prompt is sent. The full immutable payload is shown in an escaped, read-only webview with scripts, commands and resource access disabled. It is not opened as a source text document for inline completion. Close the preview or dismiss the notification to deny sending. Model discovery may request VS Code's normal Copilot consent; it receives no prompt from this extension.

Only that approved string is sent as one user message. No editor content, cached selection, Chat history, workspace search, tools, retrieval, or test output is appended. The actual model ID is hashed for metadata-only audit. Approval and attempted-dispatch records must succeed before sending. Policy, isolation and cancellation are rechecked before dispatch. Opening a project/file or enabling mandatory-local policy during approval prevents sending. No failed Ollama request silently falls back to Copilot; failed Copilot requests are not automatically retried on another provider. Copilot answers are model output, not executed tests or applied patches.

### Two-profile setup

These settings are templates, not automatically applied. Nothing in this PR changes the user's VS Code or account settings.

1. **Sensitive work profile:** disable the Copilot extensions in that profile. Copy [local-only settings](../profiles/local-only.settings.json) into its user settings and use the standalone **Ask Local Qwen** / **Ask Local Qwen About Selection** commands. Disabling built-in AI hides Chat, so `@ai-privacy` will not be available there; standalone local commands still register.
2. **Public-prompt profile/window:** enable Copilot in a separate empty window, with no project or documents open. The [public-prompt settings](../profiles/public-prompts.settings.json) disable inline and next-edit suggestions while allowing Chat.
3. In **Preferences: Open Application Settings (JSON)**, explicitly configure:
```json
{"aiPrivacyRouter.routingMode": "hybrid-public-prompts"}
```
Application-scoped settings apply across profiles. The independent empty-window and disabled-AI guards keep private/project windows local even when this global mode is enabled. Setting `aiPrivacyRouter.mandatoryLocalOnly` to `true` disables every cloud route through this extension across profiles.
4. Use `/auto` for a typed public question. Complex tasks offer the model picker and exact-payload approval; simple tasks use Ollama.

**Boundary:** this extension controls its own requests only. It cannot intercept independent Copilot Chat, completions, other extensions, tools or operating-system network traffic. Pattern checks and public-content attestation are not complete DLP or a universal no-exfiltration guarantee. Keep Copilot disabled in the sensitive profile; organizational/OS isolation is needed when a hard cross-application boundary is required.

Public-only smoke test: after installing 0.0.4, verify default local mode, synthetic secret routing, no model discovery in a project window, public preview cancellation, exact approved payload, and model/account/quota failures. Use no actual secrets for the test. No real Copilot request or local runtime test was executed while authoring this change.

## Evidence-gated local code review

Use `@ai-privacy /review check code for bugs`. Attach up to **8 local files**, with **20 KB total** across instruction, paths and source. Alternatively select code or use the focused file. The extension never scans the workspace automatically. Unreadable context or exceeded budgets stop the request rather than silently dropping source.

The reviewer receives numbered source lines and returns file paths plus inclusive line ranges. The extension extracts the actual source text itself, avoiding JSON escaping errors when the Java code contains quotes or backslashes. Selections retain their original file line numbers. Paths and ranges must belong to supplied sources. Legacy exact-evidence responses still pass the original source-match checks.

If parsing fails or all findings are rejected, one bounded repair request receives the validator's reasons. A separate skeptical local pass then checks accepted findings against the supplied files. It may reject unsupported claims. If the second pass fails, results are explicitly unverified. The same model serves both passes by default; `aiPrivacyRouter.verifierModel` can select a different installed local model. Two prompts to the same model are not independent runtime proof. Maximum: review + repair + verifier, all loopback.

Every finding remains **potential**. Neither model agreement nor a successful existing suite proves an individual bug or fix. No generated tests or patches are applied automatically. Source matching and the SQL/getter filters are heuristics, not formal verification or complete DLP.


## Local Java regression-proof agent (0.0.5)

Choose **JavaScript / Node.js** for projects with an existing `node:test` suite. Preload `node:24-slim` outside the verifier. Select one to six tracked `.js`, `.cjs` or `.mjs` production files. Generated tests use CommonJS and the built-in Node test runner. This profile uses Node's default test discovery and does not install dependencies or run package scripts. Use a project whose suite can run from the committed snapshot in the selected image.

Choose **TypeScript / Node.js** for projects with a tracked `tsconfig.json` and a native Node test suite. Set `aiPrivacyRouter.fixTypeScriptImage` to a preloaded Node.js 24 image with `tsc` and any required dependencies. Each stage first runs `tsc --project tsconfig.json --noEmit --incremental false`. Node then runs tests with its built-in TypeScript support. Use syntax that works with Node's type stripping, explicit import extensions, and a configuration that can type-check without writes. A compiler failure cannot serve as regression evidence.

For Python projects, select **Python / pytest**. Use a committed project with an existing `tests/` directory and select one to six tracked production `.py` files. Set `aiPrivacyRouter.fixPythonImage` to a preloaded local image containing Python, pytest and the project dependencies. The default image name is `hushavyr-pytest:local`. The verifier uses a fixed pytest command, disables plugin autoload, and runs with networking disabled. Projects that require plugins, live services or writing to the checkout need a compatible offline test setup.

The Python verifier checks that the existing suite passes, the approved generated test fails on an assertion, the same test passes after the fix, and the full suite still passes. Import, collection and runtime errors cannot establish a regression. The command writes the same patch and receipt artifacts as the Maven profile.

For Go modules, select **Go / go test**:

- **Project:** choose a folder with a tracked `go.mod`, then one to six tracked production `.go` files. Test files and `vendor/` or `testdata/` paths can't be selected.
- **Image:** set `aiPrivacyRouter.fixGoImage` (default `golang:1.24`) to a preloaded image with a Go toolchain that matches your module.
- **Dependencies:**
  - Vendored dependencies work as they are.
  - Other dependencies come from the local module cache, `~/go/pkg/mod`, or from `aiPrivacyRouter.fixGoModCache`. The cache is mounted read-only.
  - `GOPROXY=off`, `GOFLAGS=-mod=readonly`, `GOTOOLCHAIN=local` and `CGO_ENABLED=0` are set, and the network is disabled, so nothing is downloaded.
- **Generated test:** a single `TestHushavyr…(t *testing.T)` in the same package. It must not import `"C"`.
- **Evidence:** the proof records only `t.Errorf`/`t.Fatalf` failures of that test. Build failures and panics are treated as errors and can't prove a regression.

Run **Hushavyr: Propose and Verify Local Fix** and choose **Java / Maven** from the Command Palette in a trusted local-only profile with `chat.disableAIFeatures: true`. This is a standalone command, so it remains available when built-in Chat/Copilot is disabled. The workflow never calls Copilot, the hybrid router, an external LLM, or a model-supplied shell command.

### What it does

1. Choose a leaf Maven project, 1–6 tracked production Java files and one observable bug description.
2. Export a bounded, consistent copy of the committed Git HEAD into a private snapshot. Staged changes, differing tracked file bytes, symlinks and submodules stop preparation. Untracked files and unsaved edits are not part of the proof; save and commit first. Git object reads are used rather than checkout hooks, smudge filters, or executing repository scripts on the host. The active checkout, index and branch are not patched or reset.
3. Run the existing selected project's suite in the offline container. A passing baseline with actual Surefire test cases is required before generating a test.
4. Local Ollama proposes one behavioral regression test in the first selected production file's package. Review its complete source before it is written into the snapshot.
5. Run that test against the original production code. Only a reported assertion failure with exit code 1 counts as reproduction. Compile errors, runtime errors, timeouts, skipped tests, missing XML or zero cases do not.
6. Ollama proposes one fix to existing selected production files only. Review all replacement source before applying it to the snapshot. POMs, dependencies, settings, other sources and tests cannot be changed by the fix. The approved regression test remains byte-for-byte frozen.
7. Rerun the same regression identities, then the complete selected project's unit-test suite. Every previously passing test and every regression case must still be reported as passing. Missing, renamed or newly skipped required cases fail acceptance.
8. Only then export `verified.patch` and a content-bound `receipt.json`. Nothing is automatically applied, committed or pushed to the active checkout.

There is one test proposal and one fix proposal per run, with at most four test executions: baseline, red, green and suite. A failed or declined stage stops the workflow. There is no autonomous retry loop or provider fallback.

### Execution boundary

Prerequisites: non-root macOS/Linux, trusted local Docker with a Unix-socket context, an already-installed Maven/JDK image, and a complete local `~/.m2/repository` cache. `aiPrivacyRouter.fixMavenImage` defaults to `maven:3.9-eclipse-temurin-21`; choose a JDK compatible with the project. The image is resolved to its immutable local ID and never pulled by the agent. The Maven repository is privately copied (copy-on-write where supported), hashed, and mounted read-only so concurrent host builds cannot change dependencies between red and green. The host cache is never mounted into the test container or modified.

The container has no network, no added capabilities, no new privileges, a read-only root and source tree, a read-only Maven cache, and a non-root UID. Only the selected project's generated `target` and a bounded private `/tmp` are writable. Host home, Maven settings, credentials, SSH keys and Docker socket are not mounted. Maven runs offline with fixed arguments; stdout/stderr is not persisted or supplied to a model. Docker container logging is disabled. Timeout/cancellation stops the attach process and forcibly removes the named container/anonymous volumes; uncertain cleanup prevents normal snapshot deletion and requires attention.

The first version supports standard Surefire XML reports for a standalone or leaf Maven project that builds without host Git metadata. Aggregators, custom output/report locations, services/network-dependent tests, filtered/LFS worktrees and symlink/submodule repositories may be declined rather than weakened into an unverified pass. Each test stage is limited to two minutes, two CPUs, 4 GB memory and 256 processes.

Bounds: at most 10,000 tracked files, 64 MB total exported bytes and 2 MB per file. Local model context is limited to 12 KB for the POM plus selected sources, with a 1.5 KB bug description and an 8 KB generated test. Only the POM, explicitly selected production Java files, bug description and approved regression test are supplied to the local model. The dependency-cache snapshot is limited to 4 GB, 100,000 files and 256 MB per file, with symlinks refused. Use a small prepopulated repository via `aiPrivacyRouter.fixMavenCache` if the default cache exceeds these bounds.

### Receipts and artifacts

Private per-run directories under the extension's `verified-fixes` storage contain metadata receipts and, when approved, the proposed test source. A verified run also contains the patch. Directories are private and files use 0600 permissions. Receipts record the base commit, image ID, dependency-snapshot hash/size, configured local model name, test-source hash, patch hash, test counts, case-set hashes, exit codes, durations and interruptions. Raw parameterized test names can contain personal data and are not persisted in receipts.

Source, dependency-cache and build snapshots are removed after the run when container cleanup succeeds. Proposal/patch artifacts contain source and can be sensitive: they stay local and are never uploaded or added to cloud context. Keep only the artifacts you need; this release has no automatic artifact retention policy. A receipt is local execution evidence for the reviewed test, not a signed attestation, a proof of all behavior, or proof that the model is superior to Sonnet.

Review `verified.patch` before applying it, and verify the active branch still matches the receipt's base commit. Re-run tests after manual application. A fresh test run in a different checkout/environment is separate evidence.

### Public smoke fixture

The intentionally buggy [Price fixture](../fixtures/java-fix/src/main/java/demo/Price.java) multiplies two ints before returning a long. Its existing small-input test passes; the large-input regression should fail before a cast is added.

First preload the chosen Docker image and populate a compatible Maven cache using your normal trusted build setup. These are explicit setup steps outside the agent; no image or dependency downloads are performed by the verifier. For the public fixture, an installed Maven/JDK 17+ can prewarm common dependencies with:

```bash
mvn -f fixtures/java-fix/pom.xml test
```

Cache/plugin versions must also match the selected container image. After the cache and image are ready:

```bash
AI_PRIVACY_DOCKER_SMOKE=1 npm test
```

The opt-in smoke test uses real Git, Docker and Surefire with handwritten proposals. It checks red/green behavior, network/source restrictions, patch applicability and preservation of original files. It is disabled in ordinary unit runs and does not measure Qwen's ability to invent the fix. You can also select the fixture folder and Price.java in the local-fix command for a live Ollama experiment.

No real Docker execution, VS Code fix UX or live model-quality measurement was performed while authoring this release. Build/tests/package verification is still required before relying on it.

## Ollama daemon must also be local-only

A loopback URL alone does not prove on-device inference: Ollama supports cloud-backed models and aliases. Before each generation the adapter now reads model metadata with `/api/show`, rejects remote host/model metadata or missing local model information, and refuses cloud-labelled model names. Inventory checks also reject remote entries. Only model metadata is requested before this gate; no prompt is included.

For the sensitive-data profile, merge [the local-only server setting](../profiles/ollama-server.local-only.json) into `~/.ollama/server.json`, preserving existing settings, and restart Ollama:

```json
{"disable_ollama_cloud": true}
```

Alternatively start a dedicated daemon with `OLLAMA_NO_CLOUD=1`. Setting a client process environment variable does not reconfigure an already-running daemon. These settings are not changed automatically by this PR. The workflow assumes a trusted local Ollama daemon; model metadata is not a defense against a malicious local proxy or compromised host. Use an OS-level network boundary when that stronger guarantee is required.

## Existing regression tests

Use `@ai-privacy /test` or **Hushavyr: Run Existing Regression Tests**. Choose a trusted workspace folder and a fixed runner: `npm test`, `mvn test`, `./mvnw test`, `gradle test`, `./gradlew test`, or `python -m pytest`.

The runner executes that project's existing scripts, with no model-supplied command, arguments or generated code. It records actual exit status, duration, timeout and cancellation. Output is not stored or sent to a model. The default timeout is two minutes. On macOS/Linux cancellation kills the runner process group; Windows only stops the immediate process and may require manual cleanup of descendants. The intended local environment is macOS/Linux.

## Local model configuration

Settings are application-scoped, so repository settings cannot relax the user's policy or redirect the provider.

| Setting | Default | Behavior |
| --- | --- | --- |
| `aiPrivacyRouter.ollamaModel` | `qwen2.5-coder:7b` | Must already be installed locally |
| `aiPrivacyRouter.ollamaEndpoint` | `http://127.0.0.1:11434` | Loopback HTTP origin only; redirects rejected; localhost canonicalized to 127.0.0.1 |
| `aiPrivacyRouter.timeoutSeconds` | 180 | Per model request |
| `aiPrivacyRouter.verifierModel` | empty | Reuses reviewer unless another local model is selected |
| `aiPrivacyRouter.fixMavenImage` | `maven:3.9-eclipse-temurin-21` | Preloaded image for offline Java regression proof; resolved to local immutable image ID |
| `aiPrivacyRouter.mandatoryLocalOnly` | false | When true, prevents all cloud routes and review-only approvals |
| `aiPrivacyRouter.requireReviewer` | false | Denies approvals without a verified reviewer callback |
| `aiPrivacyRouter.findSecBugsPlugin` | empty | Path to `findsecbugs-plugin.jar`; empty uses `~/.hushavyr/findsecbugs-plugin.jar` (the CLI reads `HUSHAVYR_FINDSECBUGS_PLUGIN`) |

## Optional offline analyzers

`/security`, `/scan` and the `hushavyr-scan` CLI also run these tools when they are installed. A missing tool is skipped; it never fails a scan. **Hushavyr: Setup** offers each one (with your confirmation) only when the workspace has matching code.

| Tool | Runs when | Kept findings | Rule ids |
| --- | --- | --- | --- |
| FindSecBugs (SpotBugs + plugin jar) | Compiled classes exist in `target/classes` or `build/classes/{java,kotlin,scala,groovy}/main`; build first | `SECURITY` category, rank 1-14, priority high/medium | `findsecbugs-<TYPE>` |
| Bandit | The project has Python files | Medium/high severity **and** confidence; no B101 (`assert`), no test folders or `test_*.py` | `bandit-<ID>` |
| gosec | `go.mod` at the folder root; runs with `GOPROXY=off` | Medium/high severity and confidence; no G104, no `_test.go` | `gosec-<ID>` |
| OSV-Scanner | A dependency manifest exists; runs `scan source --offline --no-resolve` | CVEs not already reported by Trivy (same package and id/alias) | `osv-<ID>` in SARIF |

A line already flagged by a built-in rule or Semgrep keeps that one finding, and two analyzer rules for the same weakness on one line count once. OSV-Scanner needs a local database: Setup offers to download it (`osv-scanner scan source --offline-vulnerabilities --download-offline-databases --no-resolve -r <folder>`), which fetches public OSV.dev archives for the ecosystems in the folder. Without it, OSV-Scanner is skipped.

Chat checks Ollama's local model inventory, and every generation verifies local model metadata before sending its prompt. Review requests reserve a 32,768-token context window and cap output at 4,096 tokens. The conservative source and prompt byte budgets reduce accidental context truncation; model compatibility and quality still need local measurement. The startup script manages the default endpoint; custom loopback servers must be started separately.

## Full-context privacy and review-only overrides

Classification covers prompts, selected code, attachments, tool outputs and retrieved context. Missing content, restricted labels/paths, detected credentials and PII deny overrides even if labeled public. Nothing becomes proven public just because a pattern did not match. The current extension has no tools or retrieval provider that silently adds additional context.

**Review Cloud Override (No Transfer)** opens the entire candidate context in a local preview, names the hypothetical destination, requests a reason and explicit confirmation, and rechecks policy. Cancellation defaults to denial. Required reviewer approval cannot be granted in the UI because no reviewer identity provider is connected. The reusable workflow supports a verified reviewer callback for a future integration; self-confirmation is not treated as reviewer identity.

Cloud dispatch remains disabled by default. The legacy override command never sends. The optional public-prompt Copilot adapter uses the guarded transfer boundary when explicitly enabled and each exact payload is approved. It scans an immutable snapshot and awaits separate approval and attempted-dispatch audit events before invoking any transport. Failure, cancellation and completed dispatch are separate outcomes. A post-send audit error propagates without retrying a send.

Audit logs contain only allowlisted metadata, IDs, reason codes, approval type, outcome and optional token counts. Unexpected runtime fields, invalid event pairs and free-form reasons are rejected. Files use append mode, reject symlinks and restrict permissions to 0600 on POSIX. New logs live in the extension's private `audit` directory as daily segments, with 30-day retention. Existing legacy `cloud-review.jsonl` files are not automatically removed. Access control depends on the local OS account; this is not a tamper-proof remote audit service.

## Local quality benchmark

```bash
npm run review:benchmark
```

This runs the real configured local model through review, possible repair and verification on eight synthetic examples: JSON escaping, null checks, integer overflow and cross-file null handling, with positive and clean pairs. Use `OLLAMA_MODEL`, `OLLAMA_VERIFIER_MODEL` and `OLLAMA_ENDPOINT` to select installed local models and a loopback endpoint. No model is downloaded by the benchmark.

The JSON summary reports fixture-level precision, recall, unexpected findings, failures, verifier failures and durations. Matching requires the expected source location and failure mechanism; duplicate findings count as extra findings. It exits nonzero for missed bugs, unexpected findings, review errors or verifier failures. It prints neither source nor raw model responses. This small calibration set is not a production evaluation or proof of Sonnet/Sol 6.1 parity. No cloud comparator is connected.

## Validation and smoke test

```bash
npm ci --ignore-scripts
npm run build
npm test
npm run package:vsix -- --out hushavyr-0.0.10.vsix
code --install-extension hushavyr-0.0.10.vsix
```

Reload VS Code, start local Ollama and repeat `/review` on the JSON-concatenating mapper. Evidence should come from actual source lines, with second-pass status. Attach its exception class too to exercise multi-file review. Run `/test` on a disposable project. Cancel a local request and verify it stops. Stop Ollama and verify there is no fallback. Try override cancellation and a synthetic PII sample: no cloud transfer should occur.

CI uses `npm ci`, build and security regression tests. Automated tests use fake model/VS Code APIs plus actual disposable project test processes. Live detection quality, VS Code rendering and a real local model run require the smoke test on the user's machine.
