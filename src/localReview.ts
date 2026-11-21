import { LocalOllama } from "./ollama";
import { ReviewResult, reviewPrompt, reviewSchema, validateReview } from "./review";
import { ReviewInput, reviewSources, validateContext } from "./context";
import { verifyReview } from "./verifyReview";
import { scanSecurity } from "./securityRules";
import { Finding } from "./review";
import { flowSeverity, flowTitle, taintFlows } from "./taint";

export type ReviewDepth = "fast" | "thorough" | "light";
export interface ReviewOptions {
  /** "thorough" adds focused security and robustness passes; "fast" is one pass plus a retry when empty;
   * "light" (small machines) is one short pass; static candidates and the verifier carry the rest. */
  depth?: ReviewDepth;
  /** Static analyzer candidates (semgrep / bundled rules), triaged together with the model's findings. */
  staticFindings?: Promise<Finding[]>;
}

// Appended after the shared prompt so every pass reuses the same prompt prefix (Ollama keeps its KV cache).
export const LENSES = [
  "FOCUS FOR THIS PASS: security only. Look for injection (SQL, shell command, path, template, LDAP), cross-site scripting, unsafe deserialization, disabled TLS validation, weak cryptography, hardcoded credentials, SSRF and missing authorization checks. Report a finding only when an externally influenced value visibly reaches the sink.",
  "FOCUS FOR THIS PASS: robustness only. Look for null/undefined dereferences, off-by-one and boundary errors, integer overflow, falsy-zero defaults, wrong comparators or sorting, shared mutable defaults, unclosed resources, swallowed errors and race conditions."
];

/** Same location (path and overlapping line range) means the same finding; the first one wins. */
export function mergeFindings(...lists: readonly Finding[][]): Finding[] {
  const merged: Finding[] = [];
  for (const finding of lists.flat()) {
    const span = (f: Finding): [number, number] => [f.line ?? 0, (f.line ?? 0) + f.evidence.split("\n").length - 1];
    const [start, end] = span(finding);
    if (merged.some(m => { const [a, b] = span(m); return m.path === finding.path && a <= end && start <= b; })) continue;
    merged.push(finding);
    if (merged.length >= 20) break;
  }
  return merged;
}

async function lensFindings(client: Pick<LocalOllama, "generate">, prompt: string, source: ReviewInput,
  cancelled: () => boolean): Promise<ReviewResult[]> {
  const results: ReviewResult[] = [];
  for (const lens of LENSES) {
    if (cancelled()) break;
    try { results.push(validateReview(await client.generate(prompt + "\n\n" + lens, {schema: reviewSchema}), source)); }
    catch { /* one failed lens must not discard the other passes */ }
  }
  return results;
}

/** At most two local inference calls, plus model-metadata checks. Every attempt goes through the same evidence gate. */
async function collectFindings(
  client: Pick<LocalOllama, "generate">,
  instruction: string,
  source: ReviewInput,
  cancelled: () => boolean = () => false,
  depth: ReviewDepth = "fast"
): Promise<ReviewResult | undefined> {
  if (cancelled()) return;
  const prompt = reviewPrompt(instruction, source);
  const raw = await client.generate(prompt, depth === "light" ? {schema: reviewSchema, maxTokens: 1536} : {schema: reviewSchema});
  if (cancelled()) return;
  const first = validateReview(raw, source);
  if (depth === "light") return first;
  if (depth === "thorough") {
    const passes = [first, ...await lensFindings(client, prompt, source, cancelled)];
    if (cancelled()) return;
    return {...first, findings: mergeFindings(...passes.map(p => p.findings)),
      proposed: passes.reduce((n, p) => n + (p.proposed ?? 0), 0),
      rejected: passes.reduce((n, p) => n + p.rejected, 0),
      rejectionReasons: [...new Set(passes.flatMap(p => p.rejectionReasons ?? []))]};
  }
  // An empty model response is inconclusive: make one focused local retry.
  // Never manufacture findings or bypass source evidence validation.
  if (first.findings.length) return first;
  const feedback = first.error ?? (first.proposed === 0 ? "No candidate findings were proposed." : first.rejectionReasons?.join("; ") ?? "Invalid finding");
  try {
    const repaired = await client.generate(prompt +
      "\n\nLOCAL VALIDATOR FEEDBACK: " + feedback +
      "\nReview the source again, inspecting boundary conditions, error handling, and any visible concrete failure mechanisms. Correct the response shape and choose a valid source path and line range. " +
      "Discard any unsupported claim; return an empty findings array if no concrete issue is supported.",
      {schema: reviewSchema});
    if (cancelled()) return;
    const second = validateReview(repaired, source);
    // Do not hide the original useful validation feedback behind a new parser error.
    return second.error ? {...first, retryFailed: true} : second;
  } catch {
    if (!cancelled()) return {...first, retryFailed: true};
  }
}

/** Independent offline indicators, never presented as AI-generated or confirmed vulnerabilities. */
function offlineSecurityFindings(source: ReviewInput): Finding[] {
  const findings: Finding[] = [];
  for (const file of reviewSources(source)) {
    const lines = file.text.split(/\r?\n/);
    // Detect Java HTTP responses assembled from an unescaped dynamic JSON string.
    // This is a narrow correctness check, not a generic concatenation alarm.
    if (file.path.toLowerCase().endsWith(".java")) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line.includes(".entity(") || !line.includes("+")) continue;
        if (!line.includes("\\\"") || !line.includes("{")) continue;
        findings.push({
          title: "Local rule: Dynamic value embedded in manually constructed JSON",
          severity: "medium", evidence: line,
          fix: "Serialize a response DTO or JSON object with the framework's JSON serializer rather than concatenating unescaped values.",
          regressionTest: "Use an input containing quotes and backslashes, then assert the HTTP response parses as valid JSON.",
          status: "potential", path: file.path, line: (file.startLine ?? 1) + i
        });
        if (findings.length >= 10) return findings;
      }
    }
    // Source-to-sink flows from the deterministic taint engine (same engine as /security), so a small model cannot drop them.
    for (const flow of taintFlows([{path: file.path, text: file.text}])) {
      const evidence = lines[flow.sink.line - 1];
      if (flow.sink.path !== file.path || !evidence || evidence.trim().length < 8) continue;
      findings.push({
        title: "Local rule: " + flowTitle(flow),
        severity: flowSeverity(flow), evidence,
        fix: "Do not build the sink argument from request input: use parameterized APIs, an allow-list or proper encoding.",
        regressionTest: "Send a malicious value in the request parameter from line " + ((file.startLine ?? 1) + flow.source.line - 1) + " and assert it is rejected or treated as data.",
        status: "potential", path: file.path, line: (file.startLine ?? 1) + flow.sink.line - 1
      });
      if (findings.length >= 10) return findings;
    }
    for (const issue of scanSecurity(file.path, file.text)) {
      // Only surface high-confidence, directly visible TLS misconfiguration here.
      // Broader heuristic checks remain in /security to avoid noisy /review output.
      if (issue.rule !== "TLS certificate validation disabled") continue;
      const evidence = lines[issue.line - 1];
      if (!evidence || evidence.trim().length < 8) continue;
      findings.push({
        title: "Local rule: TLS certificate validation disabled",
        severity: "high", evidence,
        fix: issue.advice,
        regressionTest: "Verify connections reject an invalid or untrusted certificate.",
        status: "potential", path: file.path,
        line: (file.startLine ?? 1) + issue.line - 1
      });
      if (findings.length >= 10) return findings;
    }
  }
  return findings;
}

/** Hybrid review: model passes + static analyzer candidates, then one separate verification pass; all local. */
export async function runLocalReview(
  client: Pick<LocalOllama, "generate">, instruction: string, source: ReviewInput,
  cancelled: () => boolean = () => false, verifier?: Pick<LocalOllama, "generate">,
  options: ReviewOptions = {}
): Promise<ReviewResult | undefined> {
  validateContext(instruction, reviewSources(source));
  const model = await collectFindings(client, instruction, source, cancelled, options.depth);
  if (!model || cancelled()) return;
  const staticCandidates = options.staticFindings ? await options.staticFindings.catch(() => []) : [];
  const result = staticCandidates.length && !model.error
    ? {...model, findings: mergeFindings(model.findings, staticCandidates), staticCandidates: staticCandidates.length}
    : model;
  const verified = verifier ? await verifyReview(verifier, result, source, cancelled) : result;
  if (!verified || cancelled()) return;
  return {...verified, findings: mergeFindings(verified.findings, offlineSecurityFindings(source))};

}
