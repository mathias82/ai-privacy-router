import { ReviewInput, reviewSources, sourcePrompt } from "./context";
/** Evidence-gated local review: never promote unverified model claims to confirmed bugs. */
export interface Finding { title: string; severity: string; evidence: string; fix: string; regressionTest: string; status: "potential" | "confirmed"; path?: string; line?: number; verification?: "supported" | "unverified" }
export interface ReviewResult { findings: Finding[]; rejected: number; proposed?: number; error?: string; rejectionReasons?: string[]; retryFailed?: boolean; verifierRejected?: number; verifierFailed?: boolean; staticCandidates?: number; cached?: boolean }
// Ollama constrains the shape; source validation below still decides what can be shown.
export const reviewSchema = {
  type: "object",
  required: ["findings"],
  additionalProperties: false,
  properties: {
    findings: {type: "array", maxItems: 20, items: {
      type: "object", additionalProperties: false,
      required: ["title", "severity", "startLine", "endLine", "fix", "regressionTest", "path"],
      properties: {
        title: {type: "string"}, severity: {type: "string", enum: ["high", "medium", "low"]},
        startLine: {type: "integer", minimum: 1}, endLine: {type: "integer", minimum: 1},
        fix: {type: "string"}, regressionTest: {type: "string"}, path: {type: "string"}
      }
    }}
  }
} as const;
const codeFence = /\x60{3}(?:json)?\s*([\s\S]*?)\x60{3}/i;
function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}
function field(obj: Record<string, unknown>, key: string): string {
  return typeof obj[key] === "string" ? (obj[key] as string).trim() : "";
}
export function reviewPrompt(instruction: string, code: ReviewInput): string {
  return [
    "You are a skeptical code reviewer. Review each source using its own language and runtime semantics. Use the file name and source syntax to identify the language. Follow relevant boundaries between languages when both sides are supplied. Return ONLY valid JSON, no Markdown.",
    'Schema: {"findings":[{"title":"...","severity":"high|medium|low","path":"exact SOURCE path","startLine":1,"endLine":2,"fix":"...","regressionTest":"..."}]}.',
    "Only report concrete failure mechanisms visible in supplied code. Never claim SQL injection without a SQL query or execution sink in the provided code.",
    "Do not claim a getter throws exceptions unless source code shows that behavior.",
    "Evidence MUST be an exact verbatim substring of the provided source code, at least 8 characters. The extension extracts it from your line range; do not copy escaped source into JSON.",
    "Choose the narrowest source range supporting the failure: startLine and endLine are inclusive, 1-based, and at most 8 lines apart including both endpoints.",
    "Use only the supplied files. Follow calls across supplied files when possible; do not assume implementations or validation in absent files. Set path to the exact SOURCE path containing the evidence.",
    "Inspect correctness at input/output boundaries: serialization and escaping, null handling, state changes and error responses. Explain a concrete triggering input and its effect in the title or fix. Do not invent absent behavior.",
    "Apply language-specific semantics, not Java assumptions: Java/Kotlin nullability, transactions and resource ownership; JavaScript/TypeScript async errors, truthiness and type coercion; Python mutable defaults, exception paths and subprocess handling; Go ignored errors and goroutine/channel lifecycle; Rust Result/Option handling and unsafe boundaries; C/C++ ownership, bounds and undefined behavior; C# async disposal and null handling; SQL joins, null semantics and parameter binding; shell quoting and exit status. For other languages infer only from visible syntax.",
    "Inspect each file for a reproducible input -> operation -> incorrect output or side effect. Prioritize actual bugs over style, formatting and speculative vulnerabilities. For each finding include a precise trigger and a testable fix.",
    "A clean review is allowed, but first check boundary values (null, empty, zero, negative, duplicate, concurrent), error propagation, resource cleanup and data escaping where relevant to the language.",
    "If evidence is insufficient, return an empty findings array. Do not invent tests, other files, or execution results.",
    "User request: " + instruction,
    sourcePrompt(code)
  ].join("\n\n");
}
export function validateReview(raw: string, source: ReviewInput): ReviewResult {
  const sources = reviewSources(source);
  const combined = sources.map(s => s.text).join("\n");
  let parsed: unknown;
  try {
    const match = raw.match(codeFence);
    parsed = JSON.parse(match ? match[1] : raw);
  } catch { return {findings:[],rejected:0,error:"Model did not return valid JSON"}; }
  const obj = record(parsed);
  if (!obj || !Array.isArray(obj.findings)) return {findings:[],rejected:0,error:"Missing findings array"};
  const findings: Finding[] = [];
  const proposed = Math.min(obj.findings.length, 20);
  let rejected = 0;
  const rejectionReasons = new Set<string>();
  const reject = (reason: string): void => { rejected++; rejectionReasons.add(reason); };
  for (const candidate of obj.findings.slice(0,20)) {
    const item = record(candidate);
    if (!item) { reject("Finding must be an object"); continue; }
    const title=field(item,"title"),severity=field(item,"severity").toLowerCase();
    let evidence=field(item,"evidence");
    const fix=field(item,"fix"),regressionTest=field(item,"regressionTest");
    const path = field(item, "path");
    const eligible = path ? sources.filter(s => s.path === path) : (sources.length === 1 ? sources : []);
    const start = item.startLine, end = item.endLine;
    const hasRange = start !== undefined || end !== undefined;
    const lines = eligible.length === 1 ? eligible[0].text.replace(/\r\n/g,"\n").split("\n") : [];
    const offset = eligible[0]?.startLine ?? 1;
    const validRange = Number.isInteger(start) && Number.isInteger(end) &&
      (start as number) >= offset && (end as number) >= (start as number) &&
      (end as number) < offset + lines.length && (end as number) - (start as number) < 8;
    const rangeEvidence = validRange ? lines.slice((start as number) - offset, (end as number) - offset + 1).join("\n") : "";
    if (!evidence && validRange) evidence = rangeEvidence;
    const matched = eligible.find(s => s.text.replace(/\r\n/g,"\n").includes(evidence.replace(/\r\n/g,"\n")));
    const normalizedSource = matched?.text.replace(/\r\n/g,"\n") ?? "";
    const exactEvidence = evidence.length >= 8 && normalizedSource.includes(evidence.replace(/\r\n/g,"\n"));
    const hasSqlSink = /\b(?:prepareStatement|createStatement|executeQuery|executeUpdate|EntityManager|createNativeQuery|JdbcTemplate)\b|\b(?:SELECT|INSERT|UPDATE|DELETE)\s/i.test(combined);
    const unsupportedSql = /sql\s*injection/i.test(title) && !hasSqlSink;
    const unsupportedGetter = /(?:exception handling|unhandled exception)/i.test(title) && /getTenantId\(\)/.test(evidence) && !/throw\s+new/.test(combined);
    const reasons: string[] = [];
    if (!title || !fix || !regressionTest) reasons.push("Required title, fix or regressionTest is missing");
    if (!["high","medium","low"].includes(severity)) reasons.push("Severity must be high, medium or low");
    if (!exactEvidence) reasons.push("Evidence must copy an exact source substring of at least 8 characters");
    if (hasRange && !validRange) reasons.push("Source line range must be within the supplied file and at most 8 lines");
    if (validRange && !rangeEvidence.includes(evidence.replace(/\r\n/g,"\n"))) reasons.push("Quoted evidence does not belong to the supplied line range");
    if (!eligible.length) reasons.push("Path must identify a supplied source file");
    if (unsupportedSql) reasons.push("SQL injection claim has no SQL sink in supplied source");
    if (unsupportedGetter) reasons.push("Getter exception claim has no supporting throw in supplied source");
    if (reasons.length) { reject(reasons.join("; ")); continue; }
    const line = validRange ? start as number : normalizedSource.slice(0, normalizedSource.indexOf(evidence.replace(/\r\n/g,"\n"))).split("\n").length + (matched?.startLine ?? 1) - 1;
    findings.push({title,severity,evidence,fix,regressionTest,status:"potential",path:matched!.path,line});
  }
  return {findings,rejected,proposed,rejectionReasons:[...rejectionReasons]};
}
/** Small models often return nothing; point users at a larger local model without implying the code is clean. */
export function modelHint(model: string, result: ReviewResult): string {
  const size = /(?:^|[:\-_])(\d+(?:\.\d+)?)b(?:$|[^a-z0-9])/i.exec(model);
  if (result.findings.some(f => !f.title.startsWith("Local rule:")) || result.error || !size || Number(size[1]) >= 14) return "";
  return "\n\n_Tip: " + model + " is a small model and often misses bugs. Run **Hushavyr: Setup** to switch to a larger local model (e.g. qwen2.5-coder:14b)._";
}
const SEVERITY_RANK: Record<string, number> = {high: 0, medium: 1, low: 2};
const shortPath = (path?: string): string => decodeURIComponent((path ?? "selection").split("/").pop() ?? "selection");

/** One glanceable block for the reader: how many issues, how serious, and which one to fix first. */
export function reviewSummary(result: ReviewResult): string {
  if (!result.findings.length) return "**Summary:** nothing to fix was found. Not a guarantee that the code is clean.";
  const count = (s: string) => result.findings.filter(f => f.severity === s).length;
  const parts = [["high", "\u{1F534}"], ["medium", "\u{1F7E0}"], ["low", "\u{1F7E2}"]]
    .filter(([s]) => count(s)).map(([s, icon]) => icon + " " + count(s) + " " + s);
  const first = [...result.findings].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 3) - (SEVERITY_RANK[b.severity] ?? 3))[0];
  return "**Summary:** " + result.findings.length + " issue(s) to look at: " + parts.join(" · ") +
    "  \n**Fix first:** " + inlineText(first.title.replace(/^Local rule: /, "")) + " (`" + shortPath(first.path) + ":" + (first.line ?? "?") + "`)";
}

/** Model text shown as Markdown: keep `<`/`>` visible instead of letting the renderer drop them as HTML. */
export function inlineText(text: string): string {
  return text.replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export function formatReview(result: ReviewResult, displayPath: (path: string) => string = p => p): string {
  if (result.error) return "**Review not verified:** " + result.error + ". No findings promoted." +
    (result.retryFailed ? " The local repair attempt also failed." : "") + " Try again with a smaller selection.";
  const lines = ["### Evidence-gated local review", "", reviewSummary(result), "", "All findings are **potential**, not confirmed. Tests were suggested, not executed.", ""];
  lines.push("**Review diagnostics:** " + (result.proposed ?? result.findings.length + result.rejected) + " proposed · " + result.findings.length + " passed source validation · " + result.rejected + " rejected by source validation · " + (result.verifierRejected ?? 0) + " rejected by second local pass.", "");
  if (result.staticCandidates) lines.push("**Hybrid analysis:** " + result.staticCandidates + " candidate(s) from the bundled static rules (Semgrep) were triaged together with the model's findings.", "");
  if (result.cached) lines.push("_Same code and settings as an earlier review in this session: cached result reused._", "");
  if (result.findings.some(f => f.title.startsWith("Local rule:"))) lines.push("**Offline indicators:** \"Local rule\" findings come from bundled static rules, not from the AI model; the second local pass checks them against the source when it runs.", "");
  if (!result.findings.length) lines.push(result.proposed === 0 ? "The local model proposed no findings. This does not establish that the code is bug-free." : "No findings passed the evidence checks. The review was inconclusive; this does not establish that the code is bug-free.", "");
  for (const [i,f] of result.findings.entries()) lines.push(
    "#### " + (i+1) + ". " + inlineText(f.title),
    "**Status:** Potential · **Severity:** " + f.severity,
    "**Location:** \x60" + (f.path ? displayPath(f.path) : "selection").replace(/\x60/g, "") + ":" + (f.line ?? "?") + "\x60",
    "**Second local pass:** " + (f.verification === "supported" ? "Source support agreed; no runtime proof." : "Not verified."),
    "**Source evidence:**", "\x60\x60\x60java\n" + f.evidence + "\n\x60\x60\x60",
    "**Proposed fix:** " + inlineText(f.fix),
    "**Regression test to implement:** " + inlineText(f.regressionTest), ""
  );
  lines.push("_Filtered " + result.rejected + " unsupported or malformed finding(s). Source matching is not proof of runtime exploitability._");
  if (result.rejectionReasons?.length) lines.push("", "**Validation feedback:**", ...result.rejectionReasons.map(reason => "- " + reason));
  if (result.retryFailed) lines.push("", "The local repair attempt failed. These are the first attempt's validated results.");
  if (result.verifierRejected) lines.push("", "Second local pass rejected " + result.verifierRejected + " finding(s) as unsupported.");
  if (result.verifierFailed) lines.push("", "Second local pass was unavailable or invalid; findings remain unverified.");
  return lines.join("\n");
}


/** /review is a bug finder; questions about what the code does should get a plain answer instead. */
export function asksForExplanation(text: string): boolean {
  return /\b(explain|describe|summari[sz]e|walk me through|what (?:does|is)|how (?:does|do|is)|why (?:does|is)|tell me about)\b|\u03b5\u03be\u03ae\u03b3\u03b7\u03c3|\u03c4\u03b9 \u03ba\u03ac\u03bd\u03b5\u03b9|\u03c0\u03ce\u03c2 \u03b4\u03bf\u03c5\u03bb\u03b5\u03cd\u03b5\u03b9|\b(?:eksigis|exigis|ti kanei|pos douleuei|pws douleuei)/iu.test(text) &&
    !/\b(bugs?|vulnerabilit\w*|find (?:issues|problems)|security)\b/i.test(text);
}
