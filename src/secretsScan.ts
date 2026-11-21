/** Local deterministic credential checks. Never returns secret values. */
export interface SecretFinding {line: number; rule: string; severity: "HIGH" | "MEDIUM"}
const ASSIGNMENT = /^\s*(?:export\s+)?(?:["']?)([A-Za-z][A-Za-z0-9_.-]*)(?:["']?)\s*[:=]\s*(.*?)\s*[,;]?\s*$/;
const KEY = /(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key)/i;
const PLACEHOLDER = /^(?:["']?)(?:|\$\{[^}]+\}|\$[A-Za-z_][\w]*|<[^>]+>|\{\{.*\}\}|changeme|replace[_-]?me|your[_-].*|null|none|undefined|false|true|\*+)(?:["']?)$/i;
// Code declarations such as `const password = "..."` or `private static final String API_KEY = "...";` need a literal value.
const CODE_ASSIGNMENT = /^\s*(?:(?:export|const|let|var|final|private|public|protected|static|readonly|val)\s+)+(?:[A-Za-z_][\w<>\[\],.?]*\s+)?([A-Za-z_]\w*)\s*(?::\s*[\w<>\[\]]+\s*)?=\s*(["'])([^"']{4,})\2\s*;?\s*$/;
// File globs such as "**/*.{env,yml}" name files that may hold secrets; they are not secrets.
const GLOB = /\*\*?\/|\*\.|\{[\w.-]*(?:,[\w.-]*)+\}/;
// Keys that only mention a secret (hashAlgorithm, secretProviderClass, passwordExpirationPolicy, apiKeyRef...) hold settings, labels or references.
const NOT_SECRET_KEY = /(?:algorithm|provider_?class|last_?changed|changed_?at|length|min|max|ref|type|policy|expir\w*|name|time|subject|body|label|title|hint|message|text|placeholder|field|count|enabled|required|regex|pattern|rule|url|uri|path|file|header|param|mode|version|format|strength|validation|error|tooltip|description|prompt|colou?r|image|icon|id|state|focused|focus_?lost|prefix|result|confirmation|changed?|algorithms|request|response|dto|view|screen|dialog|form|input|button|visible|visibility|status|strategy|handler|callback|listener|validator|encoder|hasher|service|manager|repository|helper|factory|builder|options|settings)$|^(?:change|reset|forgot|show|hide|toggle|validate|is|has|use|on|was|did|should|can|will|apply|sign_?(?:in|up))(?=[A-Z_-]|$)|secretar(?:y|ies)/i;
// In source code an unquoted value is a variable, property or method reference, never a literal credential.
const CODE_FILE = /\.(?:cs|kt|kts|java|scala|groovy|ts|tsx|js|jsx|mjs|cjs|swift|go|py|rb|php|rs|dart|razor|vue|svelte)$/i;
// `options.ApiKey`, `vm::onChange`, `var.db_password`, `GetKey()` style references, with any file type.
const REFERENCE = /^!?[A-Za-z_$][\w$]*(?:(?:\?\.|!!\.|\.|::|->)[A-Za-z_$][\w$]*)+(?:\(\))?\)*$|^[A-Za-z_$][\w$]*\)+$/;
function literalValue(raw: string): string | undefined {
  const value = raw.trim();
  // Structures, resource references (@string/x), env/config lookups and calls are not literal credentials.
  if (/^[\[{@?]|^%\w+%$|\$\(|\$\{|\(|\b(?:process\.env|getenv|environ|GetEnvironmentVariable|Configuration|config|settings)\b/.test(value)) return;
  const text = value.replace(/^(["'`])(.*)\1$/, "$2");
  if (text.length < 4) return;
  // UI text and translations ("Κωδικός πρόσβασης", "Password") are labels, not secrets.
  if (/\s/.test(text.trim()) || /^\p{Lu}\p{Ll}+$/u.test(text) || /[\u0370-\u03ff]/.test(text)) return;
  return text;
}
// Tests, fixtures, docs, examples and local/dev profiles usually hold throwaway values: still reported, but MEDIUM so real config stands out.
const LOW_RISK_PATH = /(?:^|[\\/])(?:tests?|__tests__|spec|e2e|testdata|fixtures?|mocks?|examples?|samples?|docs?)[\\/]|\.(?:test|spec)\.\w+$|_test\.\w+$|\.(?:md|example|sample|template|dist)$|(?:^|[\\/.-])(?:local|dev|example|sample|template|demo)[\w-]*\.(?:env|ya?ml|json|properties|toml|ini)$/i;
const TEST_CLASS = /[a-z0-9]Tests?\.(?:java|kt|cs|scala|groovy)$/;
// Provider token formats are credentials whatever the variable is called (`stripeKey`, `token`, a comment...).
const TOKEN = /\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[0-9A-Za-z]{36,}\b|\bgithub_pat_[0-9A-Za-z_]{60,}\b|\bxox[abposr]-[0-9A-Za-z-]{20,}|\bAIza[0-9A-Za-z_-]{35}\b|-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/;
function keyName(key: string): string { return key.split(/[.[\]]/).filter(Boolean).pop() ?? key; }
export function scanSecrets(content: string, path = ""): SecretFinding[] {
  const code = CODE_FILE.test(path);
  const severity = LOW_RISK_PATH.test(path) || TEST_CLASS.test(path) ? "MEDIUM" : "HIGH";
  const findings: SecretFinding[] = [];
  for (const [index, line] of content.split(/\r?\n/).entries()) {
    if (index >= 10000 || findings.length >= 100) break;
    const token = TOKEN.exec(line);
    if (token && !/EXAMPLE|X{8}|0{16}/i.test(token[0])) {
      findings.push({line: index + 1, rule: "Potential hardcoded credential", severity});
      continue;
    }
    if (/^\s*(?:#|\/\/|\*)/.test(line)) continue;
    const decl = CODE_ASSIGNMENT.exec(line);
    if (decl && KEY.test(decl[1]) && !NOT_SECRET_KEY.test(decl[1]) && !PLACEHOLDER.test(decl[2] + decl[3] + decl[2]) && !/^\$\{|^\{\{|^<.*>$/.test(decl[3]) && !GLOB.test(decl[3]) && literalValue(decl[3]) !== undefined) {
      findings.push({line: index + 1, rule: "Potential hardcoded credential", severity});
      continue;
    }
    const match = ASSIGNMENT.exec(line);
    if (!match || !KEY.test(keyName(match[1])) || NOT_SECRET_KEY.test(keyName(match[1]))) continue;
    const value = match[2].trim().replace(/[,;]\s*$/, "").trim();
    // GitHub Actions expressions and template variable references are not literal credentials.
    if (/^["\x27]?\s*\$\{\{\s*(?:secrets|vars|env|github|inputs|steps|needs)\.[^}]+\}\}\s*["\x27]?$/.test(value)) continue;
    if (/^["\x27]?\s*\$\{[A-Za-z_][\w.:-]*\}\s*["\x27]?$/.test(value)) continue;
    // Unquoted SCREAMING_SNAKE names (API_KEY_VALUE) in docs and samples name a constant or placeholder.
    if (REFERENCE.test(value) || (code && !/^["'`]/.test(value)) || /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(value)) continue;
    if (PLACEHOLDER.test(value) || /^["']\s*["']$/.test(value) || GLOB.test(value) || literalValue(value) === undefined) continue;
    findings.push({line: index + 1, rule: "Potential hardcoded credential", severity});
  }
  return findings;
}
