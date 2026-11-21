// Optional offline analyzers: FindSecBugs (SpotBugs), Bandit, gosec and OSV-Scanner. A missing tool is skipped, never an error.
import {join, relative, resolve, isAbsolute, dirname, basename} from "node:path";
import {mkdtemp, readFile, rm, readdir, access} from "node:fs/promises";
import {existsSync} from "node:fs";
import {tmpdir, homedir} from "node:os";
import {exec} from "./exec";
import {auditDependencies, DependencyAudit, DependencyVulnerability} from "./dependencyAudit";

export type CodeScanner = "findsecbugs" | "bandit" | "gosec";
export interface CodeFinding {tool: CodeScanner; rule: string; severity: "HIGH" | "MEDIUM"; path: string; line: number; message: string; cwe?: number}
export interface CodeScanResult {tool: CodeScanner; status: "ok" | "missing" | "skipped" | "failed"; findings: CodeFinding[]; reason?: "not-applicable" | "plugin-missing" | "execution-failed" | "invalid-output"}
export interface CodeScanOptions {signal?: AbortSignal; large?: boolean; findSecBugsPlugin?: string}
export const CODE_SCANNERS: readonly CodeScanner[] = ["findsecbugs", "bandit", "gosec"];
export const defaultFindSecBugsPlugin = (): string => join(homedir(), ".hushavyr", "findsecbugs-plugin.jar");

const SKIP_DIRS = new Set([".git", "node_modules", ".venv", "venv", "env", ".tox", ".next", ".idea", ".vscode", "vendor", "__pycache__", "dist", "out", "coverage", "site-packages"]);
const TEST_PATH = /(?:^|\/)(?:tests?|testing|__tests__|testdata|fixtures?|examples?)\/|(?:^|\/)(?:test_[^/]*|[^/]*_test)\.(?:py|go)$|(?:^|\/)conftest\.py$/i;
/** Scanner text is untrusted: printable ASCII only, no markdown link or code syntax. */
const clean = (value: unknown, max = 200): string => typeof value === "string" ? value.replace(/[^\x20-\x7E]/g, " ").replace(/[`\[\]<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, max) : "";

function inside(root: string, path: string): string | undefined {
  const rel = relative(root, resolve(root, path));
  return rel && !rel.startsWith("..") && !isAbsolute(rel) ? rel.replace(/\\/g, "/") : undefined;
}
const level = (value: unknown): "HIGH" | "MEDIUM" | undefined => {
  const v = String(value ?? "").toUpperCase();
  return v === "HIGH" || v === "CRITICAL" ? "HIGH" : v === "MEDIUM" ? "MEDIUM" : undefined;
};

/** One finding per file, line and weakness: two rules for the same SQL call are shown once, the more severe one kept. */
export function dedupeFindings<T extends {path: string; line: number; cwe?: number; rule: string; severity: string}>(list: readonly T[]): T[] {
  const kept = new Map<string, T>();
  for (const f of list) {
    const key = f.path + ":" + f.line + ":" + (f.cwe ?? f.rule);
    const old = kept.get(key);
    if (!old || (old.severity !== "HIGH" && f.severity === "HIGH")) kept.set(key, f);
  }
  return [...kept.values()];
}

/** Bandit JSON: MEDIUM/HIGH severity and confidence only; asserts (B101) and test code are dropped. */
export function parseBandit(output: string, root: string, max = 500): CodeFinding[] {
  let data: unknown; try { data = JSON.parse(output); } catch { return []; }
  const rows = (data as {results?: unknown[]})?.results;
  if (!Array.isArray(rows)) return [];
  const found: CodeFinding[] = [];
  for (const row of rows as Record<string, unknown>[]) {
    const severity = level(row?.issue_severity), id = clean(row?.test_id, 12);
    const path = typeof row?.filename === "string" ? inside(root, row.filename) : undefined;
    const line = row?.line_number;
    if (!severity || !level(row.issue_confidence) || !id || id === "B101" || !path || TEST_PATH.test(path) || !Number.isInteger(line) || (line as number) < 1) continue;
    const cwe = Number((row.issue_cwe as {id?: unknown})?.id);
    found.push({tool: "bandit", rule: "bandit-" + id, severity, path, line: line as number, message: clean(row.issue_text) || id, ...(cwe > 0 ? {cwe} : {})});
  }
  return dedupeFindings(found).slice(0, max);
}

/** gosec JSON: G104 (unchecked errors), *_test.go and LOW severity or confidence are dropped. */
export function parseGosec(output: string, root: string, max = 500): CodeFinding[] {
  let data: unknown; try { data = JSON.parse(output); } catch { return []; }
  const rows = (data as {Issues?: unknown[]})?.Issues;
  if (!Array.isArray(rows)) return [];
  const found: CodeFinding[] = [];
  for (const row of rows as Record<string, unknown>[]) {
    const severity = level(row?.severity), id = clean(row?.rule_id, 12);
    const path = typeof row?.file === "string" ? inside(root, row.file) : undefined;
    const line = parseInt(String(row?.line ?? ""), 10);
    if (!severity || !level(row.confidence) || !id || id === "G104" || !path || TEST_PATH.test(path) || !(line >= 1)) continue;
    const cwe = Number((row.cwe as {id?: unknown})?.id);
    found.push({tool: "gosec", rule: "gosec-" + id, severity, path, line, message: clean(row.details) || id, ...(cwe > 0 ? {cwe} : {})});
  }
  return dedupeFindings(found).slice(0, max);
}

const xmlText = (v: string): string => v.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"").replace(/&apos;/g, "'").replace(/&amp;/g, "&");
const attr = (tag: string, name: string): string | undefined => {
  const m = new RegExp("\\s" + name + "=\"([^\"]*)\"").exec(tag);
  return m ? xmlText(m[1]) : undefined;
};
/**
 * SpotBugs XML (-xml:withMessages): SECURITY category and rank 1-14 only. Locations are source paths relative to a
 * source root (com/x/Foo.java); `source` maps them to a project file, findings it cannot place are dropped.
 */
export function parseSpotBugs(xml: string, source: (sourcepath: string) => string | undefined, max = 500): CodeFinding[] {
  const found: CodeFinding[] = [];
  for (const m of xml.matchAll(/<BugInstance\b([^>]*)>([\s\S]*?)<\/BugInstance>/g)) {
    const head = m[1], body = m[2];
    const rank = Number(attr(head, "rank") ?? 99), priority = Number(attr(head, "priority") ?? 3);
    const type = clean(attr(head, "type"), 80);
    if (attr(head, "category") !== "SECURITY" || !type || rank > 14 || priority > 2) continue;
    const primary = /<SourceLine\b[^>]*\bprimary="true"[^>]*>/.exec(body)?.[0] ?? /<Method\b[^>]*>\s*(<SourceLine\b[^>]*>)/.exec(body)?.[1];
    const sourcepath = primary && attr(primary, "sourcepath"), line = Number(primary && attr(primary, "start"));
    const path = sourcepath && !sourcepath.split("/").includes("..") ? source(sourcepath) : undefined;
    if (!path || !(line >= 1) || TEST_PATH.test(path)) continue;
    const cwe = Number(attr(head, "cweid"));
    found.push({tool: "findsecbugs", rule: "findsecbugs-" + type, severity: priority === 1 || rank <= 9 ? "HIGH" : "MEDIUM", path, line,
      message: clean(xmlText(/<ShortMessage>([\s\S]*?)<\/ShortMessage>/.exec(body)?.[1] ?? "")) || type, ...(cwe > 0 ? {cwe} : {})});
  }
  return dedupeFindings(found).slice(0, max);
}

/** Bounded directory walk; stops at `limit` matches. */
async function find(root: string, match: (rel: string, isDir: boolean) => boolean, limit: number, depth = 6): Promise<string[]> {
  const found: string[] = [];
  let visited = 0;
  const walk = async (dir: string, level: number): Promise<void> => {
    if (found.length >= limit || level > depth || ++visited > 5000) return;
    let entries; try { entries = await readdir(dir, {withFileTypes: true}); } catch { return; }
    for (const entry of entries) {
      if (found.length >= limit) return;
      const full = join(dir, entry.name), rel = relative(root, full).replace(/\\/g, "/");
      if (match(rel, entry.isDirectory())) { found.push(full); continue; }
      if (entry.isDirectory() && !SKIP_DIRS.has(entry.name) && !entry.name.startsWith(".")) await walk(full, level + 1);
    }
  };
  await walk(root, 0);
  return found;
}
/** Compiled main (non-test) class folders of Maven and Gradle modules. */
export const findClassDirs = (root: string): Promise<string[]> =>
  find(root, (rel, dir) => dir && /(?:^|\/)(?:target\/classes|build\/classes\/(?:java|kotlin|scala|groovy)\/main)$/.test(rel), 50, 8);
/** Maps a SpotBugs source path to the first matching file under a module's source roots. */
export function sourceResolver(root: string, classDirs: readonly string[], exists: (path: string) => boolean = existsSync): (sourcepath: string) => string | undefined {
  const modules = [...new Set(classDirs.map(d => /target[\\/]classes$/.test(d) ? dirname(dirname(d)) : dirname(dirname(dirname(dirname(d))))))];
  const roots = modules.flatMap(m => ["java", "kotlin", "scala", "groovy"].map(l => join(m, "src", "main", l)).concat(join(m, "src")));
  return sourcepath => {
    for (const dir of roots) {
      const file = join(dir, sourcepath);
      if (exists(file)) return inside(root, file);
    }
    return undefined;
  };
}

const failure = (tool: CodeScanner, reason: CodeScanResult["reason"]): CodeScanResult => ({tool, status: "failed", findings: [], reason});

/** Runs one optional analyzer on `root`; returns "skipped" when the project has nothing it can analyze. */
export async function runCodeScanner(tool: CodeScanner, root: string, options: CodeScanOptions = {}): Promise<CodeScanResult> {
  const large = !!options.large, max = large ? 5000 : 500;
  let classDirs: string[] = [];
  let plugin = "";
  if (tool === "bandit" && !(await find(root, (rel, dir) => !dir && rel.endsWith(".py") && !TEST_PATH.test(rel), 1)).length) return {tool, status: "skipped", findings: [], reason: "not-applicable"};
  if (tool === "gosec") { try { await access(join(root, "go.mod")); } catch { return {tool, status: "skipped", findings: [], reason: "not-applicable"}; } }
  if (tool === "findsecbugs") {
    classDirs = await findClassDirs(root);
    if (!classDirs.length) return {tool, status: "skipped", findings: [], reason: "not-applicable"};
    plugin = options.findSecBugsPlugin || defaultFindSecBugsPlugin();
    try { await access(plugin); } catch { return {tool, status: "missing", findings: [], reason: "plugin-missing"}; }
  }
  const temp = await mkdtemp(join(tmpdir(), "hushavyr-" + tool + "-"));
  const report = join(temp, "report");
  const command = tool === "findsecbugs" ? "spotbugs" : tool;
  const args = tool === "bandit"
    ? ["-r", ".", "-f", "json", "-o", report, "-q", "--severity-level", "medium", "--confidence-level", "medium", "-x", "*/tests/*,*/test/*,*/.venv/*,*/venv/*,*/node_modules/*,*/site-packages/*"]
    : tool === "gosec"
      ? ["-fmt", "json", "-out", report, "-quiet", "-no-fail", "-exclude=G104", "-severity", "medium", "-confidence", "medium", "./..."]
      : ["-textui", "-quiet", "-effort:max", "-bugCategories", "SECURITY", "-maxRank", "14", "-pluginList", plugin, "-xml:withMessages=" + report, ...classDirs];
  try {
    try {
      await exec(command, args, {cwd: root, timeout: (large ? 900 : 300) * 1000, maxBuffer: 16 * 1024 * 1024, windowsHide: true, signal: options.signal,
        // gosec loads packages through the go tool: no module downloads, no toolchain switch.
        env: tool === "gosec" ? {...process.env, GOPROXY: "off", GOTOOLCHAIN: "local"} : process.env});
    } catch (e) {
      const err = e as NodeJS.ErrnoException & {code?: string | number};
      if (err.code === "ENOENT") return {tool, status: "missing", findings: []};
      // Bandit exits 1 when it found issues; anything else without a report is a failure.
      if (options.signal?.aborted || err.name === "AbortError") return failure(tool, "execution-failed");
    }
    let output: string;
    try { output = await readFile(report, "utf8"); } catch { return failure(tool, "execution-failed"); }
    if (tool === "findsecbugs") {
      if (!output.includes("<BugCollection")) return failure(tool, "invalid-output");
      return {tool, status: "ok", findings: parseSpotBugs(output, sourceResolver(root, classDirs), max)};
    }
    try { JSON.parse(output); } catch { return failure(tool, "invalid-output"); }
    return {tool, status: "ok", findings: tool === "bandit" ? parseBandit(output, root, max) : parseGosec(output, root, max)};
  } finally { await rm(temp, {recursive: true, force: true}); }
}

/** All three code analyzers, one after another (SpotBugs and gosec are memory-hungry). */
export async function runCodeScanners(root: string, options: CodeScanOptions = {}): Promise<CodeScanResult[]> {
  const results: CodeScanResult[] = [];
  for (const tool of CODE_SCANNERS) {
    if (options.signal?.aborted) break;
    results.push(await runCodeScanner(tool, root, options));
  }
  return results;
}
export const scannerLabel = (tool: CodeScanner): string => ({findsecbugs: "FindSecBugs", bandit: "Bandit", gosec: "gosec"})[tool];
export const statusLine = (r: CodeScanResult): string => r.tool + ": " + (r.reason === "plugin-missing" ? "missing plugin" : r.status) + " (" + r.findings.length + " findings)";

// ---------- OSV-Scanner (dependency CVEs from a local OSV.dev database) ----------
export interface OsvVulnerability extends DependencyVulnerability {aliases: string[]}
export interface OsvScan {status: "ok" | "missing" | "failed" | "unsupported"; vulnerabilities: OsvVulnerability[]; reason?: "db-missing"}

function cvssLevel(score: number): string {
  return score >= 9 ? "CRITICAL" : score >= 7 ? "HIGH" : score >= 4 ? "MEDIUM" : score > 0 ? "LOW" : "UNKNOWN";
}
/** OSV-Scanner JSON: one row per vulnerability group and package; a CVE alias is preferred as the id (Trivy uses CVE ids). */
export function parseOsv(output: string, root: string): OsvVulnerability[] {
  let data: unknown; try { data = JSON.parse(output); } catch { return []; }
  const results = (data as {results?: unknown[]})?.results;
  if (!Array.isArray(results)) return [];
  const found: OsvVulnerability[] = [];
  for (const result of results as Record<string, unknown>[]) {
    const sourcePath = (result?.source as {path?: unknown})?.path;
    const target = typeof sourcePath === "string" ? inside(root, sourcePath) ?? basename(sourcePath) : "";
    for (const entry of ((result?.packages ?? []) as Record<string, unknown>[])) {
      const info = (entry?.package ?? {}) as Record<string, unknown>;
      const pkg = clean(info.name, 120), installed = clean(info.version, 40);
      const vulns = Array.isArray(entry?.vulnerabilities) ? entry.vulnerabilities as Record<string, unknown>[] : [];
      if (!pkg || !vulns.length) continue;
      const groups: Record<string, unknown>[] = Array.isArray(entry.groups) && entry.groups.length ? entry.groups : vulns.map(v => ({ids: [v.id], aliases: v.aliases}));
      for (const group of groups) {
        const ids = [...(Array.isArray(group.ids) ? group.ids : []), ...(Array.isArray(group.aliases) ? group.aliases : [])].map(v => clean(v, 40)).filter(Boolean);
        if (!ids.length) continue;
        const all = [...new Set(ids)];
        const id = all.find(v => /^CVE-\d{4}-\d+$/.test(v)) ?? all[0];
        const vuln = vulns.find(v => all.includes(clean(v.id, 40))) ?? {};
        const dbSeverity = clean((vuln.database_specific as {severity?: unknown})?.severity, 12).toUpperCase().replace("MODERATE", "MEDIUM");
        const score = Number(group.max_severity);
        const severity = score > 0 ? cvssLevel(score) : ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(dbSeverity) ? dbSeverity : "UNKNOWN";
        let fixed: string | undefined;
        for (const affected of (Array.isArray(vuln.affected) ? vuln.affected : []) as Record<string, unknown>[]) {
          if (clean((affected?.package as {name?: unknown})?.name, 120) !== pkg) continue;
          for (const range of (Array.isArray(affected.ranges) ? affected.ranges : []) as {events?: {fixed?: unknown}[]}[])
            for (const event of range?.events ?? []) if (event?.fixed && !fixed) fixed = clean(event.fixed, 80);
        }
        found.push({id, aliases: all.filter(v => v !== id), pkg, installed, fixed, severity, title: clean(vuln.summary, 140), target, source: "osv"});
      }
    }
  }
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
  return found.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity) || a.id.localeCompare(b.id));
}

const normalizePkg = (pkg: string): string => pkg.toLowerCase().replace(/[-_.]+/g, "-");
/** Trivy rows plus the OSV rows Trivy did not report: same package and the same id or alias (CVE/GHSA) counts once. */
export function mergeOsv(trivy: readonly DependencyVulnerability[], osv: readonly OsvVulnerability[]): DependencyVulnerability[] {
  const known = new Set(trivy.map(v => normalizePkg(v.pkg) + "|" + v.id.toUpperCase()));
  const extra = osv.filter(v => ![v.id, ...v.aliases].some(id => known.has(normalizePkg(v.pkg) + "|" + id.toUpperCase())));
  return [...trivy, ...extra.map(({aliases: _aliases, ...rest}) => rest)];
}

/** OSV-Scanner in --offline mode: never calls OSV.dev or deps.dev; without a downloaded database it reports "missing". */
export async function runOsvScanner(root: string, signal?: AbortSignal, large = false): Promise<OsvScan> {
  const temp = await mkdtemp(join(tmpdir(), "hushavyr-osv-"));
  const report = join(temp, "osv.json");
  try {
    let stderr = "";
    try {
      await exec("osv-scanner", ["scan", "source", "--offline", "--no-resolve", "--format", "json", "--output-file", report, "--verbosity", "error", "-r", "."],
        {cwd: root, timeout: (large ? 600 : 180) * 1000, maxBuffer: 16 * 1024 * 1024, windowsHide: true, signal});
    } catch (e) {
      const err = e as Omit<NodeJS.ErrnoException, "code"> & {code?: string | number; stderr?: string};
      if (err.code === "ENOENT") return {status: "missing", vulnerabilities: []};
      if (signal?.aborted || err.name === "AbortError") return {status: "failed", vulnerabilities: []};
      // Exit 1: vulnerabilities found. 128: no packages found. 127: error, e.g. no offline database.
      if (err.code === 128) return {status: "unsupported", vulnerabilities: []};
      stderr = String(err.stderr ?? "");
      if (/offline version of the OSV database|could not load db/i.test(stderr)) return {status: "missing", vulnerabilities: [], reason: "db-missing"};
      if (err.code !== 1) return {status: "failed", vulnerabilities: []};
    }
    let output: string;
    try { output = await readFile(report, "utf8"); JSON.parse(output); } catch { return {status: "failed", vulnerabilities: []}; }
    return {status: "ok", vulnerabilities: parseOsv(output, root)};
  } finally { await rm(temp, {recursive: true, force: true}); }
}

/** Folders OSV-Scanner reads its offline database from (OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY, else the user cache, else temp). */
export function osvDatabaseDirs(env: NodeJS.ProcessEnv = process.env, platform = process.platform, home = homedir()): string[] {
  const cache = platform === "darwin" ? join(home, "Library", "Caches") : platform === "win32" ? env.LOCALAPPDATA : env.XDG_CACHE_HOME || join(home, ".cache");
  return env.OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY ? [env.OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY] : [cache && join(cache, "osv-scanner"), join(tmpdir(), "osv-scanner")].filter((d): d is string => !!d);
}
/** Whether any ecosystem database (…/<ecosystem>/all.zip) was downloaded. */
export async function hasOsvDatabase(dirs = osvDatabaseDirs()): Promise<boolean> {
  for (const dir of dirs) if ((await find(dir, (rel, isDir) => !isDir && rel.endsWith("all.zip"), 1, 3)).length) return true;
  return false;
}

export interface CombinedAudit {audit: DependencyAudit; osv: OsvScan; vulnerabilities: DependencyVulnerability[]; totals: string[]}
/** Trivy and OSV-Scanner together, deduplicated; either may be missing. */
export async function auditDependenciesWithOsv(root: string, signal?: AbortSignal, large = false): Promise<CombinedAudit> {
  const audit = await auditDependencies(root, signal);
  const osv: OsvScan = audit.status === "unsupported" ? {status: "unsupported", vulnerabilities: []} : await runOsvScanner(root, signal, large);
  const vulnerabilities = mergeOsv(audit.vulnerabilities ?? [], osv.vulnerabilities);
  const added = vulnerabilities.length - (audit.vulnerabilities ?? []).length;
  return {audit, osv, vulnerabilities, totals: ["trivy: " + audit.status + " (" + audit.findings + " vulnerabilities)",
    "osv-scanner: " + (osv.reason === "db-missing" ? "no offline database" : osv.status) + " (" + added + " additional vulnerabilities)"]};
}
