import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtemp, writeFile, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { staticReview, semgrepToFindings } from "../staticReview";
import { mergeFindings, runLocalReview, LENSES } from "../localReview";
import { callContext, definitionSnippet } from "../callContext";
import { collectImports, reachability, vulnerableSymbols, findVulnerableCall } from "../reachability";
import { toSarif, sarifLevel } from "../sarif";
import { ResultCache } from "../reviewCache";
import { scanFolder } from "../cli";
import { staticGateProblems } from "../benchmark";
import { reviewSummary, Finding } from "../review";

const sqlSource = [{path: "file:///Repo.java", text: "class Repo {\n  void find(String id) {\n    stmt.executeQuery(\"SELECT * FROM t WHERE id=\" + id);\n  }\n}"}];
const semgrepJson = JSON.stringify({results: [{path: "f0.java", start: {line: 3},
  extra: {message: "SQL built by concatenation", severity: "ERROR", metadata: {fix: "Use PreparedStatement", test: "Quote in id"}}}]});

test("static review maps semgrep hits back to the original file and line", async () => {
  const result = await staticReview(sqlSource, "rules.yml", async (args, cwd) => {
    assert.ok(args.includes("--metrics=off"));
    assert.ok(cwd.includes("hushavyr-review-"));
    return semgrepJson;
  });
  assert.equal(result.status, "ok");
  assert.deepEqual(result.findings.map(f => [f.path, f.line, f.severity, f.fix]), [["file:///Repo.java", 3, "high", "Use PreparedStatement"]]);
  assert.match(result.findings[0].title, /^Local rule: SQL/);
  assert.deepEqual(semgrepToFindings("not json", sqlSource), []);
});

test("static review falls back to bundled rules when semgrep is missing", async () => {
  const missing = await staticReview(sqlSource, "rules.yml", async () => { throw Object.assign(new Error("no"), {code: "ENOENT"}); });
  assert.equal(missing.status, "missing");
  assert.ok(missing.findings.every(f => f.severity === "high" && f.path === "file:///Repo.java"));
});

const finding = (line: number, title = "Issue " + line): Finding => ({title, severity: "medium", evidence: "x".repeat(10),
  fix: "fix", regressionTest: "test", status: "potential", path: "file:///A.java", line});

test("mergeFindings keeps the first finding per location", () => {
  const merged = mergeFindings([finding(3, "model")], [finding(3, "static"), finding(9)]);
  assert.deepEqual(merged.map(f => f.title), ["model", "Issue 9"]);
});

test("thorough review runs the general pass plus each lens and merges static candidates", async () => {
  const prompts: string[] = [];
  const client = {generate: async (prompt: string) => { prompts.push(prompt); return '{"findings":[]}'; }};
  const result = await runLocalReview(client, "review", sqlSource, () => false, undefined,
    {depth: "thorough", staticFindings: Promise.resolve([{...finding(3), path: "file:///Repo.java", evidence: sqlSource[0].text.split("\n")[2].trim()}])});
  assert.equal(prompts.length, 1 + LENSES.length);
  assert.ok(prompts.slice(1).every((p, i) => p.startsWith(prompts[0]) && p.endsWith(LENSES[i])));
  assert.equal(result?.staticCandidates, 1);
  assert.ok(result?.findings.some(f => f.line === 3));
});

test("light review runs one short pass and still keeps static candidates", async () => {
  const calls: {maxTokens?: number}[] = [];
  const client = {generate: async (_prompt: string, options?: {maxTokens?: number}) => { calls.push(options ?? {}); return '{"findings":[]}'; }};
  const result = await runLocalReview(client, "review", sqlSource, () => false, undefined,
    {depth: "light", staticFindings: Promise.resolve([{...finding(3), path: "file:///Repo.java", evidence: sqlSource[0].text.split("\n")[2].trim()}])});
  assert.equal(calls.length, 1);
  assert.equal(calls[0].maxTokens, 1536);
  assert.ok(result?.findings.some(f => f.line === 3));
});

test("call context pulls the callee definition from another file", () => {
  const caller = {path: "file:///Svc.java", text: "class Svc { void run(String id) { repo.lookup(id); } }"};
  const files = [{path: "file:///Repo.java", text: "class Repo {\n  void lookup(String id) {\n    query(id);\n  }\n}"}];
  const extra = callContext(caller, files);
  assert.equal(extra.length, 1);
  assert.equal(extra[0].path, "file:///Repo.java");
  assert.equal(extra[0].startLine, 2);
  assert.match(extra[0].text, /query\(id\)/);
  assert.equal(definitionSnippet("def other():\n  pass", "missing"), undefined);
});

test("reachability separates imported from transitive dependencies", () => {
  const imports = new Set([...collectImports("A.java", "import com.fasterxml.jackson.databind.ObjectMapper;"),
    ...collectImports("a.ts", "import _ from \"lodash/fp\";"), ...collectImports("a.py", "import yaml, os")]);
  assert.equal(reachability("com.fasterxml.jackson.core:jackson-databind", "pom.xml", imports), "imported");
  assert.equal(reachability("org.apache.commons:commons-text", "pom.xml", imports), "not-imported");
  assert.equal(reachability("lodash", "package-lock.json", imports), "imported");
  assert.equal(reachability("PyYAML", "requirements.txt", imports), "imported");
  assert.equal(reachability("lodash", "package-lock.json", new Set()), "unknown");
});

test("SARIF output is valid 2.1.0 with mapped levels", () => {
  const sarif = toSarif([{ruleId: "sql", message: "m", path: "./src\\A.java", line: 0, level: sarifLevel("HIGH")}], "1.0.0") as any;
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].results[0].level, "error");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "src/A.java");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 1);
  assert.equal(sarifLevel("moderate"), "warning");
  assert.equal(sarifLevel("low"), "note");
});

test("result cache is keyed by content and evicts the least recently used entry", () => {
  const cache = new ResultCache<number>(2);
  assert.equal(ResultCache.key("m", [{text: "a"}]), ResultCache.key("m", [{text: "a"}]));
  assert.notEqual(ResultCache.key("m", [{text: "a"}]), ResultCache.key("m", [{text: "b"}]));
  cache.set("a", 1); cache.set("b", 2); cache.get("a"); cache.set("c", 3);
  assert.equal(cache.get("b"), undefined);
  assert.equal(cache.get("a"), 1);
});

test("CLI folder scan reports credentials and skips dependency folders", async () => {
  const root = await mkdtemp(join(tmpdir(), "hushavyr-cli-"));
  try {
    await writeFile(join(root, "config.js"), "const password = \"hunter2-super-secret-value\";\n");
    await writeFile(join(root, "package-lock.json"), "{\n  \"password\": \"hunter2-super-secret-value\"\n}\n");
    await mkdir(join(root, "node_modules"));
    await writeFile(join(root, "node_modules", "dep.js"), "const password = \"hunter2-super-secret-value\";\n");
    const results = await scanFolder(root, join(__dirname, "..", "..", "rules", "hushavyr-review.yml"));
    assert.ok(results.some(r => r.path === "config.js" && r.level === "error"));
    assert.ok(results.every(r => !r.path.startsWith("node_modules") && r.path !== "package-lock.json"));
  } finally { await rm(root, {recursive: true, force: true}); }
});

test("static gate fails on missing semgrep, false positives or missed security cases", () => {
  const ok = {semgrep: "ok", fixtureCount: 35, truePositives: 10, falsePositives: 0, securityRecall: 1, missed: [], falsePositiveCases: []};
  assert.deepEqual(staticGateProblems(ok as any), []);
  assert.equal(staticGateProblems({...ok, semgrep: "missing"} as any).length > 0, true);
  assert.equal(staticGateProblems({...ok, falsePositives: 1, falsePositiveCases: ["x"]} as any).length > 0, true);
  assert.equal(staticGateProblems({...ok, securityRecall: 0.5, missed: ["y"]} as any).length > 0, true);
});

test("review summary names the most serious issue to fix first", () => {
  const summary = reviewSummary({findings: [finding(2, "Minor"), {...finding(7, "Local rule: SQL injection"), severity: "high"}], rejected: 0});
  assert.match(summary, /2 issue/);
  assert.match(summary, /Fix first:\*\* SQL injection \(`A.java:7`\)/);
  assert.match(reviewSummary({findings: [], rejected: 0}), /nothing to fix/);
});

test("a /review marker maps to the right offline runner and nearest project", async () => {
  const { runnerFor, projectRootFor } = await import("../proofTarget");
  assert.equal(runnerFor("/w/app/src/main/java/A.java"), "Java / Maven");
  assert.equal(runnerFor("/w/a.mts"), "TypeScript / Node.js");
  assert.equal(runnerFor("/w/a.go"), "Go / go test");
  assert.equal(runnerFor("/w/a.rb"), undefined);
  const files = new Set(["/w/svc/pom.xml", "/w/pom.xml"]);
  assert.equal(projectRootFor("/w/svc/src/main/java/A.java", "Java / Maven", "/w", p => files.has(p)), "/w/svc");
  assert.equal(projectRootFor("/w/lib/x.py", "Python / pytest", "/w", p => files.has(p)), undefined);
});

test("a bug counts as reproduced only when the approved test failed by assertion", async () => {
  const { bugReproduced } = await import("../fixProof");
  const red = {stage: "red" as const, exitCode: 1, interrupted: false, durationMs: 1, passed: 0, failures: 1, errors: 0, skipped: 0, caseSetHash: ""};
  const receipt = {baseCommit: "", imageId: "", testClass: "T", testPath: "t", policyVersion: "node-red-green-v1" as const,
    runId: "", startedAtUtc: "", status: "not-verified" as const, reason: "fix-not-approved", stages: [red]};
  assert.equal(bugReproduced(receipt), true);
  assert.equal(bugReproduced({...receipt, stages: [{...red, failures: 0, errors: 1}]}), false);
  assert.equal(bugReproduced({...receipt, reason: "regression-not-reproduced"}), false);
});

test("team dismissals are stored in the repo and hide the same finding after it moves", async () => {
  const { addDismissal, loadDismissals, withoutDismissed, fingerprint } = await import("../teamMemory");
  const root = await mkdtemp(join(tmpdir(), "hushavyr-team-"));
  try {
    await addDismissal(root, {fingerprint: fingerprint("src/A.java", "  run(id);  "), path: "src/A.java", reason: "id is validated\nupstream"});
    await addDismissal(root, {fingerprint: fingerprint("src/A.java", "run(id);"), path: "src/A.java", reason: "duplicate"});
    const list = await loadDismissals(root);
    assert.equal(list.length, 1);
    assert.equal(list[0].reason, "id is validated upstream");
    const moved = {...finding(40), evidence: "run(id);", path: "file:///w/src/A.java"};
    const other = {...finding(41), evidence: "exec(cmd);", path: "file:///w/src/A.java"};
    const result = withoutDismissed([moved, other], list, p => p.replace("file:///w/", ""));
    assert.deepEqual(result.kept, [other]);
    assert.equal(result.hidden, 1);
    assert.deepEqual(await loadDismissals(join(root, "missing")), []);
  } finally { await rm(root, {recursive: true, force: true}); }
});

test("team rules file is capped and added to the review instruction as criteria", async () => {
  const { loadTeamRules, withTeamRules } = await import("../teamMemory");
  const root = await mkdtemp(join(tmpdir(), "hushavyr-rules-"));
  try {
    assert.equal(await loadTeamRules(root), "");
    assert.equal(withTeamRules("Review", ""), "Review");
    await mkdir(join(root, ".hushavyr"));
    await writeFile(join(root, ".hushavyr", "rules.md"), "- Never log tokens\n\n\n\n- " + "x".repeat(5000));
    const rules = await loadTeamRules(root);
    assert.ok(rules.startsWith("- Never log tokens\n\n- x"));
    assert.ok(Buffer.byteLength(rules) <= 3000);
    const instruction = withTeamRules("Review", rules);
    assert.ok(instruction.startsWith("Review\n\nTEAM REVIEW STANDARDS"));
    assert.ok(instruction.includes("Never log tokens"));
  } finally { await rm(root, {recursive: true, force: true}); }
});

test("PR review keeps only findings on changed lines and renders a safe comment", async () => {
  const { changedLines, onChangedLines, prComment, COMMENT_MARKER } = await import("../prReview");
  const diff = ["diff --git a/src/A.java b/src/A.java", "--- a/src/A.java", "+++ b/src/A.java", "@@ -10,0 +11,2 @@", "+x", "+y", "@@ -30 +32 @@", "-a", "+b",
    "+++ /dev/null", "@@ -1,3 +0,0 @@"].join("\n");
  const changed = changedLines(diff);
  assert.deepEqual([...changed.keys()], ["src/A.java"]);
  assert.deepEqual([...changed.get("src/A.java")!].sort((a, b) => a - b), [11, 12, 32]);
  const kept = onChangedLines([{...finding(12), evidence: "x"}, {...finding(80), evidence: "z"}], changed.get("src/A.java")!);
  assert.deepEqual(kept.map(f => f.line), [12]);
  const md = prComment([{...finding(12), path: "src/A.java", title: "XSS <script>|`x`", fix: "escape\noutput"}], 1, 2);
  assert.ok(md.startsWith(COMMENT_MARKER));
  assert.ok(!md.includes("<script>") && md.includes("escape output") && md.includes("2 finding(s) hidden"));
  assert.ok(prComment([], 3, 0).includes("No bugs or security issues found in the changed lines of 3 file(s)."));
});

test("taint follows request input across files and functions to the sink", async () => {
  const { taintFlows, flowTitle } = await import("../taint");
  const js = taintFlows([
    {path: "routes.js", text: "app.get('/u', (req, res) => {\n  const id = req.query.id;\n  res.json(users.find(id));\n});\napp.get('/n', (req, res) => res.json(users.find(parseInt(req.query.n))));"},
    {path: "users.js", text: "function find(id) {\n  return load(id);\n}\nfunction load(key) {\n  return db.query(\"SELECT * FROM u WHERE id=\" + key);\n}\nfunction safe(id) {\n  return db.query(\"SELECT * FROM u WHERE id=?\", [id]);\n}"}
  ]);
  assert.equal(js.length, 1);
  assert.deepEqual(js[0], {kind: "sql", source: {path: "routes.js", line: 2}, sink: {path: "users.js", line: 5}, via: ["find", "load"]});
  assert.equal(flowTitle(js[0]), "SQL injection: request input reaches this sink through find → load");
  const py = taintFlows([
    {path: "app.py", text: "@app.route('/f/<name>')\ndef show(name):\n    return files.cat(name)"},
    {path: "files.py", text: "import os\ndef cat(name):\n    os.system('cat ' + name)\ndef safe(name):\n    subprocess.run(['cat', name])"}
  ]);
  assert.deepEqual(py.map(f => [f.kind, f.sink.path, f.sink.line, f.source.line]), [["command", "files.py", 3, 2]]);
  const java = taintFlows([
    {path: "Api.java", text: "class Api {\n  @GetMapping(\"/u\")\n  public User get(@RequestParam String id) {\n    return repo.byId(id);\n  }\n}"},
    {path: "Repo.java", text: "class Repo {\n  public User byId(String id) {\n    return stmt.executeQuery(\"SELECT * FROM u WHERE id=\" + id);\n  }\n}"}
  ]);
  assert.deepEqual(java.map(f => [f.kind, f.sink.path, f.sink.line, f.via]), [["sql", "Repo.java", 3, ["byId"]]]);
});

test("servlet taint covers Java sinks, constant branches, collection slots and kind-aware encoders", async () => {
  const { taintFlows } = await import("../taint");
  const servlet = (name: string, body: string) => ({path: `${name}.java`, text: `class ${name} {\n  public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {\n${body}\n  }\n}`});
  const flows = taintFlows([
    servlet("Cmd", "    String v = \"\";\n    for (Cookie c : request.getCookies()) {\n      v = c.getValue();\n    }\n    new ProcessBuilder(\"sh\", \"-c\", v).start();"),
    servlet("Dead", "    String p = request.getParameter(\"p\");\n    String bar;\n    int n = 86;\n    if ((7 * 42) - n > 200) bar = \"safe\";\n    else bar = p;\n    String g = \"ABC\";\n    switch (g.charAt(1)) {\n      case 'A': bar = p; break;\n      case 'B': bar = bar + \"x\"; break;\n      default: bar = p;\n    }\n    response.getWriter().println(bar);"),
    servlet("Slots", "    String p = request.getHeader(\"h\");\n    java.util.List<String> l = new java.util.ArrayList<String>();\n    l.add(\"a\");\n    l.add(p);\n    l.add(\"b\");\n    l.remove(0);\n    java.util.Map<String, Object> m = new java.util.HashMap<String, Object>();\n    m.put(\"k1\", p);\n    m.put(\"k2\", \"safe\");\n    new java.io.File(l.get(1) + (String) m.get(\"k2\"));"),
    servlet("Writer", "    String p = ctx.getRequestParameter(\"p\");\n    String safe = org.owasp.esapi.ESAPI.encoder().encodeForHTML(p);\n    java.io.PrintWriter out = response.getWriter();\n    out.println(safe);\n    out.format(java.util.Locale.US, \"%s\", new Object[] {p});\n    request.getSession().setAttribute(\"k\", safe);"),
    servlet("Ldap", "    String p = request.getParameter(\"p\");\n    DirContext ctx = helper.getDirContext();\n    ctx.search(\"ou=users\", \"(uid=\" + p + \")\", controls);\n    String init = getServletConfig().getInitParameter(\"x\");\n    Runtime.getRuntime().exec(init);")
  ]);
  assert.deepEqual(flows.map(f => [f.sink.path, f.kind, f.sink.line]).sort(), [
    ["Cmd.java", "command", 7], ["Ldap.java", "ldap", 5], ["Writer.java", "trust-boundary", 8], ["Writer.java", "xss", 7]
  ]);
});

test("function-level reachability finds a call of the vulnerable function, not just the import", () => {
  assert.deepEqual(vulnerableSymbols("left-pad", "Prototype pollution in zipObjectDeep via yaml.load()"), ["zipObjectDeep", "load"]);
  assert.deepEqual(vulnerableSymbols("lodash", "nodejs-lodash: command injection via template"), ["template"]);
  assert.deepEqual(vulnerableSymbols("lodash", "prototype pollution in zipObjectDeep function"), ["zipObjectDeep"]);
  assert.deepEqual(vulnerableSymbols("lodash", "Allocation of Resources Without Limits"), []);
  const files = [
    {path: "a.js", text: "import _ from 'lodash';\nconst x = _.map(list, f);"},
    {path: "b.js", text: "const _ = require('lodash');\n// _.template(input)\nconst html = _.template(userInput)();"},
    {path: "c.js", text: "const template = (s) => s;\ntemplate('no lodash here');"}
  ];
  assert.deepEqual(findVulnerableCall("lodash", "package-lock.json", ["template"], files), {path: "b.js", line: 3, symbol: "template"});
  assert.equal(findVulnerableCall("lodash", "package-lock.json", ["template"], files.slice(0, 1).concat(files[2])), undefined);
  const java = [{path: "M.java", text: "import com.fasterxml.jackson.databind.ObjectMapper;\nclass M { void f(ObjectMapper m) { m.enableDefaultTyping(); } }"}];
  assert.equal(findVulnerableCall("com.fasterxml.jackson.core:jackson-databind", "pom.xml", vulnerableSymbols("com.fasterxml.jackson.core:jackson-databind", "Deserialization"), java)?.line, 2);
});

test("secrets scan ignores file globs but still flags real credentials", async () => {
  const { scanSecrets } = await import("../secretsScan");
  assert.equal(scanSecrets('const secretInclude = "**/*.{env,properties,yml}";').length, 0);
  assert.equal(scanSecrets('const apiSecret = "Zq8xK2mP9vL4nR7tY1wE";').length, 1);
});

test("ignore file matches dirs, files and globs; the CLI skips them", async () => {
  const { ignoreMatcher } = await import("../teamMemory");
  const match = ignoreMatcher("# fixtures\nsrc/test/\nsrc/benchmark.ts\n**/*.gen.ts\n");
  assert.ok(match("src/test/a.test.ts"));
  assert.ok(match("src/benchmark.ts"));
  assert.ok(match("lib/x/y.gen.ts"));
  assert.ok(!match("src/benchmark.tsx"));
  assert.ok(!match("src/cli.ts"));
  const root = await mkdtemp(join(tmpdir(), "hush-ignore-"));
  try {
    await mkdir(join(root, ".hushavyr"));
    await mkdir(join(root, "fixtures"));
    await writeFile(join(root, ".hushavyr", "ignore"), "fixtures/\n");
    await writeFile(join(root, "fixtures", "bad.js"), "eval(req.query.code);\n");
    await writeFile(join(root, "app.js"), "eval(req.query.code);\n");
    const paths = (await scanFolder(root, join(__dirname, "..", "..", "rules", "hushavyr-review.yml"))).map(r => r.path);
    assert.ok(paths.includes("app.js"));
    assert.ok(!paths.some(p => p.startsWith("fixtures")));
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("escalation pseudonymizes, restores locally and blocks secrets, PII and local-only", async () => {
  const { pseudonymize, restore, escalationBlock, escalate } = await import("../escalation");
  const code = "// PaymentService owner: acme\nfunction chargeCustomer(customerId) {\n  return db.query(\"SELECT * FROM payments WHERE id=\" + customerId);\n}";
  const p = pseudonymize(code);
  assert.ok(!/chargeCustomer|customerId|payments|acme|PaymentService/.test(p.text), p.text);
  assert.ok(p.text.includes("query"));
  assert.equal(restore(p.text, p.map).replace(/\s+/g, " ").trim(), code.split("\n").slice(1).join("\n").replace(/\s+/g, " ").trim());
  const base = { path: "src/pay.js", code, question: "", localOnly: false, ignored: false };
  assert.equal(escalationBlock(base), undefined);
  assert.match(escalationBlock({ ...base, localOnly: true }) ?? "", /local-only/);
  assert.match(escalationBlock({ ...base, ignored: true }) ?? "", /ignore/);
  assert.match(escalationBlock({ ...base, code: 'const password = "Zq8xK2mP9vL4nR7tY1wE";' }) ?? "", /secret|sensitive/);
  assert.match(escalationBlock({ ...base, code: "send('maria@example.com')" }) ?? "", /sensitive/);
  assert.match(escalationBlock({ ...base, path: ".env" }) ?? "", /sensitive/);
  const sent: string[] = [], audit: string[] = [];
  const deps = (approve: boolean) => ({
    pickModel: async () => ({ id: "m", label: "M", send: async (t: string) => { sent.push(t); return "Bug in id1: concatenates id2 into s1"; } }),
    confirm: async () => approve, audit: async (e: { action: string }) => { audit.push(e.action); }, cancelled: () => false
  });
  assert.equal((await escalate(base, deps(false))).outcome, "cancelled");
  assert.equal(sent.length, 0);
  const ok = await escalate(base, deps(true));
  assert.equal(ok.outcome, "sent");
  assert.equal(sent.length, 1);
  assert.ok(!sent[0].includes("chargeCustomer"));
  assert.match(ok.text ?? "", /chargeCustomer/);
  assert.ok(audit.includes("cloud-dispatch"));
});

test("edit intent, safe edit parsing and short diff", async () => {
  const { isEditRequest, parseEdit, shortDiff } = await import("../codeEdit");
  for (const p of ["can you add them", "add logging to this method", "πρόσθεσέ τα", "μπορείς να αλλάξεις το όνομα;", "rename run to start"]) assert.ok(isEditRequest(p), p);
  for (const p of ["explain the code", "what does add do here?", "this class", "check code for bugs"]) assert.ok(!isEditRequest(p), p);
  const original = "a\nb\nc\nd\ne\n";
  assert.equal(parseEdit(JSON.stringify({ content: "a\n" }), original), undefined); // truncated
  assert.equal(parseEdit(JSON.stringify({ content: original }), original), undefined); // unchanged
  assert.equal(parseEdit(JSON.stringify({ content: "a\nb\nX\nd\ne" }), original), "a\nb\nX\nd\ne\n");
  assert.equal(shortDiff(original, "a\nb\nX\nd\ne\n"), "@@ line 3 @@\n- c\n+ X");
});

test("pull request: new branch from main, commit, push, gh fallback to compare URL", async () => {
  const { branchName, compareUrl, statusPaths, createPullRequest } = await import("../pullRequest");
  assert.equal(branchName("Add MDC checks!", new Date("2026-11-21T09:05:00Z")), "hushavyr/add-mdc-checks-202611210905");
  assert.equal(compareUrl("git@github.com:mathias82/Hushavyr.git", "main", "hushavyr/x"), "https://github.com/mathias82/Hushavyr/compare/main...hushavyr%2Fx?expand=1");
  assert.equal(compareUrl("https://dev.azure.com/org/p/_git/r", "main", "x"), undefined);
  assert.deepEqual(statusPaths(" M src/a.ts\n?? new.ts\nR  old.ts -> moved.ts\n"), ["src/a.ts", "new.ts", "moved.ts"]);
  const calls: string[] = [];
  const exec = async (cmd: string, args: string[]) => { calls.push(cmd + " " + args.join(" ")); if (cmd === "gh") throw new Error("gh missing"); return ""; };
  const result = await createPullRequest({ root: "/r", current: "main", base: "main", files: ["a.ts"], stat: "", remote: "https://github.com/o/r.git" }, "Fix bug", exec);
  assert.equal(result.created, false);
  assert.match(result.url ?? "", /^https:\/\/github.com\/o\/r\/compare\/main\.\.\.hushavyr%2Ffix-bug-/);
  assert.match(calls[0], /^git switch -c hushavyr\/fix-bug-/);
  assert.deepEqual(calls.slice(1, 3), ["git add -A", "git commit -m Fix bug"]);
  assert.match(calls[3], /^git push -u origin hushavyr\/fix-bug-/);
});

test("escalation also pseudonymizes code names used in the question", async () => {
  const { escalate } = await import("../escalation");
  const sent: string[] = [];
  const result = await escalate({ path: "a.js", code: "function chargeCustomer(amount) { return amount * 2; }", question: "rename chargeCustomer", localOnly: false, ignored: false }, {
    pickModel: async () => ({ id: "m", label: "M", send: async (t: string) => { sent.push(t); return "ok"; } }),
    confirm: async () => true, audit: async () => undefined, cancelled: () => false });
  assert.equal(result.outcome, "sent");
  assert.ok(!sent[0].includes("chargeCustomer"), sent[0]);
});

test("verified fix receipt: only a complete red/green/suite proof with a matching patch becomes a draft PR", async () => {
  const { checkReceipt, addedLines, prBody } = await import("../pullRequest");
  const { sha256 } = await import("../fixProof");
  const patch = Buffer.from("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n");
  const run = (stage: string, exitCode: number, passed: number) => ({stage, exitCode, passed, failures: exitCode, errors: 0, skipped: 0});
  const stages = [run("baseline", 0, 3), run("red", 1, 2), run("green", 0, 3), run("suite", 0, 40)];
  const receipt = (over: object) => JSON.stringify({status: "verified", reason: "red-green-and-suite-passed", baseCommit: "a".repeat(40),
    patchHash: sha256(patch), testHash: "c".repeat(64), stages, ...over});
  const ok = checkReceipt(receipt({}), patch);
  assert.ok(typeof ok !== "string");
  assert.match(prBody(ok as never), /suite: exit 0, 40 passed/);
  assert.match(String(checkReceipt(receipt({status: "not-verified"}), patch)), /not verified/);
  assert.match(String(checkReceipt(receipt({}), Buffer.from("tampered"))), /hash/);
  assert.match(String(checkReceipt(receipt({stages: stages.map(s => s.stage === "suite" ? {...s, exitCode: 1} : s)}), patch)), /suite run did not pass/);
  assert.match(String(checkReceipt(receipt({stages: stages.map(s => s.stage === "red" ? {...s, exitCode: 0} : s)}), patch)), /did not fail/);
  assert.match(String(checkReceipt(receipt({cleanupRequiresAttention: true}), patch)), /cleanup/);
  assert.match(String(checkReceipt(receipt({testHash: undefined}), patch)), /proof is incomplete/);
  assert.equal(addedLines(patch.toString()), "new");
});

test("/improve asks for real improvements and keeps a safe change summary", async () => {
  const { improveInstruction, parseSummary, isEditRequest } = await import("../codeEdit");
  assert.match(improveInstruction(), /real bugs/);
  assert.match(improveInstruction("performance"), /Focus on: performance$/);
  assert.deepEqual(parseSummary(JSON.stringify({content: "x", summary: ["Close the stream in finally", " ", "Use `textContent` <b>"]})), ["Close the stream in finally", "Use textContent <b>"]);
  assert.deepEqual(parseSummary("not json"), []);
  assert.ok(isEditRequest("βελτίωσέ το"));
  assert.ok(isEditRequest("improve error handling"));
});

test("credentials: code references and UI names are not secrets, literals still are", async () => {
  const { scanSecrets } = await import("../secretsScan");
  const none = (text: string, path = "") => assert.equal(scanSecrets(text, path).length, 0, text);
  none("    apiKey = options.ApiKey,", "A.cs");
  none("    password = password,", "Login.kt");
  none("  onPasswordChange = viewModel::onPasswordChange,", "Screen.kt");
  none("  wasPasswordFocused = true", "Screen.kt");
  none("  password = var.db_admin_password", "main.tf");
  none("X-API-Key: MY_API_KEY_VALUE", "README.md");
  none("let profilePasswordChangeState = .idle", "View.swift");
  assert.equal(scanSecrets("    password = \"s3cr3tValue\",", "Login.kt").length, 1);
  assert.equal(scanSecrets("spring.mail.password=s3cr3t9x", "application.properties").length, 1);
  assert.equal(scanSecrets("password: hunter2abc", "docker-compose.yml").length, 1);
});

test("Rust: shell commands, format! SQL and MD5 are flagged; a direct program call is not", async () => {
  const { scanSecurity } = await import("../securityRules");
  const rules = (code: string) => scanSecurity("a.rs", code).map(i => i.rule);
  assert.deepEqual(rules("Command::new(\"sh\").arg(\"-c\").arg(x)"), ["Potential command execution"]);
  assert.deepEqual(rules("c.execute(&format!(\"DELETE FROM t WHERE n = '{}'\", n), [])"), ["SQL string concatenation"]);
  assert.deepEqual(rules("md5::compute(x)"), ["Weak cryptographic hash"]);
  assert.deepEqual(rules("Command::new(\"git\").arg(\"log\").arg(x)"), []);
});

test("taint ignores method heads, other methods' locals, System.out, static helpers and other languages", () => {
  const { taintFlows } = require("../taint") as typeof import("../taint");
  const servlet = {path: "file:///S.java", text: [
    "class S {",
    "  void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {",
    "    String id = request.getParameter(\"id\");",
    "    PrintWriter out = response.getWriter();",
    "    Helper.execute(id);",
    "    evaluate(id);",
    "  }",
    "  public int execute(Connection conn, Map<String, Object> id) throws Exception {",
    "    System.out.println(\"id \" + id);",
    "    return conn.createStatement().executeUpdate(\"DELETE FROM t\");",
    "  }",
    "}"].join("\n")};
  const js = {path: "file:///lib.js", text: "function evaluate(code) {\n  return eval(code);\n}"};
  assert.deepEqual(taintFlows([servlet, js]), []);
  const real = {path: "file:///R.java", text: "class R {\n  void doGet(HttpServletRequest request) throws Exception {\n    String id = request.getParameter(\"id\");\n    stmt.executeQuery(\"SELECT * FROM t WHERE id=\" + id);\n  }\n}"};
  assert.deepEqual(taintFlows([real]).map(f => [f.kind, f.sink.line]), [["sql", 4]]);
});

test("insecure random is reported only near security use", () => {
  const { scanSecurity } = require("../securityRules") as typeof import("../securityRules");
  assert.deepEqual(scanSecurity("A.java", "double x = Math.random();"), []);
  assert.equal(scanSecurity("A.java", "String token = \"\" + new Random().nextInt();").length, 1);
});
