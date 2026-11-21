import {test} from "node:test";
import {strict as assert} from "node:assert";
import {mkdtemp, writeFile, rm, mkdir, chmod} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {parseBandit, parseGosec, parseSpotBugs, sourceResolver, findClassDirs, runCodeScanner, parseOsv, mergeOsv, runOsvScanner, hasOsvDatabase, osvDatabaseDirs} from "../codeScanners";
import {DependencyVulnerability} from "../dependencyAudit";
import {scanFolder} from "../cli";

const banditRow = (over: object) => ({filename: "./app/main.py", line_number: 6, issue_severity: "HIGH", issue_confidence: "HIGH", test_id: "B602",
  issue_text: "subprocess call with shell=True identified, security issue.", issue_cwe: {id: 78}, code: "6     subprocess.call(SECRET_CMD, shell=True)", ...over});

test("Bandit keeps only medium/high severity and confidence, outside tests, without code snippets", () => {
  const output = JSON.stringify({errors: [], results: [
    banditRow({}),
    banditRow({line_number: 9, issue_confidence: "LOW", test_id: "B301"}),
    banditRow({line_number: 10, issue_severity: "LOW", test_id: "B311"}),
    banditRow({line_number: 11, test_id: "B101", issue_severity: "MEDIUM"}),
    banditRow({filename: "./tests/test_main.py"}),
    banditRow({filename: "./app/test_util.py"}),
    banditRow({filename: "../outside.py"}),
    banditRow({line_number: 12, issue_severity: "MEDIUM", issue_confidence: "MEDIUM", test_id: "B608", issue_cwe: {id: 89}})
  ]});
  const findings = parseBandit(output, "/repo");
  assert.deepEqual(findings.map(f => [f.rule, f.path, f.line, f.severity, f.cwe]), [["bandit-B602", "app/main.py", 6, "HIGH", 78], ["bandit-B608", "app/main.py", 12, "MEDIUM", 89]]);
  assert.doesNotMatch(JSON.stringify(findings), /SECRET_CMD/);
  assert.deepEqual(parseBandit("not json", "/repo"), []);
});

test("gosec drops G104, test files and duplicate rules for the same weakness on one line", () => {
  const issue = (over: object) => ({severity: "HIGH", confidence: "HIGH", cwe: {id: "89"}, rule_id: "G201", details: "SQL string formatting",
    file: "/repo/db/main.go", code: "12: db.Query(...)", line: "12", ...over});
  const output = JSON.stringify({Issues: [
    issue({}), issue({rule_id: "G701", details: "SQL injection via taint analysis"}),
    issue({rule_id: "G104", cwe: {id: "703"}, line: "14"}),
    issue({file: "/repo/db/main_test.go", rule_id: "G204", cwe: {id: "78"}}),
    issue({rule_id: "G204", cwe: {id: "78"}, line: "13-15", severity: "MEDIUM"}),
    issue({rule_id: "G401", cwe: {id: "328"}, line: "20", confidence: "LOW"})
  ]});
  assert.deepEqual(parseGosec(output, "/repo").map(f => [f.rule, f.path, f.line, f.severity]), [["gosec-G201", "db/main.go", 12, "HIGH"], ["gosec-G204", "db/main.go", 13, "MEDIUM"]]);
});

const bug = (type: string, attrs: string, line: number, sourcepath = "com/demo/Dao.java") => `
  <BugInstance type="${type}" ${attrs}>
    <ShortMessage>Potential ${type}</ShortMessage>
    <LongMessage>Uses com.demo.Dao.secretMethod</LongMessage>
    <Class classname="com.demo.Dao" primary="true"><SourceLine classname="com.demo.Dao" start="7" end="17" sourcefile="Dao.java" sourcepath="${sourcepath}"/></Class>
    <Method classname="com.demo.Dao" name="find" primary="true"><SourceLine classname="com.demo.Dao" start="9" end="11" sourcepath="${sourcepath}"/></Method>
    <SourceLine classname="com.demo.Dao" primary="true" start="${line}" end="${line}" sourcefile="Dao.java" sourcepath="${sourcepath}"/>
  </BugInstance>`;

test("FindSecBugs reports security bugs at the primary source line of the real source file", () => {
  const xml = "<BugCollection version=\"4.10.5\">" +
    bug("SQL_INJECTION_JDBC", "priority=\"2\" rank=\"12\" category=\"SECURITY\" cweid=\"89\"", 10) +
    bug("SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE", "priority=\"1\" rank=\"10\" category=\"SECURITY\" cweid=\"89\"", 10) +
    bug("COMMAND_INJECTION", "priority=\"2\" rank=\"12\" category=\"SECURITY\" cweid=\"78\"", 16) +
    bug("PREDICTABLE_RANDOM", "priority=\"2\" rank=\"17\" category=\"SECURITY\" cweid=\"330\"", 20) +
    bug("NP_NULL_ON_SOME_PATH", "priority=\"1\" rank=\"5\" category=\"CORRECTNESS\"", 21) +
    bug("XSS_SERVLET", "priority=\"2\" rank=\"10\" category=\"SECURITY\" cweid=\"79\"", 5, "com/demo/Missing.java") +
    "</BugCollection>";
  const root = "/repo";
  const resolve = sourceResolver(root, ["/repo/svc/target/classes"], path => path === "/repo/svc/src/main/java/com/demo/Dao.java");
  const findings = parseSpotBugs(xml, resolve);
  assert.deepEqual(findings.map(f => [f.rule, f.path, f.line, f.severity]), [
    ["findsecbugs-SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE", "svc/src/main/java/com/demo/Dao.java", 10, "HIGH"],
    ["findsecbugs-COMMAND_INJECTION", "svc/src/main/java/com/demo/Dao.java", 16, "MEDIUM"]]);
  assert.doesNotMatch(JSON.stringify(findings), /secretMethod/);
});

test("FindSecBugs finds Maven and Gradle main classes and maps Kotlin sources", async () => {
  const root = await mkdtemp(join(tmpdir(), "hushavyr-classes-"));
  try {
    await mkdir(join(root, "api", "target", "classes"), {recursive: true});
    await mkdir(join(root, "app", "build", "classes", "kotlin", "main"), {recursive: true});
    await mkdir(join(root, "app", "build", "classes", "kotlin", "test"), {recursive: true});
    await mkdir(join(root, "app", "src", "main", "kotlin", "com", "x"), {recursive: true});
    await writeFile(join(root, "app", "src", "main", "kotlin", "com", "x", "Api.kt"), "class Api\n");
    const dirs = (await findClassDirs(root)).map(d => d.slice(root.length + 1).replace(/\\/g, "/")).sort();
    assert.deepEqual(dirs, ["api/target/classes", "app/build/classes/kotlin/main"]);
    assert.equal(sourceResolver(root, await findClassDirs(root))("com/x/Api.kt"), "app/src/main/kotlin/com/x/Api.kt");
  } finally { await rm(root, {recursive: true, force: true}); }
});

test("missing analyzers, plugin or project files are skipped, never failures", async () => {
  const root = await mkdtemp(join(tmpdir(), "hushavyr-missing-"));
  const path = process.env.PATH;
  try {
    assert.deepEqual(await runCodeScanner("gosec", root), {tool: "gosec", status: "skipped", findings: [], reason: "not-applicable"});
    await writeFile(join(root, "app.py"), "import os\n");
    await writeFile(join(root, "go.mod"), "module x\n");
    await mkdir(join(root, "target", "classes"), {recursive: true});
    assert.equal((await runCodeScanner("findsecbugs", root, {findSecBugsPlugin: join(root, "none.jar")})).reason, "plugin-missing");
    process.env.PATH = join(root, "no-bin");
    for (const tool of ["bandit", "gosec"] as const) assert.deepEqual(await runCodeScanner(tool, root), {tool, status: "missing", findings: []});
    assert.deepEqual(await runOsvScanner(root), {status: "missing", vulnerabilities: []});
  } finally { process.env.PATH = path; await rm(root, {recursive: true, force: true}); }
});

const osvOutput = (root: string) => JSON.stringify({results: [{source: {path: join(root, "web", "package-lock.json"), type: "lockfile"}, packages: [{
  package: {name: "lodash", version: "4.17.20", ecosystem: "npm"},
  vulnerabilities: [
    {id: "GHSA-35jh-r3h4-6jhm", aliases: ["CVE-2021-23337"], summary: "Command Injection in lodash", database_specific: {severity: "HIGH"},
      affected: [{package: {name: "lodash", ecosystem: "npm"}, ranges: [{type: "SEMVER", events: [{introduced: "0"}, {fixed: "4.17.21"}]}]}]},
    {id: "GHSA-29mw-wpgm-hmr9", aliases: ["CVE-2020-28500"], summary: "ReDoS in lodash", database_specific: {severity: "MODERATE"},
      affected: [{package: {name: "lodash", ecosystem: "npm"}, ranges: [{type: "SEMVER", events: [{introduced: "4.0.0"}, {fixed: "4.17.21"}]}]}]},
    {id: "GHSA-p6mc-m468-83gw", aliases: [], summary: "Prototype pollution", database_specific: {severity: "HIGH"}, affected: []}],
  groups: [{ids: ["GHSA-35jh-r3h4-6jhm"], aliases: ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"], max_severity: "7.2"},
    {ids: ["GHSA-29mw-wpgm-hmr9"], aliases: ["CVE-2020-28500", "GHSA-29mw-wpgm-hmr9"], max_severity: "5.3"},
    {ids: ["GHSA-p6mc-m468-83gw"], aliases: [], max_severity: ""}]}]}]});

test("OSV-Scanner rows prefer CVE ids, carry fixes and severity, and are deduplicated against Trivy", () => {
  const osv = parseOsv(osvOutput("/repo"), "/repo");
  assert.deepEqual(osv.map(v => [v.id, v.severity, v.fixed, v.target]), [
    ["CVE-2021-23337", "HIGH", "4.17.21", "web/package-lock.json"], ["GHSA-p6mc-m468-83gw", "HIGH", undefined, "web/package-lock.json"],
    ["CVE-2020-28500", "MEDIUM", "4.17.21", "web/package-lock.json"]]);
  const trivy: DependencyVulnerability[] = [
    {id: "CVE-2021-23337", pkg: "lodash", installed: "4.17.20", severity: "HIGH", title: "lodash: command injection", target: "web/package-lock.json"},
    {id: "GHSA-p6mc-m468-83gw", pkg: "Lodash", installed: "4.17.20", severity: "HIGH", title: "", target: "web/package-lock.json"},
    {id: "CVE-2020-28500", pkg: "other-package", installed: "1.0.0", severity: "MEDIUM", title: "", target: "package-lock.json"}];
  const merged = mergeOsv(trivy, osv);
  assert.deepEqual(merged.slice(3).map(v => [v.id, v.pkg, v.source]), [["CVE-2020-28500", "lodash", "osv"]]);
  assert.equal(merged.length, 4);
  assert.deepEqual(parseOsv("{}", "/repo"), []);
});

test("OSV offline database is detected only when an ecosystem archive exists", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hushavyr-osvdb-"));
  try {
    assert.equal(await hasOsvDatabase([dir]), false);
    await mkdir(join(dir, "osv-scalibr", "npm"), {recursive: true});
    await writeFile(join(dir, "osv-scalibr", "npm", "all.zip"), "");
    assert.equal(await hasOsvDatabase([dir]), true);
  } finally { await rm(dir, {recursive: true, force: true}); }
});

test("OSV database lookup includes the osv-scalibr cache used by OSV-Scanner v2", () => {
  const dirs = osvDatabaseDirs({}, "darwin", "/Users/dev");
  assert.ok(dirs.includes(join("/Users/dev", "Library", "Caches", "osv-scalibr")));
  assert.deepEqual(osvDatabaseDirs({OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: "/db"}, "linux", "/home/dev"), ["/db"]);
});

test("CLI adds Bandit findings with a prefixed rule id, once per line next to built-in rules", {skip: process.platform === "win32"}, async () => {
  const root = await mkdtemp(join(tmpdir(), "hushavyr-bandit-"));
  const bin = await mkdtemp(join(tmpdir(), "hushavyr-bin-"));
  const path = process.env.PATH;
  try {
    await writeFile(join(root, "app.py"), "import subprocess\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n\nTEMPLATE = 'x'\n");
    const report = JSON.stringify({results: [banditRow({filename: "./app.py", line_number: 4}), banditRow({filename: "./app.py", line_number: 6, test_id: "B608", issue_cwe: {id: 89}, issue_severity: "MEDIUM"})]});
    // A stand-in bandit that writes its report to the -o path, like the real CLI.
    await writeFile(join(bin, "bandit"), "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf '%s' '" + report + "' > \"$1\"; fi; shift; done\nexit 1\n");
    await chmod(join(bin, "bandit"), 0o755);
    process.env.PATH = bin + ":" + path;
    const results = await scanFolder(root, join(__dirname, "..", "..", "rules", "hushavyr-review.yml"));
    const bandit = results.filter(r => r.ruleId.startsWith("bandit-"));
    assert.ok(bandit.some(r => r.ruleId === "bandit-B608" && r.line === 6 && r.level === "warning"));
    const line4 = results.filter(r => r.path === "app.py" && r.line === 4);
    assert.equal(line4.length, 1);
  } finally { process.env.PATH = path; await rm(root, {recursive: true, force: true}); await rm(bin, {recursive: true, force: true}); }
});
