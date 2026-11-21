import { test } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runRegressionTests, formatTestReceipt, TestProfile, detectTestProfiles } from "../regression";
async function fixture(script: string, run: (cwd: string) => Promise<void>) {
  const cwd = await mkdtemp(join(tmpdir(), "router-tests-"));
  try {
    await writeFile(join(cwd, "package.json"), JSON.stringify({scripts: {test: "node test.cjs"}}));
    await writeFile(join(cwd, "test.cjs"), script);
    await run(cwd);
  } finally {await rm(cwd, {recursive: true, force: true});}
}
test("executes actual selected project tests and records exit status", async () => {
  for (const code of [0, 7]) await fixture('process.exit(' + code + ')', async cwd => {
    const receipt = await runRegressionTests({cwd, profile: "npm", trusted: true});
    assert.equal(receipt.status, code === 0 ? "passed" : "failed");
    assert.equal(receipt.exitCode, code);
    assert.match(formatTestReceipt(receipt), /does not confirm or disprove/);
  });
});
test("untrusted projects and model-like command injection never execute", async () => {
  await assert.rejects(runRegressionTests({cwd: ".", profile: "npm", trusted: false}));
  await assert.rejects(runRegressionTests({cwd: ".", profile: "npm; echo injected" as TestProfile, trusted: true}));
});
test("test execution timeout and cancellation stop the child group", async () => {
  await fixture('setInterval(() => {}, 1000)', async cwd => {
    const receipt = await runRegressionTests({cwd, profile: "npm", trusted: true, timeoutMs: 300});
    assert.equal(receipt.status, "timed-out");
    const controller = new AbortController();
    const pending = runRegressionTests({cwd, profile: "npm", trusted: true, signal: controller.signal});
    const timer = setTimeout(() => controller.abort(), 300);
    try { assert.equal((await pending).status, "cancelled"); } finally { clearTimeout(timer); }
  });
});
test("missing runner returns unavailable and pre-cancellation executes nothing", async () => {
  await fixture('process.exit(0)', async cwd => {
    assert.equal((await runRegressionTests({cwd, profile: "maven-wrapper", trusted: true})).status, "unavailable");
    const controller = new AbortController(); controller.abort();
    assert.equal((await runRegressionTests({cwd, profile: "npm", trusted: true, signal: controller.signal})).status, "cancelled");
  });
});

test("only runners whose build file exists are offered", async () => {
  const dir = await mkdtemp(join(tmpdir(), "runners-"));
  assert.equal((await detectTestProfiles(dir)).length, 6);
  await writeFile(join(dir, "package.json"), "{}");
  await writeFile(join(dir, "pom.xml"), "<project/>");
  assert.deepEqual(await detectTestProfiles(dir), ["npm", "maven"]);
  await rm(dir, {recursive: true});
});
