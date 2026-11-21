import { spawn } from "node:child_process";
import { access, realpath } from "node:fs/promises";
import { join } from "node:path";

// User selects a fixed project runner. Model text is never a command or argument.
export const testProfiles = {
  npm: {label: "npm test", executable: "npm", args: ["test"]},
  maven: {label: "mvn test", executable: "mvn", args: ["test"]},
  "maven-wrapper": {label: "./mvnw test", executable: "./mvnw", args: ["test"]},
  gradle: {label: "gradle test", executable: "gradle", args: ["test"]},
  "gradle-wrapper": {label: "./gradlew test", executable: "./gradlew", args: ["test"]},
  pytest: {label: "python -m pytest", executable: "python", args: ["-m", "pytest"]}
} as const;
export type TestProfile = keyof typeof testProfiles;

const MARKERS: Record<TestProfile, string[]> = {
  npm: ["package.json"], maven: ["pom.xml"], "maven-wrapper": ["mvnw"],
  gradle: ["build.gradle", "build.gradle.kts"], "gradle-wrapper": ["gradlew"],
  pytest: ["pytest.ini", "pyproject.toml", "setup.cfg", "setup.py", "tox.ini", "conftest.py"]
};
/** Runners whose build file exists in the project root; all runners when none is recognised. */
export async function detectTestProfiles(dir: string): Promise<TestProfile[]> {
  const all = Object.keys(testProfiles) as TestProfile[];
  const found: TestProfile[] = [];
  for (const profile of all)
    for (const marker of MARKERS[profile])
      if (await access(join(dir, marker)).then(() => true, () => false)) { found.push(profile); break; }
  return found.length ? found : all;
}
export interface TestRunOptions { cwd: string; profile: TestProfile; trusted: boolean; timeoutMs?: number; signal?: AbortSignal }
export interface TestReceipt { profile: string; status: "passed" | "failed" | "cancelled" | "timed-out" | "unavailable"; exitCode: number | null; durationMs: number }

/** Runs existing trusted workspace tests, never generated code or model-provided shell. */
export async function runRegressionTests(options: TestRunOptions): Promise<TestReceipt> {
  if (!options.trusted) throw new Error("Tests require a trusted workspace");
  if (!Object.hasOwn(testProfiles, options.profile)) throw new Error("Unknown test profile");
  const timeoutMs = options.timeoutMs ?? 120000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600000) throw new Error("Invalid test timeout");
  const cwd = await realpath(options.cwd);
  const profile = testProfiles[options.profile];
  const started = Date.now();
  const receipt = (status: TestReceipt["status"], exitCode: number | null): TestReceipt =>
    ({profile: profile.label, status, exitCode, durationMs: Date.now() - started});
  if (options.signal?.aborted) return receipt("cancelled", null);
  return new Promise(resolve => {
    let timedOut = false, cancelled = false, settled = false;
    // A process group lets cancellation stop wrappers and their descendants on macOS/Linux.
    const child = spawn(profile.executable, [...profile.args], {cwd, shell: false, stdio: "ignore", detached: process.platform !== "win32"});
    const stop = (): void => {
      try {
        if (process.platform !== "win32" && child.pid) process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch { /* process already exited */ }
    };
    const abort = (): void => { cancelled = true; stop(); };
    const timer = setTimeout(() => { timedOut = true; stop(); }, timeoutMs);
    options.signal?.addEventListener("abort", abort, {once: true});
    if (options.signal?.aborted) abort();
    const finish = (status: TestReceipt["status"], code: number | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", abort);
      resolve(receipt(status, code));
    };
    child.once("error", () => finish(cancelled ? "cancelled" : "unavailable", null));
    child.once("close", code => finish(cancelled ? "cancelled" : timedOut ? "timed-out" : code === 0 ? "passed" : "failed", code));
  });
}
export function formatTestReceipt(receipt: TestReceipt): string {
  return "**Existing test suite:** " + receipt.status + " · " + receipt.profile +
    " · exit code " + (receipt.exitCode ?? "none") + " · " + receipt.durationMs + " ms.\n\n" +
    "This run does not confirm or disprove individual review findings. No generated tests were installed or executed. Output stays local and is not added to model context.";
}
