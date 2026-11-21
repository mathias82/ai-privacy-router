import {readFile} from "node:fs/promises";
import {join} from "node:path";
import {scanSecrets} from "./secretsScan";
import {sha256} from "./fixProof";
import {githubRepo, validateProof} from "./fixPrPolicy";
import {exec as run} from "./exec";
export type Exec = (cmd: string, args: string[], cwd: string) => Promise<string>;
export const defaultExec: Exec = async (cmd, args, cwd) =>
  (await run(cmd, args, {cwd, timeout: 120_000, windowsHide: true, maxBuffer: 4 * 1024 * 1024})).stdout;

const DEFAULT_BRANCHES = new Set(["main", "master", "develop", "dev", "trunk"]);
export function branchName(title: string, now = new Date()): string {
  const slug = title.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "changes";
  return "hushavyr/" + slug + "-" + now.toISOString().slice(0, 16).replace(/\D/g, "");
}
/** github.com compare URL from an https or ssh remote; undefined for other hosts. */
export function compareUrl(remote: string, base: string, branch: string): string | undefined {
  const repo = githubRepo(remote);
  return repo ? "https://github.com/" + repo + "/compare/" + encodeURIComponent(base) + "..." + encodeURIComponent(branch) + "?expand=1" : undefined;
}
/** Changed paths from `git status --porcelain` (renames give the new path). */
export function statusPaths(porcelain: string): string[] {
  return porcelain.split("\n").filter(l => l.length > 3).map(l => l.slice(3).replace(/^.* -> /, "").replace(/^"(.*)"$/, "$1"));
}

export interface PrPlan {root: string; current: string; base: string; files: string[]; stat: string; remote: string}
export async function planPullRequest(root: string, exec: Exec = defaultExec): Promise<PrPlan | string> {
  try { await exec("git", ["rev-parse", "--is-inside-work-tree"], root); } catch { return "This folder is not a git repository."; }
  const files = statusPaths(await exec("git", ["status", "--porcelain", "--untracked-files=all"], root));
  if (!files.length) return "There are no changes to put in a pull request.";
  const current = (await exec("git", ["rev-parse", "--abbrev-ref", "HEAD"], root)).trim();
  let remote = "";
  try { remote = (await exec("git", ["remote", "get-url", "origin"], root)).trim(); } catch { return "No `origin` remote is configured."; }
  let base = current;
  try { base = (await exec("git", ["symbolic-ref", "--short", "refs/remotes/origin/HEAD"], root)).trim().replace(/^origin\//, ""); } catch { /* keep current */ }
  let stat = "";
  try { stat = (await exec("git", ["diff", "--stat", "HEAD"], root)).replace(/^\n+|\s+$/g, ""); } catch { /* new repository */ }
  // `git diff --stat` leaves out untracked files, which the commit will still add.
  let untracked: string[] = [];
  try { untracked = (await exec("git", ["ls-files", "--others", "--exclude-standard"], root)).split("\n").filter(Boolean); } catch { /* keep the diff stat */ }
  if (untracked.length) stat = (stat ? stat + "\n" : "") + untracked.map(f => " " + f + " | new file").join("\n");
  return {root, current, base, files, stat, remote};
}

/** Changed files that look like they contain credentials; such a PR is never pushed. */
export async function secretsInChanges(plan: PrPlan): Promise<string[]> {
  const hits: string[] = [];
  for (const file of plan.files.slice(0, 200)) {
    try { if (scanSecrets(await readFile(join(plan.root, file), "utf8"), file).length) hits.push(file); } catch { /* deleted or unreadable */ }
  }
  return hits;
}

export interface PrResult {branch: string; url?: string; created: boolean}
export async function createPullRequest(plan: PrPlan, title: string, exec: Exec = defaultExec, body = ""): Promise<PrResult> {
  const branch = DEFAULT_BRANCHES.has(plan.current) || plan.current === "HEAD" ? branchName(title) : plan.current;
  if (!/^[\w./-]+$/.test(branch)) throw new Error("Invalid branch name");
  if (branch !== plan.current) await exec("git", ["switch", "-c", branch], plan.root);
  await exec("git", ["add", "-A"], plan.root);
  await exec("git", ["commit", "-m", title], plan.root);
  await exec("git", ["push", "-u", "origin", branch], plan.root);
  const base = plan.base === branch ? "main" : plan.base;
  try {
    const out = await exec("gh", ["pr", "create", "--base", base, "--head", branch, "--title", title, "--body",
      (body ? body + "\n\n" : "") + "Created with Hushavyr. Changes were prepared locally; review before merging."], plan.root);
    const url = /https:\/\/\S+/.exec(out)?.[0];
    return {branch, url, created: true};
  } catch {
    return {branch, url: compareUrl(plan.remote, base, branch), created: false};
  }
}

// Verified-fix receipts (from the local red/green/suite proof) that may become a draft PR.
export interface Stage {stage: string; exitCode: number; interrupted?: boolean; passed?: number; failures?: number; errors?: number}
export interface VerifiedReceipt {baseCommit: string; patchHash: string; stages: Stage[]}

/** The single gate for verified-fix receipts: a complete red/green/suite proof whose patch matches its hash; returns why not otherwise. */
export function checkReceipt(raw: string, patch: Buffer): VerifiedReceipt | string {
  let r: {status?: string; baseCommit?: string; patchHash?: string; stages?: Stage[]; cleanupRequiresAttention?: boolean};
  try { r = JSON.parse(raw); } catch { return "receipt.json is not valid JSON"; }
  if (r.status !== "verified") return "the fix was not verified (" + String(r.status) + ")";
  if (r.cleanupRequiresAttention) return "the sandbox cleanup needs attention first";
  if (!/^[a-f0-9]{40}$/.test(r.baseCommit ?? "") || !/^[a-f0-9]{64}$/.test(r.patchHash ?? "")) return "the receipt has no valid base commit or patch hash";
  const stage = (name: string): Stage | undefined => r.stages?.find(s => s.stage === name);
  if (!["baseline", "red", "green", "suite"].every(stage)) return "the receipt is missing proof stages";
  // red must fail on the unchanged code; green and the full suite must pass with the fix.
  if (stage("red")!.exitCode === 0) return "the regression test did not fail before the fix";
  for (const s of ["green", "suite"]) if (stage(s)!.exitCode !== 0 || stage(s)!.interrupted) return "the " + s + " run did not pass";
  if (patch.length === 0 || patch.length > 1024 * 1024) return "the patch is empty or too large";
  if (sha256(patch) !== r.patchHash) return "the patch does not match its hash";
  // Strict policy last: exact stage order, test counts and test hash.
  try { validateProof(r as never, patch); } catch (e) { return "the proof is incomplete: " + (e as Error).message; }
  return {baseCommit: r.baseCommit!, patchHash: r.patchHash!, stages: r.stages!};
}

/** Lines the patch adds; only these are checked for credentials. */
export function addedLines(patch: string): string {
  return patch.split("\n").filter(l => l.startsWith("+") && !l.startsWith("+++")).map(l => l.slice(1)).join("\n");
}

export function prBody(receipt: VerifiedReceipt): string {
  const counts = receipt.stages.map(s => "- " + s.stage + ": exit " + s.exitCode + (s.passed !== undefined ? ", " + s.passed + " passed" : "") +
    (s.failures ? ", " + s.failures + " failed" : ""));
  return ["Generated by Hushavyr from a local red/green/suite proof (offline Docker, local model only).", "",
    "Base commit: " + receipt.baseCommit, "", ...counts, "",
    "The user reviewed the patch and approved this branch and draft PR. Let CI rerun the tests and review before merging."].join("\n");
}

