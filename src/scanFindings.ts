// Deterministic scan helpers shared by the workspace scan: chat links, taint flows and local rule/secret findings.
import {markDependencies} from "./dependencyMarkers";
import {groupVulnerabilities, GroupedVulnerability} from "./dependencyAudit";
import {auditDependenciesWithOsv} from "./codeScanners";
import {join} from "node:path";
import {flowSeverity, flowTitle, taintFlows, TaintFile, TaintFlow} from "./taint";
import {collectImports, findVulnerableCall, reachability, vulnerableSymbols} from "./reachability";
import {scanSecurity} from "./securityRules";
import * as vscode from "vscode";
import {offerToolInstallation} from "./setup";

/** Chat file links use the original workspace URI, never user-controlled markdown paths. */
export function findingLink(uri: vscode.Uri, line: number, label: string): string {
  const safeLabel = label.replace(/[\[\]\r\n]/g, "");
  const target = uri.with({fragment: "L" + Math.max(1, Math.trunc(line))}).toString();
  return "[" + safeLabel + "](" + target + ")";
}

export function streamFlows(flows: readonly TaintFlow[], uriOf: ReadonlyMap<string, vscode.Uri>, stream: vscode.ChatResponseStream): void {
  if (flows.length) stream.markdown("**Data flow (request input to dangerous call, across files):**\n\n");
  for (const flow of flows.slice(0, 50)) {
    const sink = uriOf.get(flow.sink.path), source = uriOf.get(flow.source.path);
    if (!sink || !source) continue;
    stream.markdown("**" + flowSeverity(flow).toUpperCase() + " · " + flowTitle(flow).replace(/[\r\n`\[\]]/g, " ") + "** · sink " + findingLink(sink, flow.sink.line, flow.sink.path + ":" + flow.sink.line) +
      " · input " + findingLink(source, flow.source.line, flow.source.path + ":" + flow.source.line) + "\n\n");
  }
}

/** Text of a small, non-binary file; undefined when unreadable, over 60 KB or binary (never sent to a model or scanner). */
export async function readSmallText(uri: vscode.Uri): Promise<string | undefined> {
  try {
    const bytes = await vscode.workspace.fs.readFile(uri);
    return bytes.length > 60_000 || bytes.includes(0) ? undefined : Buffer.from(bytes).toString("utf8");
  } catch { return undefined; }
}

/** /scan runs everything that is deterministic too: built-in rules, cross-file data flow and dependency CVEs (Trivy, OSV-Scanner). */
export async function deterministicForScan(context: vscode.ExtensionContext, files: readonly vscode.Uri[], seen: ReadonlySet<string>,
  stream: vscode.ChatResponseStream, token: vscode.CancellationToken, signal: AbortSignal): Promise<string[]> {
  const taintFiles: TaintFile[] = [];
  const depFiles: {path: string; text: string}[] = [];
  const uriOf = new Map<string, vscode.Uri>();
  const imports = new Set<string>();
  let rules = 0;
  for (const uri of files) {
    if (token.isCancellationRequested) break;
    const text = await readSmallText(uri);
    if (text === undefined) continue;
    const rel = vscode.workspace.asRelativePath(uri);
    taintFiles.push({path: rel, text});
    uriOf.set(rel, uri);
    const found = collectImports(uri.path, text);
    for (const name of found) imports.add(name);
    if (found.length) depFiles.push({path: rel, text});
    for (const finding of scanSecurity(rel, text)) {
      if (seen.has(uri.fsPath + ":" + finding.line)) continue;
      if (!rules++) stream.markdown("**Built-in security rules:**\n\n");
      stream.markdown("- **" + finding.severity + " · " + finding.rule + "** · " + findingLink(uri, finding.line, rel + ":" + finding.line) + " · " + finding.advice + "\n");
    }
  }
  if (rules) stream.markdown("\n");
  const flows = token.isCancellationRequested ? [] : taintFlows(taintFiles);
  streamFlows(flows, uriOf, stream);
  const totals = ["built-in rules: " + rules, "data flows: " + flows.length];
  for (const folder of vscode.workspace.workspaceFolders ?? []) {
    if (token.isCancellationRequested) break;
    const {audit, osv, vulnerabilities, totals: counts} = await auditDependenciesWithOsv(folder.uri.fsPath, signal);
    totals.push(...counts);
    if (audit.status === "missing") await offerToolInstallation("trivy");
    const groups = groupVulnerabilities(vulnerabilities);
    if (!groups.length) continue;
    const eco = (v: GroupedVulnerability) => v.targets.join(" ") + " " + (audit.manager ?? "");
    const rows = groups.map(v => {
      const reach = reachability(v.pkg, eco(v), imports);
      const call = reach === "imported" ? findVulnerableCall(v.pkg, eco(v), vulnerableSymbols(v.pkg, v.title ?? ""), depFiles) : undefined;
      return {v, call, rank: call ? 0 : reach === "imported" ? 1 : reach === "unknown" ? 2 : 3};
    }).sort((a, b) => a.rank - b.rank);
    stream.markdown("**Dependency vulnerabilities (" + (audit.status === "ok" ? "Trivy" : "") + (audit.status === "ok" && osv.status === "ok" ? " + " : "") + (osv.status === "ok" ? "OSV-Scanner" : "") + ", offline):** " + groups.length + " · " + rows.filter(r => r.rank === 0).length + " with the vulnerable function called · " +
      rows.filter(r => r.rank === 1).length + " imported by your code\n\n");
    for (const {v, call, rank} of rows.slice(0, 20)) {
      stream.markdown("- **" + v.severity + "** · `" + (v.id + " " + v.pkg + " " + v.installed).replace(/`/g, "") + "`" + (v.source === "osv" ? " · OSV" : "") + " · " + (v.fixed ? "fixed in `" + v.fixed.replace(/`/g, "") + "`" : "no fix") +
        (call ? " · **vulnerable function `" + call.symbol + "` called at " + findingLink(uriOf.get(call.path)!, call.line, call.path + ":" + call.line) + "**" : rank === 1 ? " · used in code" : rank === 3 ? " · _not imported directly_" : "") + "\n");
    }
    stream.markdown(rows.length > 20 ? "\n_" + (rows.length - 20) + " more: run `/dependencies` for the full list._\n\n" : "\n");
    await markDependencies(context, folder.uri, rows.map(r => r.v));
  }
  return totals;
}
