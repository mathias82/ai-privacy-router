import * as vscode from "vscode";
import {arch, platform, release, totalmem} from "node:os";
import {formatReport} from "./issueReport";

async function onPath(tool: string): Promise<boolean> {
  const {exec} = await import("./exec");
  try { await exec(tool, ["--version"], {timeout: 3000, windowsHide: true}); return true; } catch { return false; }
}

/** Opt-in only: nothing is sent unless the user reviews the report and opens the issue page themselves. */
export function registerReportIssue(context: vscode.ExtensionContext): void {
  context.subscriptions.push(vscode.commands.registerCommand("aiPrivacyRouter.reportIssue", async () => {
    const problem = await vscode.window.showInputBox({prompt: "Briefly describe the problem (do not paste code or secrets)", ignoreFocusOut: true});
    if (problem === undefined) return;
    const config = vscode.workspace.getConfiguration("aiPrivacyRouter");
    const keys = Object.keys((context.extension?.packageJSON?.contributes?.configuration?.properties ?? {}) as object)
      .map(key => key.replace(/^aiPrivacyRouter\./, ""));
    const settings = Object.fromEntries(keys.map(key => [key, config.get(key)]));
    const tools = Object.fromEntries(await Promise.all(["ollama", "docker", "semgrep", "trivy", "gitleaks", "spotbugs", "bandit", "gosec", "osv-scanner"].map(async t => [t, await onPath(t)] as const)));
    const body = formatReport({extension: String(context.extension?.packageJSON?.version ?? "unknown"), vscode: vscode.version,
      os: platform() + " " + release() + " " + arch(), memoryGb: Math.round(totalmem() / 2 ** 30), settings, tools, problem});
    const preview = await vscode.workspace.openTextDocument({content: body, language: "markdown"});
    await vscode.window.showTextDocument(preview, {preview: true});
    const choice = await vscode.window.showInformationMessage("Review the report. Open a prefilled GitHub issue with exactly this text?",
      {modal: true}, "Open GitHub issue", "Copy to clipboard");
    if (choice === "Copy to clipboard") await vscode.env.clipboard.writeText(body);
    if (choice === "Open GitHub issue") {
      const url = "https://github.com/mathias82/Hushavyr/issues/new?labels=bug&title=" + encodeURIComponent("Bug: " + problem.slice(0, 80)) +
        "&body=" + encodeURIComponent(body);
      await vscode.env.openExternal(vscode.Uri.parse(url, true));
    }
  }));
}
