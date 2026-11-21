import * as vscode from "vscode";
import {execFile} from "node:child_process";
import {existsSync} from "node:fs";
import {totalmem} from "node:os";
import {defaultFindSecBugsPlugin, hasOsvDatabase} from "./codeScanners";
import {LocalOllama} from "./ollama";
import {tr} from "./i18n";
import {configuredModel, recommendedModel} from "./model";
export {recommendedModel};


/** Approximate resident size of common quantized models; warn before loading one that will swap. */
export function lowMemoryWarning(model: string, memoryBytes = totalmem()): string {
  const size = /(\d+(?:\.\d+)?)b\b/i.exec(model);
  if (!size) return "";
  const needGb = Number(size[1]) * 0.7 + 2;
  const haveGb = memoryBytes / 1024 ** 3;
  return needGb > haveGb ? "**Warning:** " + model + " needs about " + Math.ceil(needGb) + " GB of memory but this machine has " + Math.floor(haveGb) + " GB; expect slow responses. Run **Hushavyr: Setup** to pick a smaller model." : "";
}

export type Runner = (executable: string, args: string[]) => Promise<boolean>;
const defaultRunner: Runner = (executable, args) => new Promise(resolve =>
  execFile(executable, args, {timeout: 8000, windowsHide: true}, error => resolve(!error)));

/** Which optional offline tools are installed; each probe only runs `--version`. FindSecBugs also needs its plugin jar. */
export async function detectTools(run: Runner = defaultRunner, findSecBugsPlugin = defaultFindSecBugsPlugin(), exists: (path: string) => boolean = existsSync): Promise<Record<InstallableTool, boolean>> {
  const [semgrep, gitleaks, trivy, spotbugs, bandit, gosec, osv] = await Promise.all([
    run("semgrep", ["--version"]), run("gitleaks", ["version"]), run("trivy", ["--version"]), run("spotbugs", ["-version"]),
    run("bandit", ["--version"]), run("gosec", ["-version"]), run("osv-scanner", ["--version"])]);
  return {semgrep, gitleaks, trivy, findsecbugs: spotbugs && exists(findSecBugsPlugin), bandit, gosec, "osv-scanner": osv};
}

export type InstallableTool = "semgrep" | "gitleaks" | "trivy" | "findsecbugs" | "bandit" | "gosec" | "osv-scanner";
/** Only offer analyzers the workspace can use: Bandit for Python, gosec for Go modules, FindSecBugs for Maven/Gradle builds. */
export function relevantTools(installed: Record<InstallableTool, boolean>, has: {python: boolean; go: boolean; jvm: boolean}): InstallableTool[] {
  const relevant: Record<InstallableTool, boolean> = {semgrep: true, gitleaks: true, trivy: true, "osv-scanner": true, bandit: has.python, gosec: has.go, findsecbugs: has.jvm};
  return (Object.keys(installed) as InstallableTool[]).filter(tool => !installed[tool] && relevant[tool]);
}
const pluginUrl = "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/1.14.0/findsecbugs-plugin-1.14.0.jar";
const pluginDownload = "mkdir -p ~/.hushavyr && curl -fsSL -o ~/.hushavyr/findsecbugs-plugin.jar " + pluginUrl;
/** Downloads public OSV.dev data for the ecosystems found in `root`; vulnerability matching itself stays local. */
export const osvDatabaseCommand = (root: string): string =>
  "osv-scanner scan source --offline-vulnerabilities --download-offline-databases --no-resolve --format table -r '" + root.replace(/'/g, "'\\''") + "'";
const installPromptOpen = new Set<InstallableTool>();
const installCommands: Record<InstallableTool, {label: string; purpose: string; darwin: string; other: string}> = {
  semgrep: {label: "Semgrep", purpose: "additional offline security checks", darwin: "brew install semgrep", other: "pipx install semgrep"},
  gitleaks: {label: "Gitleaks", purpose: "offline secret scanning", darwin: "brew install gitleaks", other: "go install github.com/gitleaks/gitleaks/v8@latest"},
  trivy: {label: "Trivy", purpose: "offline dependency vulnerability audits", darwin: "brew install trivy && trivy image --download-db-only", other: "See https://trivy.dev/latest/getting-started/installation/ then run: trivy image --download-db-only"},
  findsecbugs: {label: "FindSecBugs (SpotBugs)", purpose: "bytecode security analysis of compiled Java and Kotlin classes", darwin: "brew install spotbugs && " + pluginDownload, other: "See https://spotbugs.readthedocs.io/en/latest/installing.html then run: " + pluginDownload},
  bandit: {label: "Bandit", purpose: "offline Python security checks", darwin: "brew install bandit", other: "pipx install bandit"},
  gosec: {label: "gosec", purpose: "offline Go security checks", darwin: "brew install gosec", other: "go install github.com/securego/gosec/v2/cmd/gosec@latest"},
  "osv-scanner": {label: "OSV-Scanner", purpose: "offline dependency vulnerability checks against the OSV.dev database", darwin: "brew install osv-scanner", other: "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"}
};
export async function offerToolInstallation(tool: InstallableTool): Promise<void> {
  if (installPromptOpen.has(tool)) return;
  installPromptOpen.add(tool);
  const info = installCommands[tool];
  try {
    const choice = await vscode.window.showInformationMessage(
      "Hushavyr: " + info.label + " is not installed. Install it locally to enable " + info.purpose + "?",
      "Show install command", "Not now"
    );
    if (choice !== "Show install command") return;
    if (process.platform === "win32") {
      await vscode.window.showInformationMessage(
        info.label + " should be installed through WSL or its official Windows installer, then Hushavyr run in that workspace. No command was executed.",
        { modal: true }, "OK"
      );
      return;
    }
    const command = process.platform === "darwin" ? info.darwin : info.other;
    const confirm = await vscode.window.showWarningMessage(
      "Run this command in a new terminal? " + command + ". This downloads software from the package manager; Hushavyr will not send project code.",
      { modal: true }, "Run install command", "Copy command"
    );
    if (confirm === "Copy command") {
      await vscode.env.clipboard.writeText(command);
    } else if (confirm === "Run install command") {
      const terminal = vscode.window.createTerminal({ name: "Hushavyr · Install " + info.label });
      terminal.show();
      terminal.sendText(command);
      if (tool === "osv-scanner") await offerOsvDatabase(terminal);
    }
  } finally {
    installPromptOpen.delete(tool);
  }
}

/** OSV-Scanner only scans offline in Hushavyr, so it needs a local database; downloading one is a separate, explicit choice. */
export async function offerOsvDatabase(terminal?: vscode.Terminal): Promise<void> {
  const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!root || process.platform === "win32") return;
  const choice = await vscode.window.showInformationMessage(
    "Hushavyr: download the OSV offline vulnerability database for this workspace? It fetches public OSV.dev data for the package ecosystems used here (npm, Maven, PyPI, ...). No code or dependency list is sent; later scans run fully offline.",
    {modal: true}, "Download database", "Not now");
  if (choice !== "Download database") return;
  const target = terminal ?? vscode.window.createTerminal({name: "Hushavyr · OSV database"});
  target.show();
  target.sendText(osvDatabaseCommand(root));
}

/** Guided first-run check: Ollama, model, optional scanners. Every install needs explicit consent. */
export async function runSetup(): Promise<void> {
  const config = vscode.workspace.getConfiguration("aiPrivacyRouter");
  const endpoint = config.get<string>("ollamaEndpoint", "http://127.0.0.1:11434");
  const timeoutMs = config.get<number>("timeoutSeconds", 180) * 1000;
  const language = config.get<string>("language", "en");
  let model = configuredModel(config);
  const summary: string[] = [];
  const probe = new LocalOllama({model, endpoint, timeoutMs});
  if (!await probe.isRunning()) {
    const choice = await vscode.window.showWarningMessage(
      "Ollama is not running. Install or start it, then run Hushavyr: Setup again.", "Install Ollama", "Start Ollama");
    if (choice === "Install Ollama") await vscode.commands.executeCommand("aiPrivacyRouter.installOllama");
    if (choice === "Start Ollama") await vscode.commands.executeCommand("aiPrivacyRouter.startOllama");
    return;
  }
  summary.push("Ollama: running");
  const best = recommendedModel(totalmem());
  const options = [...new Set([model, best, "qwen2.5-coder:7b", "qwen2.5-coder:14b", "qwen3-coder:30b", "qwen2.5-coder:32b", "deepseek-coder-v2:16b"])];
  const pick = await vscode.window.showQuickPick(options.map(label => ({
    label, description: label === best ? tr(language, "setupRecommended") : label === model ? tr(language, "setupCurrent") : undefined
  })), {placeHolder: tr(language, "setupPick")});
  if (!pick) return;
  if (pick.label !== model) {
    model = pick.label;
    await config.update("ollamaModel", model, vscode.ConfigurationTarget.Global);
  }
  try {
    await vscode.window.withProgress({location: vscode.ProgressLocation.Notification, title: "Hushavyr: preparing " + model, cancellable: true}, async (progress, token) => {
      const controller = new AbortController();
      token.onCancellationRequested(() => controller.abort());
      let last = 0;
      await new LocalOllama({model, endpoint, timeoutMs}).ensureInstalled(controller.signal, percent => {
        if (percent === undefined) return;
        progress.report({increment: Math.max(0, percent - last), message: percent + "%"});
        last = percent;
      });
    });
    summary.push("Model " + model + ": " + tr(language, "setupReady"));
  } catch {
    void vscode.window.showErrorMessage("Hushavyr: " + model + " " + tr(language, "setupFailed"));
    return;
  }
  const tools = await detectTools(undefined, config.get<string>("findSecBugsPlugin", "") || defaultFindSecBugsPlugin());
  for (const tool of Object.keys(tools) as InstallableTool[]) {
    summary.push(installCommands[tool].label + ": " + (tools[tool] ? "installed" : "not installed (optional)"));
  }
  void vscode.window.showInformationMessage(tr(language, "setupDone") + " " + summary.join(" · "));
  const exclude = "**/{node_modules,.git,.venv,venv,vendor}/**";
  const [python, go, jvm] = await Promise.all(["**/*.py", "**/go.mod", "**/{pom.xml,build.gradle,build.gradle.kts}"].map(async glob => (await vscode.workspace.findFiles(glob, exclude, 1)).length > 0));
  for (const tool of relevantTools(tools, {python, go, jvm})) await offerToolInstallation(tool);
  if (tools["osv-scanner"] && !await hasOsvDatabase()) await offerOsvDatabase();
}
