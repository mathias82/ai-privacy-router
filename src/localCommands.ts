import {configuredClient, configuredModel} from "./model";
import * as vscode from "vscode";
import {classifyInput} from "./classifier";
import {createAutoPrompt, formatRouted} from "./autoPrompt";
import {toSarif, sarifLevel, SarifResult} from "./sarif";
import {tr} from "./i18n";
import {uiLanguage} from "./trivyCommands";
import {reviewOverride} from "./overrideFlow";
import {writeRetainedAuditEvent} from "./audit";
import {validateContext} from "./context";
import {runRegressionTests, testProfiles, detectTestProfiles, formatTestReceipt} from "./regression";

/** Writes every Hushavyr marker (review, security, dependencies) to hushavyr.sarif in the first workspace folder. */
async function exportSarif(context: vscode.ExtensionContext): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  const lang = uiLanguage();
  const results: SarifResult[] = [];
  for (const [uri, diagnostics] of vscode.languages.getDiagnostics()) for (const d of diagnostics) {
    if (d.source !== "Hushavyr") continue;
    const message = d.message.split("\n")[0].replace(/^Potential: /, "");
    results.push({ruleId: /^(?:CVE|GHSA)-[\w-]+/.exec(message)?.[0] ?? message.replace(/^Local rule: /, "").slice(0, 60),
      message: d.message, path: vscode.workspace.asRelativePath(uri, false), line: d.range.start.line + 1,
      level: sarifLevel(d.severity === vscode.DiagnosticSeverity.Error ? "high" : d.severity === vscode.DiagnosticSeverity.Warning ? "medium" : "low")});
  }
  if (!folder || !results.length) { void vscode.window.showInformationMessage("Hushavyr: " + tr(lang, "sarifEmpty")); return; }
  const target = vscode.Uri.joinPath(folder.uri, "hushavyr.sarif");
  const version = String((context.extension?.packageJSON as {version?: string} | undefined)?.version ?? "0.0.0");
  await vscode.workspace.fs.writeFile(target, Buffer.from(JSON.stringify(toSarif(results, version), null, 2)));
  void vscode.window.showInformationMessage("Hushavyr: " + tr(lang, "sarifDone") + " " + target.fsPath);
}

/** Commands that work on the editor selection or workspace locally; none of them send content anywhere. */
export function registerLocalCommands(context: vscode.ExtensionContext, autoPrompt: ReturnType<typeof createAutoPrompt>): void {
  context.subscriptions.push(vscode.commands.registerCommand("aiPrivacyRouter.exportSarif", () => exportSarif(context)));
  context.subscriptions.push(vscode.commands.registerCommand("aiPrivacyRouter.runTests", async () => {
    const receipt = await runWorkspaceTests();
    if (!receipt) return;
    const document = await vscode.workspace.openTextDocument({content: formatTestReceipt(receipt), language: "markdown"});
    await vscode.window.showTextDocument(document, {preview: true});
  }));

  context.subscriptions.push(vscode.commands.registerCommand("aiPrivacyRouter.askAuto", async () => {
    const prompt = await vscode.window.showInputBox({
      prompt: "Route a typed prompt only. No editor contents, files or history are added.",
      ignoreFocusOut: true
    });
    if (!prompt?.trim()) return;
    try {
      const result = await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification, title: "Hushavyr", cancellable: true
      }, (_, token) => autoPrompt(prompt, token));
      if (result.reason === "cancelled") return;
      const document = await vscode.workspace.openTextDocument({content: formatRouted(result), language: "markdown"});
      await vscode.window.showTextDocument(document, {preview: true});
    } catch {
      void vscode.window.showErrorMessage("AI request stopped. No automatic provider fallback; inspect local setup and audit availability.");
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand("aiPrivacyRouter.classifySelection", async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.selection.isEmpty) {
      void vscode.window.showWarningMessage("Select text in an editor first.");
      return;
    }
    const selected = editor.document.getText(editor.selection);
    const decision = classifyInput({prompt: selected, workspaceTrusted: vscode.workspace.isTrusted});
    void vscode.window.showInformationMessage(`Hushavyr: ${decision.route}; ${decision.reasons.join(", ")}. No content transmitted.`);
  }));

  context.subscriptions.push(vscode.commands.registerCommand("aiPrivacyRouter.reviewCloudOverride", async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.selection.isEmpty) {
      void vscode.window.showWarningMessage("Select content to review first.");
      return;
    }
    const selected = editor.document.getText(editor.selection);
    const input = {prompt: "Review selected content for possible external processing",
      selectedCode: [{path: editor.document.uri.toString(), content: selected}], workspaceTrusted: vscode.workspace.isTrusted};
    const config = vscode.workspace.getConfiguration("aiPrivacyRouter");
    // This legacy command is review-only; it cannot dispatch to Copilot or any other provider.
    const preview = await vscode.workspace.openTextDocument({content: JSON.stringify(input, null, 2), language: "json"});
    await vscode.window.showTextDocument(preview, {preview: true, viewColumn: vscode.ViewColumn.Beside});
    try {
      const outcome = await reviewOverride(input,
        {cloudEnabled: true, allowOverrides: true,
          mandatoryLocalOnly: config.get<boolean>("mandatoryLocalOnly", false),
          requireReviewer: config.get<boolean>("requireReviewer", false)}, {
          confirmWarning: async () => await vscode.window.showWarningMessage(
            "Review only: Anthropic Sonnet (NOT CONNECTED). The local preview shows the entire candidate context: " +
            Buffer.byteLength(selected, "utf8") + " bytes from one selected file. Nothing will be sent.",
            {modal: true}, "Review override") === "Review override",
          justification: async () => vscode.window.showInputBox({prompt: "Why is this content safe for external processing? (not logged verbatim)", ignoreFocusOut: true}),
          confirmReview: async () => await vscode.window.showWarningMessage(
            "Record this review locally? This does not enable cloud transfer.", {modal: true}, "Confirm review") === "Confirm review"
          // No verified reviewer identity provider is connected. requireReviewer therefore denies approval.
        }, event => writeRetainedAuditEvent(context.globalStorageUri.fsPath + "/audit", event));
      void vscode.window.showInformationMessage(outcome === "approved"
        ? "Review approved and audited locally. This command never sends content."
        : "Review " + outcome + " and audited locally. Nothing was sent.");
    } catch {
      void vscode.window.showErrorMessage("Audit write failed. No approval or transfer is permitted.");
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand("aiPrivacyRouter.privacyPreview", async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.selection.isEmpty) {
      void vscode.window.showWarningMessage("Select text for privacy review.");
      return;
    }
    const decision = classifyInput({prompt:editor.document.getText(editor.selection),workspaceTrusted:vscode.workspace.isTrusted});
    const report = [
      "# Hushavyr — Privacy Preview", "",
      "**Route:** " + decision.route,
      "**Sensitivity:** " + decision.sensitivity,
      "**Task:** " + decision.task,
      "**Workspace trusted:** " + vscode.workspace.isTrusted,
      "**Cloud dispatch:** This command is local-only; optional public-prompt routing is configured separately.", "",
      "## Detection reasons",
      ...decision.reasons.map(reason => "- " + reason), "",
      "No selected content is included in this report.",
      "Classification is heuristic and does not certify that content is safe to share.",
      "No cloud approval or transfer was performed."
    ].join("\n");
    const document = await vscode.workspace.openTextDocument({content:report,language:"markdown"});
    await vscode.window.showTextDocument(document,{preview:true});
  }));

  context.subscriptions.push(vscode.commands.registerCommand("aiPrivacyRouter.askLocal", async () => {
    const prompt = await vscode.window.showInputBox({prompt:"Ask local Qwen (never sent to cloud)",ignoreFocusOut:true});
    if (!prompt?.trim()) return;
    await runLocal(prompt);
  }));

  context.subscriptions.push(vscode.commands.registerCommand("aiPrivacyRouter.askLocalSelection", async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.selection.isEmpty) {
      void vscode.window.showWarningMessage("Select code or document text first.");
      return;
    }
    const selected = editor.document.getText(editor.selection);
    const instruction = await vscode.window.showInputBox({
      prompt:"What should local Qwen do with the selected text?",
      value:"Explain the selected content",
      ignoreFocusOut:true
    });
    if (!instruction?.trim()) return;
    await runLocal(instruction + "\n\nSelected content:\n" + selected);
  }));
}

async function runLocal(prompt: string): Promise<void> {
  try { validateContext(prompt, []); }
  catch {
    void vscode.window.showWarningMessage("Context exceeds 20 KB. Select less content.");
    return;
  }
  const decision = classifyInput({prompt, workspaceTrusted: vscode.workspace.isTrusted});
  // This standalone local command never selects or dispatches to a cloud provider.
  if (decision.route === "blocked") {
    void vscode.window.showErrorMessage("Content blocked by privacy policy.");
    return;
  }
  const model = configuredModel(vscode.workspace.getConfiguration("aiPrivacyRouter"));
  try {
    const result = await vscode.window.withProgress({
      location:vscode.ProgressLocation.Notification,
      title:"Hushavyr: local Qwen"
    }, async () => {
      const config = vscode.workspace.getConfiguration("aiPrivacyRouter");
      const client = configuredClient(config, model);
      await client.ensureAvailable();
      return client.generate(prompt);
    });
    const document = await vscode.workspace.openTextDocument({content:result,language:"markdown"});
    await vscode.window.showTextDocument(document,{preview:true});
  } catch {
    void vscode.window.showErrorMessage("Local Ollama failed. No cloud fallback or external transfer was attempted.");
  }
}
export async function runWorkspaceTests(externalToken?: vscode.CancellationToken) {
  if (externalToken?.isCancellationRequested) return;
  if (!vscode.workspace.isTrusted) {
    void vscode.window.showWarningMessage("Trust this workspace before running its tests.");
    return;
  }
  const folder = await vscode.window.showWorkspaceFolderPick({placeHolder: "Choose the project whose existing tests will run"});
  if (!folder || folder.uri.scheme !== "file") return;
  const items = (await detectTestProfiles(folder.uri.fsPath)).map(profile => ({label: testProfiles[profile].label, profile}));
  const choice = await vscode.window.showQuickPick(items, {placeHolder: "Run existing tests locally (project scripts may execute code)"});
  if (!choice) return;
  return vscode.window.withProgress({location: vscode.ProgressLocation.Notification,
    title: "Running " + choice.label, cancellable: true}, async (_, token) => {
    const controller = new AbortController();
    const subscription = token.onCancellationRequested(() => controller.abort());
    const externalSubscription = externalToken?.onCancellationRequested(() => controller.abort());
    if (token.isCancellationRequested || externalToken?.isCancellationRequested) controller.abort();
    try {
      return await runRegressionTests({cwd: folder.uri.fsPath, profile: choice.profile,
        trusted: vscode.workspace.isTrusted, signal: controller.signal});
    } catch {
      void vscode.window.showErrorMessage("Unable to run the existing local test suite. Check the selected project and runner.");
      return;
    } finally { subscription.dispose(); externalSubscription?.dispose(); }
  });
}
