import * as vscode from "vscode";
import {inlineText} from "./review";
import {randomUUID} from "node:crypto";
import {configuredClient, configuredModel} from "./model";
import {LocalOllama} from "./ollama";
import {codeBlock, editPrompt, editSchema, parseEdit, parseSummary, shortDiff} from "./codeEdit";
import {escalate, MAX_ESCALATION_CHARS} from "./escalation";
import {confirmPublicPayload, pickCopilotModel} from "./autoPrompt";
import {writeRetainedAuditEvent} from "./audit";
import {loadIgnore} from "./teamMemory";

export const MAX_EDIT_CHARS = 12_000;
export interface EditTarget {uri: vscode.Uri; languageId: string; path: string; original: string; range?: vscode.Range; instruction: string; previousAnswer: string; title?: string}
interface Pending extends EditTarget {updated?: string; model: string; summary: string[]}
const pending = new Map<string, Pending>();

function localClient(model?: string): LocalOllama {
  const config = vscode.workspace.getConfiguration("aiPrivacyRouter");
  return configuredClient(config, model);
}

async function generateLocal(target: EditTarget, model: string, signal: AbortSignal): Promise<{updated?: string; summary: string[]}> {
  const client = localClient(model);
  await client.ensureInstalled(signal);
  const raw = await client.generate(editPrompt(target.path, target.languageId, target.original, target.instruction, target.previousAnswer),
    {schema: editSchema, signal, maxTokens: 12288});
  const updated = parseEdit(raw, target.original);
  return {updated, summary: updated ? parseSummary(raw) : []};
}

async function showDiff(item: Pending, title: string): Promise<void> {
  const doc = await vscode.workspace.openTextDocument(item.uri);
  const full = item.range ? doc.getText().slice(0, doc.offsetAt(item.range.start)) + item.updated + doc.getText().slice(doc.offsetAt(item.range.end)) : item.updated ?? "";
  const preview = await vscode.workspace.openTextDocument({content: full, language: item.languageId});
  await vscode.commands.executeCommand("vscode.diff", item.uri, preview.uri, title);
}

async function apply(id: string): Promise<void> {
  const item = pending.get(id);
  if (!item?.updated) return;
  const doc = await vscode.workspace.openTextDocument(item.uri);
  const range = item.range ?? new vscode.Range(doc.positionAt(0), doc.positionAt(doc.getText().length));
  if (doc.getText(range) !== item.original) {
    void vscode.window.showWarningMessage("Hushavyr: the file changed since the proposal. Ask again.");
    return;
  }
  const edit = new vscode.WorkspaceEdit();
  edit.replace(item.uri, range, item.updated);
  if (await vscode.workspace.applyEdit(edit)) {
    pending.delete(id);
    const title = item.title ?? item.instruction.split("\n")[0].slice(0, 72);
    const body = item.summary.length ? "Changes in `" + item.path + "` (" + item.model + "):\n" + item.summary.map(s => "- " + inlineText(s)).join("\n") : "";
    const choice = await vscode.window.showInformationMessage("Hushavyr: change applied (not saved yet). Review or test it, then open a pull request.", "Open pull request");
    if (choice === "Open pull request") await vscode.commands.executeCommand("aiPrivacyRouter.openPullRequest", title, body);
  }
}

async function offer(id: string, label: string): Promise<void> {
  const answer = await vscode.window.showInformationMessage("Hushavyr: " + label + " Apply it?", "Apply", "Discard");
  if (answer === "Apply") await apply(id);
}

async function retryWithModel(id: string): Promise<void> {
  const item = pending.get(id);
  if (!item) return;
  let models: string[] = [];
  try { models = await localClient().listModels(); } catch { /* reported below */ }
  if (!models.length) { void vscode.window.showWarningMessage("Hushavyr: no local Ollama models found."); return; }
  const model = await vscode.window.showQuickPick(models.filter(m => m !== item.model).concat(models.includes(item.model) ? [item.model] : []),
    {placeHolder: "Local model for this change (code stays on this machine)"});
  if (!model) return;
  const updated = await vscode.window.withProgress({location: vscode.ProgressLocation.Notification, title: "Hushavyr: " + model + " is editing locally", cancellable: true},
    async (_p, token) => {
      const controller = new AbortController();
      token.onCancellationRequested(() => controller.abort());
      try { return await generateLocal(item, model, controller.signal); } catch { return undefined; }
    });
  if (!updated?.updated) { void vscode.window.showWarningMessage("Hushavyr: " + model + " did not produce a usable change."); return; }
  item.updated = updated.updated; item.summary = updated.summary; item.model = model;
  await showDiff(item, "Hushavyr (" + model + "): " + item.instruction.slice(0, 50));
  await offer(id, model + " proposed a change.");
}

async function escalateEdit(id: string, context: vscode.ExtensionContext): Promise<void> {
  const item = pending.get(id);
  if (!item) return;
  const config = vscode.workspace.getConfiguration("aiPrivacyRouter");
  const folder = vscode.workspace.getWorkspaceFolder(item.uri);
  const localOnly = !config.get<boolean>("cloudEscalation", false) || config.get<boolean>("mandatoryLocalOnly", false) || !vscode.workspace.isTrusted;
  const ignored = folder ? (await loadIgnore(folder.uri.fsPath))(item.path) : false;
  const source = new vscode.CancellationTokenSource();
  try {
    const result = await escalate({path: item.path, code: item.original, localOnly, ignored,
      question: item.instruction + "\nReturn the complete updated fragment in ONE fenced code block."}, {
      pickModel: () => pickCopilotModel(source.token, "Choose the model for this pseudonymized change"),
      confirm: (payload, label) => confirmPublicPayload(payload, label, source.token),
      audit: event => writeRetainedAuditEvent(context.globalStorageUri.fsPath + "/audit", event),
      cancelled: () => source.token.isCancellationRequested
    });
    if (result.outcome !== "sent") {
      void vscode.window.showWarningMessage("Hushavyr: nothing was sent (" + (result.reason ?? result.outcome) + ")." +
        (result.reason === "this workspace is local-only" ? " Enable aiPrivacyRouter.cloudEscalation to allow it." : ""));
      return;
    }
    const block = codeBlock(result.text ?? "");
    const updated = block === undefined ? undefined : parseEdit(JSON.stringify({content: block}), item.original);
    if (!updated) { void vscode.window.showWarningMessage("Hushavyr: the cloud answer contained no usable code. Nothing changed."); return; }
    item.updated = updated; item.summary = []; item.model = "cloud";
    await showDiff(item, "Hushavyr (escalated, names restored locally): " + item.instruction.slice(0, 40));
    await offer(id, "The escalated model proposed a change (verify it locally).");
  } finally { source.dispose(); }
}

export function registerEditCommands(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("aiPrivacyRouter.applyEdit", (id: string) => apply(id)),
    vscode.commands.registerCommand("aiPrivacyRouter.retryEditModel", (id: string) => retryWithModel(id)),
    vscode.commands.registerCommand("aiPrivacyRouter.escalateEdit", (id: string) => escalateEdit(id, context)));
}

/** Local model edits the target; the chat shows the diff and buttons. Nothing changes until Apply. */
export async function runEdit(target: EditTarget, stream: vscode.ChatResponseStream, token: vscode.CancellationToken): Promise<void> {
  if (target.original.length > MAX_EDIT_CHARS) {
    stream.markdown("The file is over " + MAX_EDIT_CHARS / 1000 + " KB. Select the part to change (a method or class) and ask again. Nothing was sent.");
    return;
  }
  const model = configuredModel(vscode.workspace.getConfiguration("aiPrivacyRouter"));
  const controller = new AbortController();
  const sub = token.onCancellationRequested(() => controller.abort());
  stream.progress("Editing `" + target.path + "` locally with " + model + "…");
  let updated: string | undefined, summary: string[] = [];
  try { ({updated, summary} = await generateLocal(target, model, controller.signal)); }
  catch { if (!token.isCancellationRequested) stream.markdown("Local model unavailable. Check Ollama. No cloud fallback."); return; }
  finally { sub.dispose(); }
  if (token.isCancellationRequested) return;
  const id = randomUUID();
  pending.set(id, {...target, updated, model, summary});
  if (pending.size > 20) pending.delete(pending.keys().next().value as string);
  if (!updated) {
    stream.markdown(target.title ? "**" + model + "** found nothing worth changing in `" + target.path + "` (or its answer was unusable). You can try another model:\n\n"
      : "**" + model + "** did not produce a usable change for `" + target.path + "`. Try another model:\n\n");
  } else {
    stream.markdown("**Proposed change** to `" + target.path + "` (" + model + ", local). Nothing is changed until you apply it.\n\n" +
      (summary.length ? summary.map(s => "- " + inlineText(s)).join("\n") + "\n\n" : "") + "```diff\n" +
      shortDiff(target.original, updated).replace(/```/g, "ˋˋˋ") + "\n```\n");
    stream.button({command: "aiPrivacyRouter.applyEdit", title: "Apply change", arguments: [id]});
    void showDiff(pending.get(id) as Pending, "Hushavyr: " + target.instruction.slice(0, 60));
  }
  stream.button({command: "aiPrivacyRouter.retryEditModel", title: "Try another local model", arguments: [id]});
  if (target.original.length <= MAX_ESCALATION_CHARS) stream.button({command: "aiPrivacyRouter.escalateEdit", title: "Escalate (pseudonymized, needs approval)", arguments: [id]});
}
