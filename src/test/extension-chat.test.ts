import { test } from "node:test";
import { strict as assert } from "node:assert";
import type * as vscode from "vscode";
class Uri {
  constructor(readonly value: string, readonly scheme = "file") {}
  toString() { return this.value; }
}
class Location {}
class TabInputText {}
const disposable = {dispose() {}};
let handler: (request: any, context: any, stream: any, token: any) => Promise<unknown>;
let docs = new Map<string, string>();
// Pin the single-pass, LLM-only flow so request counts stay exact; hybrid paths have their own tests.
const configuration: Record<string, unknown> = {ollamaModel: "qwen2.5-coder:7b", reviewDepth: "fast", staticAnalysis: false, callContext: false};
const registeredCommands = new Set<string>();
let copilotLookups = 0, participantRegistrations = 0;
const fake = {
  Uri, Location, TabInputText,
  languages: {createDiagnosticCollection: () => ({clear() {}, set() {}, dispose() {}}), registerCodeActionsProvider: () => disposable},
  CodeActionKind: {QuickFix: "quickfix"},
  DiagnosticSeverity: {Error: 0, Warning: 1, Information: 2},
  window: {
    activeTextEditor: undefined, visibleTextEditors: [], tabGroups: {activeTabGroup: {}},
    onDidChangeActiveTextEditor: () => disposable, onDidChangeTextEditorSelection: () => disposable,
    showWarningMessage: async () => undefined, showErrorMessage: async () => undefined,
    showInformationMessage: async () => undefined
  },
  commands: {registerCommand: (id: string) => {registeredCommands.add(id); return disposable;}, executeCommand: async () => undefined},
  lm: {selectChatModels: async () => {copilotLookups++; throw new Error("Unexpected cloud discovery");}},
  workspace: {
    isTrusted: true,
    workspaceFolders: undefined,
    textDocuments: [] as any[],
    getConfiguration: () => ({get: (key: string, fallback?: unknown) => configuration[key] ?? fallback}),
    findFiles: async () => [],
    asRelativePath: (uri: Uri) => uri.toString().replace("file:///", ""),
    openTextDocument: async (uri: Uri) => ({getText: () => docs.get(uri.toString()) ?? ""})
  },
  chat: {createChatParticipant: (_id: string, callback: typeof handler) => {participantRegistrations++; handler = callback; return disposable;}}
};
// Load the extension against a small VS Code API double; no Electron or network needed.
const Module = require("node:module") as { _load: (name: string, ...args: any[]) => unknown };
const originalLoad = Module._load;
let activate: typeof import("../extension").activate;
try {
  Module._load = function(name, ...args) { return name === "vscode" ? fake : originalLoad.call(this, name, ...args); };
  activate = require("../extension").activate;
} finally { Module._load = originalLoad; }

async function chat(files: Record<string, string>, responses: string[], prompt = "check code for bugs", unknown: boolean | object[] = false, commandOverride?: string) {
  docs = new Map(Object.entries(files));
  const requests: {url: string; payload?: any}[] = [];
  const output: string[] = [];
  const priorFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const url = String(input);
    requests.push({url, payload: init?.body ? JSON.parse(String(init.body)) : undefined});
    if (url.endsWith("/api/show")) return new Response(JSON.stringify({model_info: {"general.architecture": "qwen2"}}));
    if (url.endsWith("/api/tags")) return new Response(JSON.stringify({models: [{name: "qwen2.5-coder:7b"}]}));
    const response = responses.shift();
    assert.equal(typeof response, "string", "unexpected model invocation");
    if (requests[requests.length - 1].payload?.stream === true)
      return new Response(JSON.stringify({response}) + "\n" + JSON.stringify({response: "", done: true}) + "\n");
    return new Response(JSON.stringify({response}));
  };
  try {
    activate({subscriptions: [], asAbsolutePath: (p: string) => p, globalStorageUri: {fsPath: "/unused"}, globalState: {get: () => true, update: async () => undefined}} as unknown as vscode.ExtensionContext);
    await handler({command: commandOverride ?? (prompt === "Explain" ? undefined : "review"), prompt,
      references: Array.isArray(unknown) ? unknown : unknown ? [{value: "unreadable"}] : Object.keys(files).map(path => ({value: new Uri(path)}))}, {},
    {markdown: (text: string) => output.push(text), progress: () => undefined, button: (b: {title: string}) => output.push("[button] " + b.title)}, {isCancellationRequested: false, onCancellationRequested: () => disposable});
    return {requests, output: output.join('\n')};
  } finally {globalThis.fetch = priorFetch;}
}

test("Chat passes both attached files through review, line extraction and separate local verification", async () => {
  const result = await chat({"file:///Mapper.java": "String value = raw + input;", "file:///Input.java": "String input;"}, [
    JSON.stringify({findings: [{title: "JSON escaping", severity: "medium", path: "file:///Mapper.java", startLine: 1, endLine: 1,
      fix: "Use serializer", regressionTest: "Input with quote"}]}), '{"verdicts":[{"index":0,"supported":true}]}'
  ]);
  assert.equal(result.requests.length, 5); // inventory + local-model attestations + reviewer + verifier
  assert.ok(result.requests.every(r => r.url.startsWith("http://127.0.0.1:11434/")));
  assert.match(result.requests[2].payload.prompt, /file:\/\/\/Input.java/);
  assert.match(result.requests[4].payload.prompt, /skeptical second reviewer/);
  assert.match(result.output, /String value = raw \+ input;/);
  assert.match(result.output, /Source support agreed/);
});
test("unreadable or oversized Chat context stops before any network request", async () => {
  const unknown = await chat({}, [], "review", true);
  assert.equal(unknown.requests.length, 0);
  assert.match(unknown.output, /cannot be inspected/);
  const large = await chat({"file:///Large.java": "x".repeat(21000)}, []);
  assert.equal(large.requests.length, 0);
  assert.match(large.output, /20 KB/);
});
test("normal Chat keeps the ordinary generation path", async () => {
  const result = await chat({}, ["Local explanation"], "Explain");
  assert.equal(result.requests.length, 3);
  assert.equal(result.requests[2].payload.format, undefined);
  assert.match(result.output, /Local explanation/);
});

test("auto defaults to local without Copilot discovery or implicit file context", async () => {
  const before = copilotLookups;
  const result = await chat({}, ["local routed answer"], "Design a Java queue", false, "auto");
  assert.equal(copilotLookups, before);
  assert.equal(result.requests.length, 3);
  assert.equal(result.requests[2].payload.prompt, "Design a Java queue");
  assert.match(result.output, /Route:\*\* ollama/);
});
test("auto ignores the skill index VS Code attaches and still routes the typed prompt", async () => {
  const result = await chat({}, ["local routed answer"], "Design a Java queue",
    [{id: "vscode.customizations.index", value: "<skills>...</skills>"}], "auto");
  assert.doesNotMatch(result.output, /cannot be inspected|Attached context stays local/);
  assert.equal(result.requests[2].payload.prompt, "Design a Java queue");
});
test("auto attachments stay on the local review path", async () => {
  const before = copilotLookups;
  const result = await chat({"file:///Private.java": "public class Private {}"}, ['{"findings":[]}'], "review", false, "auto");
  assert.equal(copilotLookups, before);
  assert.match(result.output, /Attached context stays local/);
  assert.equal(result.requests.length, 5); // model metadata + two local review attempts
});
test("local commands register even when built-in AI and Copilot are disabled", () => {
  const before = participantRegistrations;
  configuration.disableAIFeatures = true;
  try {
    activate({subscriptions: [], asAbsolutePath: (p: string) => p, globalStorageUri: {fsPath: "/unused"}, globalState: {get: () => true, update: async () => undefined}} as unknown as vscode.ExtensionContext);
    assert.equal(participantRegistrations, before + 1);
    assert.ok(registeredCommands.has("aiPrivacyRouter.askLocal"));
    assert.ok(registeredCommands.has("aiPrivacyRouter.verifyLocalFix"));
    assert.ok(registeredCommands.has("aiPrivacyRouter.askLocalSelection"));
  } finally {delete configuration.disableAIFeatures;}
});
test("/explain answers in prose about the attached file without the review schema", async () => {
  const result = await chat({"file:///Svc.java": "class Svc { int twice(int x) { return x * 2; } }"}, ["It doubles a number."], "", false, "explain");
  assert.equal(result.requests.length, 3);
  assert.equal(result.requests[2].payload.format, undefined);
  assert.match(result.requests[2].payload.prompt, /Explain what this code does/);
  assert.match(result.requests[2].payload.prompt, /twice/);
  assert.match(result.output, /It doubles a number/);
  assert.doesNotMatch(result.output, /use `@ai-privacy \/explain`/);
});
test("/review asked to explain still answers, and points to /explain", async () => {
  const result = await chat({"file:///Svc.java": "class Svc {}"}, ["An empty class."], "explain the code", false, "review");
  assert.equal(result.requests.length, 3);
  assert.match(result.output, /An empty class/);
  assert.match(result.output, /use `@ai-privacy \/explain`/);
});
test("instruction files attached by Chat are ignored; the code file is what gets explained", async () => {
  const result = await chat({"file:///repo/.github/copilot-instructions.md": "Use the .ai-context directory as a knowledge base.", "file:///repo/Processor.java": "class Processor { void load() {} }"},
    ["Processor loads a resource."], "this class", false, "explain");
  const prompt = result.requests[2].payload.prompt as string;
  assert.match(prompt, /class Processor/);
  assert.doesNotMatch(prompt, /knowledge base/);
});

test("edit follow-up changes the open file locally and shows a diff with apply, other-model and escalate buttons", async () => {
  const code = "class Svc {\n  void run() {}\n}\n";
  const result = await chat({"file:///Svc.java": code}, [JSON.stringify({content: "class Svc {\n  void run() {}\n  void stop() {}\n}\n"})], "can you add them", false, "explain");
  assert.ok(result.requests.every(r => r.url.startsWith("http://127.0.0.1:11434/")));
  const generate = result.requests.find(r => r.url.endsWith("/api/generate"));
  assert.match(generate?.payload.prompt, /USER REQUEST: can you add them/);
  assert.match(generate?.payload.prompt, /void run/);
  assert.match(result.output, /\+   void stop\(\) \{\}/);
  assert.match(result.output, /\[button\] Apply change/);
  assert.match(result.output, /\[button\] Try another local model/);
  assert.match(result.output, /\[button\] Escalate/);
});
