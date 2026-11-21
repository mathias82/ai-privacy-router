export interface LocalModelConfig { model: string; timeoutMs?: number; endpoint?: string; /** Context window; smaller is faster and uses less memory. */ contextTokens?: number }
export interface OllamaTransport { (url: string, init: RequestInit): Promise<Response> }
export interface GenerateOptions { json?: boolean; schema?: object; signal?: AbortSignal; maxTokens?: number;
  /** Prose answers only: called with each text chunk as the local model writes it. */
  onText?: (chunk: string) => void }

export function localEndpoint(value = "http://127.0.0.1:11434"): string {
  const url = new URL(value);
  if (url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
    url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new Error("Ollama endpoint must be a loopback HTTP origin");
  }
  if (url.hostname === "localhost") url.hostname = "127.0.0.1";
  return url.origin;
}

export class LocalOllama {
  private readonly base: string;
  constructor(private readonly config: LocalModelConfig, private readonly transport: OllamaTransport = fetch) {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}$/.test(config.model)) throw new Error("Invalid local model name");
    if (config.timeoutMs !== undefined && (!Number.isFinite(config.timeoutMs) || config.timeoutMs <= 0)) throw new Error("Invalid timeout");
    if (/(?:^|[:/-])cloud(?:$|[:/-])/i.test(config.model)) throw new Error("Cloud models are not allowed on the local route");
    this.base = localEndpoint(config.endpoint);
  }
  private async request(path: string, init: RequestInit, signal?: AbortSignal): Promise<unknown> {
    const controller = new AbortController();
    const abort = (): void => controller.abort();
    if (signal?.aborted) abort();
    signal?.addEventListener("abort", abort, {once: true});
    const timeout = setTimeout(abort, this.config.timeoutMs ?? 120000);
    try {
      const response = await this.transport(this.base + path, {...init, signal: controller.signal, redirect: "error"});
      if (!response.ok) throw new Error("HTTP error");
      return await response.json();
    } catch {
      throw new Error("Local Ollama unavailable or request failed. No cloud fallback.");
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
    }
  }
  async ensureAvailable(signal?: AbortSignal): Promise<void> {
    const data = await this.request("/api/tags", {method: "GET"}, signal);
    if (!data || typeof data !== "object" || !("models" in data) || !Array.isArray(data.models)) throw new Error("Invalid local model inventory. No cloud fallback.");
    const expected = this.config.model.includes(":") ? this.config.model : this.config.model + ":latest";
    const installed = data.models.find(m => m && typeof m === "object" && (m.name === this.config.model || m.name === expected));
    if (installed && (("remote_model" in installed && installed.remote_model !== "") || ("remote_host" in installed && installed.remote_host !== ""))) throw new Error("Remote Ollama model rejected. No prompt sent.");
    if (!installed) {
      throw new Error("Configured model is not installed locally. Run npm run ai:serve or install it with Ollama. No cloud fallback.");
    }
  }
  /** Names of models installed on this machine (remote and cloud models excluded). */
  async listModels(signal?: AbortSignal): Promise<string[]> {
    const data = await this.request("/api/tags", {method: "GET"}, signal) as {models?: Array<{name?: unknown; remote_model?: unknown; remote_host?: unknown}>};
    return (data?.models ?? []).filter(m => typeof m.name === "string" && !m.remote_model && !m.remote_host && !/(?:^|[:/-])cloud(?:$|[:/-])/i.test(m.name as string))
      .map(m => m.name as string).sort();
  }
  /** True when the loopback Ollama server answers; never throws. */
  async isRunning(signal?: AbortSignal): Promise<boolean> {
    try { await this.request("/api/tags", {method: "GET"}, signal); return true; } catch { return false; }
  }
  /** Downloads the configured model from the local Ollama server when it is not installed yet. */
  async ensureInstalled(signal?: AbortSignal, onProgress?: (percent?: number, status?: string) => void): Promise<void> {
    try {
      await this.ensureAvailable(signal);
      return;
    } catch (error) {
      if (!(error instanceof Error) || !error.message.startsWith("Configured model is not installed")) throw error;
    }
    onProgress?.(0, "starting");
    const controller = new AbortController();
    const abort = (): void => controller.abort();
    if (signal?.aborted) abort();
    signal?.addEventListener("abort", abort, {once: true});
    const timeout = setTimeout(abort, 60 * 60 * 1000);
    try {
      const response = await this.transport(this.base + "/api/pull", {
        method: "POST", headers: {"Content-Type": "application/json"}, redirect: "error", signal: controller.signal,
        body: JSON.stringify({model: this.config.model, stream: true})
      });
      if (!response.ok || !response.body) throw new Error("pull failed");
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "", success = false;
      const handle = (line: string): void => {
        if (!line.trim()) return;
        const event = JSON.parse(line) as {status?: unknown; total?: unknown; completed?: unknown; error?: unknown};
        if (event.error) throw new Error("pull failed");
        const status = typeof event.status === "string" ? event.status : undefined;
        if (status === "success") success = true;
        const percent = typeof event.total === "number" && event.total > 0 && typeof event.completed === "number"
          ? Math.min(100, Math.floor(event.completed / event.total * 100)) : undefined;
        onProgress?.(percent, status);
      };
      for (;;) {
        const {done, value} = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, {stream: true});
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        lines.forEach(handle);
      }
      handle(buffer);
      if (!success) throw new Error("pull failed");
    } catch {
      throw new Error("Could not download the local model. No cloud fallback.");
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
    }
    await this.ensureAvailable(signal);
  }
  async assertLocalModel(signal?: AbortSignal): Promise<void> {
    // Model aliases can reference remote inference despite a loopback server URL.
    const metadata = await this.request("/api/show", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({model: this.config.model})
    }, signal);
    if (!metadata || typeof metadata !== "object" ||
      ("remote_model" in metadata && metadata.remote_model !== "") || ("remote_host" in metadata && metadata.remote_host !== "") ||
      !("model_info" in metadata) || !metadata.model_info || typeof metadata.model_info !== "object" ||
      Array.isArray(metadata.model_info) || !Object.keys(metadata.model_info).length) {
      throw new Error("Local model metadata is missing or remote. No prompt sent.");
    }
  }
  async generate(prompt: string, options: GenerateOptions = {}): Promise<string> {
    if (!prompt.trim()) throw new Error("Empty prompt");
    if (options.schema && Buffer.byteLength(prompt, "utf8") > 28000) throw new Error("Structured review prompt exceeds the local context budget");
    if (options.signal?.aborted) throw new Error("Local request cancelled");
    await this.assertLocalModel(options.signal);
    if (options.signal?.aborted) throw new Error("Local request cancelled");
    if (options.onText && !options.schema && !options.json) return this.streamGenerate(prompt, options.onText, options.signal);
    const data = await this.request("/api/generate", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({model: this.config.model, prompt, stream: false, keep_alive: "30m",
        ...(options.schema || options.json ? {format: options.schema ?? "json", options: {temperature: 0, num_predict: Math.min(options.maxTokens ?? 4096, 12288), num_ctx: this.config.contextTokens ?? 16384}} : {})})
    }, options.signal);
    if (!data || typeof data !== "object" || !("response" in data) || typeof data.response !== "string") throw new Error("Invalid local Ollama response. No cloud fallback.");
    return data.response;
  }
  private async streamGenerate(prompt: string, onText: (chunk: string) => void, signal?: AbortSignal): Promise<string> {
    const controller = new AbortController();
    const abort = (): void => controller.abort();
    if (signal?.aborted) abort();
    signal?.addEventListener("abort", abort, {once: true});
    const timeout = setTimeout(abort, this.config.timeoutMs ?? 120000);
    let text = "";
    try {
      const response = await this.transport(this.base + "/api/generate", {
        method: "POST", headers: {"Content-Type": "application/json"}, redirect: "error", signal: controller.signal,
        body: JSON.stringify({model: this.config.model, prompt, stream: true, keep_alive: "30m"})
      });
      if (!response.ok || !response.body) throw new Error("HTTP error");
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "", done = false;
      const handle = (line: string): void => {
        if (!line.trim()) return;
        const event = JSON.parse(line) as {response?: unknown; done?: unknown; error?: unknown};
        if (event.error || (event.response !== undefined && typeof event.response !== "string")) throw new Error("Invalid event");
        if (typeof event.response === "string" && event.response) { text += event.response; onText(event.response); }
        if (event.done === true) done = true;
      };
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        buffer += decoder.decode(chunk.value, {stream: true});
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        lines.forEach(handle);
      }
      handle(buffer);
      if (!done) throw new Error("Incomplete stream");
      return text;
    } catch {
      throw new Error("Local Ollama unavailable or request failed. No cloud fallback.");
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
    }
  }
}
