import { test } from "node:test";
import { strict as assert } from "node:assert";
import { LocalOllama } from "../ollama";
test("only calls localhost Ollama and returns model text", async () => {
  let target = "";
  const client = new LocalOllama({model:"qwen2.5-coder:7b"}, async (url, init) => {
    if (url.endsWith("/api/show")) return new Response(JSON.stringify({model_info: {"general.architecture": "qwen2"}}));
    target = url;
    assert.equal(init.method, "POST");
    assert.equal(JSON.parse(String(init.body)).stream, false);
    return new Response(JSON.stringify({response:"Hello from Qwen"}), {status:200});
  });
  assert.equal(await client.generate("Write a Java method"), "Hello from Qwen");
  assert.equal(target, "http://127.0.0.1:11434/api/generate");
});
test("never falls back to cloud on connection failure", async () => {
  let calls=0;
  const client = new LocalOllama({model:"qwen2.5-coder:7b"}, async () => { calls++; throw new Error("offline"); });
  await assert.rejects(client.generate("test"), /No cloud fallback/);
  assert.equal(calls,1);
});
test("invalid model is rejected", () => {
  assert.throws(() => new LocalOllama({model:"invalid model name"}));
});
test("empty prompts do not reach the transport", async () => {
  const client = new LocalOllama({model:"qwen2.5-coder:7b"}, async () => { throw new Error("Should not call"); });
  await assert.rejects(client.generate("  "), /Empty prompt/);
});

test("structured review requests Ollama JSON mode and temperature zero", async () => {
  const client = new LocalOllama({model:"qwen2.5-coder:7b"}, async (_url, init) => {
    if (_url.endsWith("/api/show")) return new Response(JSON.stringify({model_info: {"general.architecture": "qwen2"}}));
    const payload = JSON.parse(String(init.body));
    assert.equal(payload.format,"json");
    assert.equal(payload.options.temperature,0);
    return new Response(JSON.stringify({response:'{"findings":[]}'}),{status:200});
  });
  assert.equal(await client.generate("Review Java", {json:true}), '{"findings":[]}');
});


test("rejects remote endpoints, credentials, paths and insecure redirect handling", async () => {
  for (const endpoint of ["https://example.test", "http://example.test", "http://127.0.0.1:11434/path", "http://user:pass@127.0.0.1:11434", "http://127.0.0.1:11434?target=remote"]) {
    assert.throws(() => new LocalOllama({model: "qwen", endpoint}));
  }
  let target = "";
  const client = new LocalOllama({model: "qwen", endpoint: "http://localhost:11435"}, async (url, init) => {
    if (url.endsWith("/api/show")) return new Response(JSON.stringify({model_info: {"general.architecture": "qwen2"}}));
    target = url; assert.equal(init.redirect, "error");
    return new Response(JSON.stringify({response: "local"}));
  });
  await client.generate("test");
  assert.equal(target, "http://127.0.0.1:11435/api/generate");
});
test("checks installed local models without invoking generation or pulling", async () => {
  for (const installed of [true, false]) {
    const client = new LocalOllama({model: "qwen"}, async (url, init) => {
      assert.equal(url, "http://127.0.0.1:11434/api/tags"); assert.equal(init.method, "GET");
      return new Response(JSON.stringify({models: installed ? [{name: "qwen:latest"}] : []}));
    });
    if (installed) await client.ensureAvailable();
    else await assert.rejects(client.ensureAvailable(), /not installed locally/);
  }
});
test("local request timeout and cancellation abort the actual transport signal", async () => {
  const client = new LocalOllama({model: "qwen", timeoutMs: 15}, async (_url, init) => new Promise((_, reject) => {
    init.signal!.addEventListener("abort", () => reject(new Error("aborted")), {once: true});
  }));
  await assert.rejects(client.generate("test"), /No cloud fallback/);
  const controller = new AbortController();
  const pending = client.generate("test", {signal: controller.signal});
  controller.abort();
  await assert.rejects(pending, /No cloud fallback/);
});

test("oversized structured prompts fail before local transport", async () => {
  let calls = 0;
  const client = new LocalOllama({model: "qwen"}, async () => {calls++; throw new Error("unexpected");});
  await assert.rejects(client.generate("x".repeat(28001), {schema: {type: "object"}}), /context budget/);
  assert.equal(calls, 0);
});

test("cloud names and remote aliases never receive a prompt on the local route", async () => {
  for (const model of ["example:cloud", "example-cloud", "example/remote-cloud"]) {
    assert.throws(() => new LocalOllama({model}), /Cloud models/);
  }
  const bodies: string[] = [];
  const alias = new LocalOllama({model: "innocent-alias"}, async (url, init) => {
    assert.equal(url, "http://127.0.0.1:11434/api/show");
    bodies.push(String(init.body));
    return new Response(JSON.stringify({remote_host: "https://remote.example.test", remote_model: "upstream"}));
  });
  await assert.rejects(alias.generate("private synthetic source"), /No prompt sent/);
  assert.equal(bodies.length, 1);
  assert.doesNotMatch(bodies[0], /private synthetic source/);
});
test("missing local model metadata fails closed before generation", async () => {
  let calls = 0;
  const client = new LocalOllama({model: "alias"}, async url => {
    calls++; assert.ok(url.endsWith("/api/show")); return new Response(JSON.stringify({model_info: {}}));
  });
  await assert.rejects(client.generate("private"), /No prompt sent/);
  assert.equal(calls, 1);
});
test("remote model inventory entries cannot pass local availability checks", async () => {
  const client = new LocalOllama({model: "alias"}, async () => new Response(JSON.stringify({
    models: [{name: "alias:latest", remote_host: "https://remote.example.test", remote_model: "remote"}]
  })));
  await assert.rejects(client.ensureAvailable(), /Remote Ollama model rejected/);
});

test("prose answers stream NDJSON chunks to onText", async () => {
  const client = new LocalOllama({model:"qwen2.5-coder:7b"}, async (url, init) => {
    if (url.endsWith("/api/show")) return new Response(JSON.stringify({model_info: {"general.architecture": "qwen2"}}));
    assert.equal(JSON.parse(String(init.body)).stream, true);
    return new Response('{"response":"Hel"}\n{"response":"lo"}\n{"response":"","done":true}');
  });
  const chunks: string[] = [];
  assert.equal(await client.generate("Explain", {onText: chunk => chunks.push(chunk)}), "Hello");
  assert.deepEqual(chunks, ["Hel", "lo"]);
});
test("truncated streams fail without cloud fallback", async () => {
  const client = new LocalOllama({model:"qwen2.5-coder:7b"}, async (url) => {
    if (url.endsWith("/api/show")) return new Response(JSON.stringify({model_info: {"general.architecture": "qwen2"}}));
    return new Response('{"response":"Hel"}\n');
  });
  await assert.rejects(client.generate("Explain", {onText: () => undefined}), /No cloud fallback/);
});
