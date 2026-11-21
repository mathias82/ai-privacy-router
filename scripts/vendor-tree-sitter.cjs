// Copies the tree-sitter WASM runtime and the Java grammar into dist/vendor, so the packaged extension and CLI
// (shipped without node_modules) can parse Java. A missing file only disables the AST path; the regex engine stays.
const {copyFileSync, existsSync, mkdirSync} = require("node:fs");
const {join} = require("node:path");

const root = join(__dirname, "..");
const out = join(root, "dist", "vendor");
const files = [
  ["web-tree-sitter/web-tree-sitter.cjs", "web-tree-sitter.cjs"],
  ["web-tree-sitter/web-tree-sitter.wasm", "web-tree-sitter.wasm"],
  ["web-tree-sitter/LICENSE", "web-tree-sitter.LICENSE"],
  ["tree-sitter-java/tree-sitter-java.wasm", "tree-sitter-java.wasm"],
  ["tree-sitter-java/LICENSE", "tree-sitter-java.LICENSE"]
];
mkdirSync(out, {recursive: true});
for (const [from, to] of files) {
  const source = join(root, "node_modules", from);
  if (existsSync(source)) copyFileSync(source, join(out, to));
  else console.warn("vendor-tree-sitter: " + from + " not found; Java taint falls back to the line-based engine");
}
