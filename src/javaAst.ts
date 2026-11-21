import {join} from "node:path";

/**
 * Java syntax trees (tree-sitter, WASM) for the taint engine: exact method declarations, parameter annotations, comments,
 * and the declared type of each call's receiver, so a call resolves to the class it is made on instead of to every
 * same-named method. Loaded asynchronously from dist/vendor; when it is unavailable the line-based engine runs alone.
 */
interface Point { row: number; column: number }
interface SyntaxNode {
  type: string; text: string; startIndex: number; endIndex: number; startPosition: Point; endPosition: Point; hasError: boolean;
  namedChildren: SyntaxNode[]; childForFieldName(name: string): SyntaxNode | null;
}
interface Parser { parse(text: string): {rootNode: SyntaxNode; delete(): void} | null }

export interface JavaParam { name: string; annotated: boolean }
/** Lines are 1-based; body is the 0-based [line, column] of the opening and closing braces. */
export interface JavaMethod { name: string; cls: string; startLine: number; endLine: number; body: [number, number, number, number]; params: JavaParam[]; varargs: boolean }
/** A call site: receiver is a declared type name, "self:Cls" for an unqualified or this-call inside Cls, or undefined when unknown. */
export interface JavaCall { name: string; line: number; argc: number; receiver?: string }
export interface JavaFile { text: string; methods: JavaMethod[]; calls: JavaCall[]; classes: {name: string; supers: string[]; methods: Set<string>}[] }

const ANNOTATED = /^(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|QueryParam|PathParam|FormParam|HeaderParam)$/;
const CLASS = /^(?:class|interface|enum|record|annotation_type)_declaration$/;

let active: Parser | undefined;
let generation = 0;
const loads = new Map<string, Promise<Parser | undefined>>();

async function load(dir: string): Promise<Parser | undefined> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const ts = require(join(dir, "web-tree-sitter.cjs")) as {
      Parser: {init(options: object): Promise<void>; new(): Parser & {setLanguage(language: unknown): void}};
      Language: {load(path: string): Promise<unknown>};
    };
    await ts.Parser.init({locateFile: (name: string) => join(dir, name)});
    const parser = new ts.Parser();
    parser.setLanguage(await ts.Language.load(join(dir, "tree-sitter-java.wasm")));
    return parser;
  } catch {
    return undefined;
  }
}

/** Loads the Java parser from dir (default: the bundled dist/vendor); resolves false, leaving the regex engine, when it cannot. */
export async function initJavaParser(dir = join(__dirname, "vendor")): Promise<boolean> {
  const mine = ++generation;
  let loading = loads.get(dir);
  if (!loading) loads.set(dir, loading = load(dir));
  const parser = await loading;
  if (mine === generation) active = parser;
  return parser !== undefined;
}

export const javaParserReady = (): boolean => active !== undefined && process.env.HUSHAVYR_JAVA_AST !== "0";

/** Simple name of a declared type (java.sql.Statement, List<String> → Statement, List); undefined for arrays, var and primitives. */
function typeName(node: SyntaxNode | null): string | undefined {
  if (!node) return undefined;
  if (node.type === "type_identifier") return node.text === "var" ? undefined : node.text;
  if (node.type === "scoped_type_identifier") return typeName(node.namedChildren[node.namedChildren.length - 1]);
  if (node.type === "generic_type") return typeName(node.namedChildren[0]);
  if (node.type === "annotated_type") return typeName(node.namedChildren[node.namedChildren.length - 1]);
  return undefined;
}

/** Declared type of a variable, using the initialiser for var (new X(), (X) y). */
function declared(type: SyntaxNode | null, value: SyntaxNode | null): string | undefined {
  if (type?.text !== "var") return typeName(type);
  if (value?.type === "object_creation_expression" || value?.type === "cast_expression") return typeName(value.childForFieldName("type"));
  return undefined;
}

const annotations = (node: SyntaxNode): string[] => node.namedChildren.find(c => c.type === "modifiers")?.namedChildren
  .filter(c => c.type === "annotation" || c.type === "marker_annotation").map(c => typeName(c.childForFieldName("name")) ?? c.childForFieldName("name")?.text.split(".").pop() ?? "") ?? [];

/** Parses Java source; undefined when the parser is not loaded or the file does not parse cleanly (the regex engine then handles it). */
export function parseJava(source: string): JavaFile | undefined {
  if (!javaParserReady()) return undefined;
  let tree;
  try { tree = active!.parse(source); } catch { return undefined; }
  if (!tree) return undefined;
  try {
    const root = tree.rootNode;
    if (root.hasError) return undefined;
    const chars = source.split(""), starts = [0];
    for (let i = 0; i < source.length; i++) if (source[i] === "\n") starts.push(i + 1);
    const at = (index: number): [number, number] => { let lo = 0, hi = starts.length - 1; while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= index) lo = mid; else hi = mid - 1; } return [lo, index - starts[lo]]; };
    const methods: JavaMethod[] = [], calls: JavaCall[] = [], classes: JavaFile["classes"] = [];
    // Each scope maps a variable to its declared type (undefined: declared, type unknown); fields open a class scope.
    const scopes: Map<string, string | undefined>[] = [];
    const owners: {name: string; fields: Map<string, string | undefined>}[] = [];
    const lookupVar = (name: string): {found: boolean; type?: string} => {
      for (let i = scopes.length - 1; i >= 0; i--) if (scopes[i].has(name)) return {found: true, type: scopes[i].get(name)};
      return {found: false};
    };
    const blank = (node: SyntaxNode, keepQuotes: boolean) => {
      for (let i = node.startIndex; i < node.endIndex; i++) if (chars[i] !== "\n" && chars[i] !== "\r") chars[i] = " ";
      if (keepQuotes) chars[node.endIndex - 1] = chars[node.endIndex - 2] = "\"";
    };
    const receiver = (object: SyntaxNode | null): string | undefined => {
      const owner = owners[owners.length - 1];
      if (!object) return owner?.name ? "self:" + owner.name : undefined;
      if (object.type === "this") return owner?.name ? "self:" + owner.name : undefined;
      if (object.type === "identifier") {
        const v = lookupVar(object.text);
        if (v.found) return v.type;
        return /^[A-Z]/.test(object.text) ? object.text : undefined;
      }
      if (object.type === "field_access" && object.childForFieldName("object")?.type === "this" && owner) {
        const field = object.childForFieldName("field")?.text ?? "";
        return owner.fields.get(field);
      }
      if (object.type === "object_creation_expression" && !object.namedChildren.some(c => c.type === "class_body")) return typeName(object.childForFieldName("type"));
      if (object.type === "parenthesized_expression" && object.namedChildren[0]?.type === "cast_expression") return typeName(object.namedChildren[0].childForFieldName("type"));
      if (object.type === "parenthesized_expression") return receiver(object.namedChildren[0]);
      return undefined;
    };
    const declare = (name: SyntaxNode | null, type: string | undefined) => { if (name && scopes.length) scopes[scopes.length - 1].set(name.text, type); };
    const params = (list: SyntaxNode | null): {params: JavaParam[]; varargs: boolean} => {
      const out: JavaParam[] = [];
      let varargs = false;
      for (const p of list?.namedChildren ?? []) {
        if (p.type === "formal_parameter") {
          declare(p.childForFieldName("name"), typeName(p.childForFieldName("type")));
          out.push({name: p.childForFieldName("name")?.text ?? "", annotated: annotations(p).some(a => ANNOTATED.test(a))});
        } else if (p.type === "spread_parameter") {
          const name = p.namedChildren.find(c => c.type === "variable_declarator")?.childForFieldName("name") ?? null;
          declare(name, undefined);
          out.push({name: name?.text ?? "", annotated: annotations(p).some(a => ANNOTATED.test(a))});
          varargs = true;
        }
      }
      return {params: out, varargs};
    };
    const classBody = (node: SyntaxNode, name: string, body: SyntaxNode | null) => {
      const fields = new Map<string, string | undefined>(), own = new Set<string>();
      for (const member of body?.namedChildren ?? []) {
        if (member.type === "field_declaration" || member.type === "constant_declaration") {
          const type = member.childForFieldName("type");
          for (const d of member.namedChildren) if (d.type === "variable_declarator") fields.set(d.childForFieldName("name")?.text ?? "", declared(type, d.childForFieldName("value")));
        } else if (member.type === "method_declaration" || member.type === "constructor_declaration") own.add(member.childForFieldName("name")?.text ?? "");
        else if (member.type === "enum_body_declarations") for (const m of member.namedChildren) {
          if (m.type === "method_declaration") own.add(m.childForFieldName("name")?.text ?? "");
          else if (m.type === "field_declaration") for (const d of m.namedChildren) if (d.type === "variable_declarator") fields.set(d.childForFieldName("name")?.text ?? "", declared(m.childForFieldName("type"), d.childForFieldName("value")));
        }
      }
      for (const p of node.type === "record_declaration" ? node.childForFieldName("parameters")?.namedChildren ?? [] : [])
        if (p.type === "formal_parameter") fields.set(p.childForFieldName("name")?.text ?? "", typeName(p.childForFieldName("type")));
      if (name) {
        const supers: string[] = [];
        for (const c of node.namedChildren) if (/^(?:superclass|super_interfaces|extends_interfaces)$/.test(c.type))
          for (const t of c.type === "superclass" ? c.namedChildren : c.namedChildren.flatMap(l => l.type === "type_list" ? l.namedChildren : [l])) { const n = typeName(t); if (n) supers.push(n); }
        classes.push({name, supers, methods: own});
      }
      owners.push({name, fields});
      scopes.push(new Map(fields));
      for (const member of body?.namedChildren ?? []) visit(member);
      scopes.pop();
      owners.pop();
    };
    const visit = (node: SyntaxNode): void => {
      switch (node.type) {
        case "line_comment": case "block_comment": blank(node, false); return;
        case "string_literal": if (node.text.startsWith("\"\"\"")) blank(node, true); return;
        case "class_declaration": case "interface_declaration": case "enum_declaration": case "record_declaration": case "annotation_type_declaration":
          for (const c of node.namedChildren) if (c.type !== "class_body" && c.type !== "interface_body" && c.type !== "enum_body" && c.type !== "annotation_type_body") visit(c);
          return classBody(node, node.childForFieldName("name")?.text ?? "", node.childForFieldName("body"));
        case "method_declaration": case "constructor_declaration": {
          const body = node.childForFieldName("body");
          scopes.push(new Map());
          const {params: ps, varargs} = params(node.childForFieldName("parameters"));
          if (body) {
            // The head starts at the first modifier keyword, return type or name after any annotations.
            const parts = node.namedChildren.flatMap(c => c.type === "modifiers" ? [] : [c]);
            const modifiers = node.namedChildren.find(c => c.type === "modifiers");
            const firstModifier = modifiers && modifiers.text.replace(/@[\w.]+(?:\s*\((?:[^()]|\([^()]*\))*\))?/g, m => " ".repeat(m.length)).search(/\S/);
            let start = parts[0]?.startPosition.row ?? node.startPosition.row;
            if (modifiers && firstModifier !== undefined && firstModifier >= 0) start = Math.min(start, modifiers.startPosition.row + (modifiers.text.slice(0, firstModifier).match(/\n/g)?.length ?? 0));
            methods.push({name: node.childForFieldName("name")?.text ?? "", cls: owners[owners.length - 1]?.name ?? "", startLine: start + 1, endLine: body.endPosition.row + 1,
              body: [...at(body.startIndex), ...at(body.endIndex - 1)] as [number, number, number, number], params: ps, varargs});
          }
          for (const c of node.namedChildren) if (c.type !== "formal_parameters") visit(c);
          scopes.pop();
          return;
        }
        case "block": case "constructor_body": case "switch_block": case "switch_block_statement_group": case "switch_rule":
        case "for_statement": case "enhanced_for_statement": case "catch_clause": case "try_with_resources_statement": case "lambda_expression": {
          scopes.push(new Map());
          if (node.type === "enhanced_for_statement") declare(node.childForFieldName("name"), typeName(node.childForFieldName("type")));
          if (node.type === "lambda_expression") {
            const p = node.childForFieldName("parameters");
            if (p?.type === "identifier") declare(p, undefined);
            else if (p?.type === "formal_parameters") params(p);
            else for (const id of p?.namedChildren ?? []) if (id.type === "identifier") declare(id, undefined);
          }
          for (const c of node.namedChildren) if (!(node.type === "lambda_expression" && c === node.childForFieldName("parameters"))) visit(c);
          scopes.pop();
          return;
        }
        case "catch_formal_parameter": declare(node.childForFieldName("name"), undefined); return;
        case "resource": {
          for (const c of node.namedChildren) visit(c);
          declare(node.childForFieldName("name"), declared(node.childForFieldName("type"), node.childForFieldName("value")));
          return;
        }
        case "local_variable_declaration": {
          const type = node.childForFieldName("type");
          for (const d of node.namedChildren) if (d.type === "variable_declarator") {
            for (const c of d.namedChildren) visit(c);
            declare(d.childForFieldName("name"), declared(type, d.childForFieldName("value")));
          }
          return;
        }
        case "type_pattern": case "record_pattern_component": {
          const id = node.namedChildren.find(c => c.type === "identifier");
          declare(id ?? null, undefined);
          break;
        }
        case "method_invocation": {
          const name = node.childForFieldName("name"), args = node.childForFieldName("arguments");
          const object = node.childForFieldName("object");
          if (name) calls.push({name: name.text, line: name.startPosition.row + 1, argc: args?.namedChildren.filter(a => !/comment$/.test(a.type)).length ?? 0, receiver: receiver(object)});
          break;
        }
        case "object_creation_expression": {
          const type = node.childForFieldName("type"), args = node.childForFieldName("arguments"), n = typeName(type), body = node.namedChildren.find(c => c.type === "class_body");
          if (n && type) calls.push({name: n, line: type.endPosition.row + 1, argc: args?.namedChildren.filter(a => !/comment$/.test(a.type)).length ?? 0, receiver: n});
          if (body) {
            for (const c of node.namedChildren) if (c !== body) visit(c);
            return classBody(node, "", body);
          }
          break;
        }
      }
      for (const c of node.namedChildren) visit(c);
    };
    scopes.push(new Map());
    visit(root);
    return {text: chars.join(""), methods, calls, classes};
  } catch {
    return undefined;
  } finally {
    tree.delete();
  }
}

/** Class hierarchy of the parsed Java files and receiver-type resolution of their call sites. */
export class JavaProject {
  private readonly supers = new Map<string, Set<string>>();
  private readonly subs = new Map<string, Set<string>>();
  private readonly owned = new Map<string, Set<string>>();
  private readonly sites = new Map<string, Map<string, JavaCall[]>>();

  constructor(files: ReadonlyMap<string, JavaFile>) {
    for (const [path, file] of files) {
      for (const c of file.classes) {
        const s = this.supers.get(c.name) ?? new Set<string>();
        for (const t of c.supers) { s.add(t); this.subs.set(t, (this.subs.get(t) ?? new Set<string>()).add(c.name)); }
        this.supers.set(c.name, s);
        const m = this.owned.get(c.name) ?? new Set<string>();
        for (const n of c.methods) m.add(n);
        this.owned.set(c.name, m);
      }
      const byName = new Map<string, JavaCall[]>();
      for (const call of file.calls) byName.set(call.name, [...(byName.get(call.name) ?? []), call]);
      this.sites.set(path, byName);
    }
  }

  isProject(cls: string): boolean { return this.supers.has(cls); }

  private closure(start: string, edges: Map<string, Set<string>>): Set<string> {
    const seen = new Set<string>([start]), queue = [start];
    while (queue.length) for (const next of edges.get(queue.pop()!) ?? []) if (!seen.has(next)) { seen.add(next); queue.push(next); }
    return seen;
  }

  /** The class itself and its project supertypes (where an inherited method is declared). */
  ancestors(cls: string): Set<string> { return this.closure(cls, this.supers); }

  /** Classes whose method a call on a receiver of these types may run: the type, its supertypes and its subtypes (overrides). */
  related(types: ReadonlySet<string>): Set<string> {
    const out = new Set<string>();
    for (const t of types) for (const c of [...this.closure(t, this.supers), ...this.closure(t, this.subs)]) out.add(c);
    return out;
  }

  /**
   * Receiver types of the calls of name on lines from..to of path, plus their argument counts; types is undefined when any
   * receiver is unknown (the caller then falls back to name matching). An unqualified call is typed by its own class only when
   * that class or a project supertype declares the method; otherwise it may be inherited from a library or statically imported.
   */
  resolve(path: string, name: string, from: number, to: number): {types?: Set<string>; argc: Set<number>} | undefined {
    const sites = this.sites.get(path)?.get(name)?.filter(c => c.line >= from && c.line <= to);
    if (!sites?.length) return undefined;
    const types = new Set<string>(), argc = new Set(sites.map(c => c.argc));
    let unknown = false;
    for (const c of sites) {
      if (c.receiver?.startsWith("self:")) {
        const cls = c.receiver.slice(5);
        if ([...this.ancestors(cls)].some(a => this.owned.get(a)?.has(name))) types.add(cls); else unknown = true;
      } else if (c.receiver) types.add(c.receiver);
      else unknown = true;
    }
    return {types: unknown ? undefined : types, argc};
  }
}
