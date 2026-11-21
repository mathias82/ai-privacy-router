import {definedNames, definitionSnippet} from "./callContext";
import {initJavaParser, JavaFile, JavaProject, parseJava} from "./javaAst";

export {initJavaParser};
// Loading starts at import, so a scan that reads files first finds the parser ready; await initJavaParser() to be sure.
void initJavaParser();

/**
 * Project-wide (interprocedural, cross-file) taint tracking without a model or Semgrep Pro.
 * Each function gets a summary "parameter i reaches sink K" and "parameter i reaches the return value"; summaries are
 * propagated through calls to a fixpoint, then request input (req.query, @RequestParam, getParameter...) is followed into them.
 * Statements are tracked with their block context, so constant conditions, constant switch selectors and constant
 * collection slots do not carry taint, and assignments inside conditional branches only add taint.
 * Heuristic and line-based: it reports a path to verify, not a proof. Java files are parsed with tree-sitter when the parser
 * is loaded (initJavaParser): methods, parameters and annotations come from the syntax tree, comments are ignored, and a
 * call on a receiver of a declared type resolves only to that type's methods (and only reaches a SQL, command, LDAP, XPath
 * or session sink on a matching API type).
 */
export type SinkKind = "sql" | "command" | "code" | "path" | "ssrf" | "xss" | "ldap" | "xpath" | "trust-boundary";
export interface TaintFile { path: string; text: string }
export interface TaintFlow { kind: SinkKind; source: {path: string; line: number}; sink: {path: string; line: number}; via: string[] }

const JAVA = /\.(?:java|kt)$/i;
const BRACES = /\.(?:java|kt|js|jsx|mjs|cjs|ts|tsx|cs|php|go|rs|scala|swift)$/i;
interface Sink { kind: SinkKind; call: RegExp; when?: RegExp; lang?: RegExp; scope?: RegExp; all?: boolean }
const SINKS: Sink[] = [
  {kind: "sql", call: /(?:^|[^\w$])(?:executeQuery|executeUpdate|execute|executemany|query|raw|createQuery|createNativeQuery|prepareStatement|exec_driver_sql)\s*\(/g},
  {kind: "sql", call: /\.(?:prepareCall|addBatch|batchUpdate|queryFor\w+)\s*\(/g, lang: JAVA},
  {kind: "command", call: /(?:\bos\.(?:system|popen)|child_process\.(?:exec|execSync)|getRuntime\(\)\.exec|(?:^|[^\w$.])(?:exec|execSync|system|popen))\s*\(/g},
  {kind: "command", call: /\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\(/g, when: /shell\s*=\s*True/},
  {kind: "command", call: /(?:\.exec|\.command|\bnew\s+ProcessBuilder)\s*\(/g, lang: JAVA, all: true},
  {kind: "code", call: /(?:(?:^|[^\w$.])(?:eval|Function)|\bnew\s+Function)\s*\(/g},
  {kind: "path", call: /(?:\b(?:readFile|readFileSync|createReadStream|sendFile|unlink|unlinkSync)|\bFiles\.(?:readAllBytes|readString|newInputStream|lines|delete)|\bnew\s+(?:File|FileInputStream)|(?:^|[^\w$.])open)\s*\(/g},
  {kind: "path", call: /(?:\bnew\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)|\b(?:java\.nio\.file\.)?(?:Paths\.get|Path\.of))\s*\(/g, lang: JAVA, all: true},
  {kind: "ssrf", call: /(?:(?:^|[^\w$.])(?:fetch|urlopen)|\baxios(?:\.(?:get|post|put|request))?|\brequests\.(?:get|post|put|request)|\bhttps?\.get|\bgetForObject|\bgetForEntity)\s*\(/g},
  {kind: "xss", call: /(?:\.(?:innerHTML|outerHTML)\s*\+?=|\bdocument\.write\s*\()/g},
  {kind: "xss", call: /\b(?:getWriter|getOutputStream)\(\)\.(?:print|println|write|format|printf|append)\s*\(/g, lang: JAVA, all: true},
  {kind: "ldap", call: /\.search\s*\(/g, lang: JAVA, all: true, scope: /\b(?:Initial)?(?:Ldap|Dir)Context\b/},
  {kind: "xpath", call: /\.(?:evaluate|compile)\s*\(/g, lang: JAVA, scope: /\bXPath\b/},
  {kind: "trust-boundary", call: /(?:\bgetSession\([^)]*\)|\b\w*[sS]ession)\.(?:setAttribute|putValue)\s*\(/g, lang: JAVA, all: true}
];
// Request accessors, including wrapper/helper getters such as getRequestParameter or getCustomHeader (init parameters are trusted config).
const SOURCE = /\b(?:req|request)\.(?:query|params|body|headers|cookies|args|form|values|json|GET|POST|FILES|data)\b|\b(?:get(?!Init)\w*?(?:Parameter|Header|Cookie)s?(?:Values|Map|Names)?|getQueryString)\s*\(/;
/** Output encoders only neutralise markup; the value stays dangerous for queries, commands, paths and sessions. */
const HTML_ESCAPE = /\b(?:escapeHtml\w*|escapeXml\w*|htmlEscape\w*|encodeForHTML\w*|encodeForXML\w*|encodeForJavaScript|escapeEcmaScript)\s*\(/;
const SANITIZER = /\b(?:parseInt|parseFloat|Number|Integer\.parseInt|Long\.parseLong|int|float|bool|escape\w*|encodeURIComponent|encodeFor\w*|htmlEscape\w*|sanitize\w*|quote|basename|UUID\.fromString|isValid\w*|validate\w*|clean\w*)\s*\(/;
const ANNOTATED = /@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|QueryParam|PathParam|FormParam|HeaderParam)\b/;
const ROUTE = /^\s*@\w+(?:\.\w+)*\.(?:route|get|post|put|delete|patch)\s*\(/;
const ASSIGN = /^\s*((?:(?:const|let|var|final|val|auto|static)\s+)*(?:[\w$.]+(?:\s*<[^=]*>)?(?:\s*\[\s*\])*\s+)?)([A-Za-z_$][\w$]*)\s*(\+?=)(?!=)\s*([\s\S]+)$/;
const MUTATOR = /^(?:add|addAll|addElement|addFirst|addLast|append|insert|offer|push|put|putAll|putIfAbsent|set|setProperty|remove|clear|merge|compute\w*)$/;
const CONTAINER = /^new\s+[\w$.]*(?:List|Map|Set|Vector|Stack|Queue|Deque)\s*(?:<[^()]*>)?\s*\(\s*\)$/;
const MAX_FILES = 3000;
/** API types whose methods are the sinks; a typed receiver of any other type (a project class, an executor, an HTTP client) is not the sink. */
const RECEIVER: Partial<Record<SinkKind, RegExp>> = {
  sql: /^(?:Statement|PreparedStatement|CallableStatement|Connection|\w*Jdbc\w*|EntityManager|\w*Session|Query|TypedQuery|NativeQuery|SQLiteDatabase|DSLContext|Handle|DatabaseClient)$/,
  command: /^(?:Runtime|ProcessBuilder)$/,
  ldap: /^(?:\w*DirContext|\w*LdapContext|LdapTemplate|LdapOperations)$/,
  xpath: /^(?:XPath|XPathExpression)$/,
  "trust-boundary": /^\w*Session$/
};
/** A method or constructor head (Java, C#, Kotlin, JS/TS functions); calls end with ";" and control statements are excluded. */
const DECL = /^\s*(?:@[\w.]+(?:\([^)]*\))?\s+)*(?:(?:public|private|protected|static|final|abstract|synchronized|native|default|override|async|internal|open|suspend)\s+)*(?:fun\s+|function\s*\*?\s*|func\s+|(?!(?:return|new|else|throw|await|yield|case|typeof|delete|if|for|while|switch|catch)\b)[\w$.]+(?:<[^()]*>)?(?:\[\s*\])*\s+)(?!(?:if|for|while|switch|catch|synchronized)\b)[A-Za-z_$][\w$]*\s*\([^;]*\)\s*(?:throws\s+[\w$.,\s]+?)?(?::\s*[\w$.<>[\]?, ]+)?\s*\{/;

/** Code with comments removed and plain string contents replaced by "@n" (n indexes lits); template literals and f-strings keep their interpolations. */
function code(line: string, lits: string[]): string {
  return line.replace(/(?<![fF\w])"(?:[^"\x5c]|\x5c.)*"|(?<![fF\w])'(?:[^'\x5c]|\x5c.)*'/g, s => "\"@" + (lits.push(s.slice(1, -1)) - 1) + "\"")
    .replace(/\/\/.*$|(?:^|\s)#.*$/, "");
}

/** Index of the bracket closing the one at open, or text.length. */
function closing(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if ("([{".includes(text[i])) depth++;
    else if (")]}".includes(text[i]) && --depth === 0) return i;
  }
  return text.length;
}

/** Top-level comma-separated arguments from the "(" at open until the matching ")" or end of text. */
function splitArgs(text: string, open: number): string[] {
  const args: string[] = [];
  let depth = 0, current = "";
  for (let i = open + 1; i < text.length; i++) {
    const ch = text[i];
    if ("([{".includes(ch)) depth++;
    else if (")]}".includes(ch)) { if (depth === 0) break; depth--; }
    else if (ch === "," && depth === 0) { args.push(current); current = ""; continue; }
    current += ch;
  }
  if (current.trim() || args.length) args.push(current);
  return args;
}

const depth = (text: string) => (text.match(/[([]/g)?.length ?? 0) - (text.match(/[)\]]/g)?.length ?? 0);

/** Statements: physical lines joined while brackets are open or an operator continues them, then split at top-level ";". */
function statements(lines: readonly string[], lits: string[]): {text: string; index: number; end: number}[] {
  const out: {text: string; index: number; end: number}[] = [];
  for (let i = 0; i < lines.length; i++) {
    const index = i;
    let text = code(lines[i], lits);
    while (i + 1 < lines.length && i - index < 12 && !/[{};]\s*$/.test(text) &&
      (depth(text) > 0 || /(?:[=+,?([]|&&|\|\|)\s*$/.test(text) || /^\s*(?:\.(?!\.)|\+(?!\+)|\?|:(?!:)|&&|\|\|)/.test(lines[i + 1]))) text += " " + code(lines[++i], lits);
    let level = 0, start = 0;
    for (let k = 0; k < text.length; k++) {
      if ("([".includes(text[k])) level++;
      else if (")]".includes(text[k])) level--;
      else if (text[k] === ";" && level <= 0) { out.push({text: text.slice(start, k), index, end: i}); start = k + 1; }
    }
    if (text.slice(start).trim() || start === 0) out.push({text: text.slice(start), index, end: i});
  }
  return out;
}

type Value = number | string | boolean;
/** Value of a constant arithmetic/comparison expression over known constants, or undefined. */
function evaluate(expr: string, consts: ReadonlyMap<string, Value>): Value | undefined {
  const tokens = expr.match(/\d+|[A-Za-z_$][\w$]*|[<>!=]=|&&|\|\||\S/g) ?? [];
  let i = 0;
  const num = (v: Value): number => { if (typeof v !== "number") throw 0; return v; };
  const prim = (): Value => {
    const t = tokens[i++];
    if (t === "(") { const v = or(); if (tokens[i++] !== ")") throw 0; return v; }
    if (t === "-") return -num(prim());
    if (t === "!") { const v = prim(); if (typeof v !== "boolean") throw 0; return !v; }
    if (/^\d+$/.test(t ?? "")) return Number(t);
    if (t === "true" || t === "false") return t === "true";
    const c = consts.get(t);
    if (typeof c === "number" || typeof c === "boolean") return c;
    throw 0;
  };
  const level = (next: () => Value, ops: string[], apply: (op: string, a: Value, b: Value) => Value) => (): Value => {
    let v = next();
    while (ops.includes(tokens[i])) { const op = tokens[i++]; v = apply(op, v, next()); }
    return v;
  };
  const mul = level(prim, ["*", "/", "%"], (op, a, b) => {
    const x = num(a), y = num(b);
    if (op !== "*" && y === 0) throw 0;
    return op === "*" ? x * y : op === "/" ? Math.trunc(x / y) : x % y;
  });
  const add = level(mul, ["+", "-"], (op, a, b) => op === "+" ? num(a) + num(b) : num(a) - num(b));
  const cmp = level(add, ["<", ">", "<=", ">="], (op, a, b) => op === "<" ? num(a) < num(b) : op === ">" ? num(a) > num(b) : op === "<=" ? num(a) <= num(b) : num(a) >= num(b));
  const eq = level(cmp, ["==", "!="], (op, a, b) => op === "==" ? a === b : a !== b);
  const and = level(eq, ["&&"], (_, a, b) => a === true && b === true);
  const or: () => Value = level(and, ["||"], (_, a, b) => a === true || b === true);
  try { const v = or(); return i === tokens.length ? v : undefined; } catch { return undefined; }
}

interface Param { name: string; annotated: boolean }
function params(snippet: string, path: string): Param[] {
  const open = snippet.indexOf("(");
  if (open < 0) return [];
  const go = /\.go$/i.test(path);
  return splitArgs(snippet, open).map(part => {
    const annotated = ANNOTATED.test(part);
    const bare = part.replace(/@\w+(?:\([^)]*\))?/g, "").replace(/=[\s\S]*$/, "").replace(/^\s*(?:\.\.\.|\*\*|\*)/, "").trim();
    if (/^[{[]/.test(bare)) return {name: "", annotated};
    const name = bare.includes(":") ? bare.split(":")[0].trim() : go ? (/^([A-Za-z_]\w*)/.exec(bare)?.[1] ?? "") : (/([A-Za-z_]\w*)\s*$/.exec(bare)?.[1] ?? "");
    return {name, annotated};
  }).filter(p => p.name !== "self" && p.name !== "cls");
}

interface Reach { kind: SinkKind; path: string; line: number; via: string[] }
/** returns: parameters whose taint is returned; markup: the subset still returned without HTML encoding. */
interface Summary { path: string; sinks: Map<number, Reach>; returns: Set<number>; markup: Set<number>; source: boolean; cls?: string; arity?: number; varargs?: boolean }
type Site = ReturnType<JavaProject["resolve"]>;
type Summaries = Map<string, Summary[]>;
const FAMILY: [RegExp, string][] = [[/\.(?:java|kt|scala|groovy)$/i, "jvm"], [/\.(?:[cm]?js|jsx|tsx?)$/i, "js"], [/\.py$/i, "py"], [/\.cs$/i, "cs"], [/\.php$/i, "php"], [/\.go$/i, "go"], [/\.rb$/i, "rb"], [/\.rs$/i, "rs"]];
const family = (path: string) => FAMILY.find(([re]) => re.test(path))?.[1] ?? path;
/** Summaries for a called name; a definition in the calling file shadows same-named ones elsewhere.
 * Without types a call is matched by name only, so other languages never match, and a name defined
 * in more than two other files (execute, run, handle) is too ambiguous to follow. A parsed Java call site narrows the
 * candidates to overloads taking its argument count and, when its receiver type is known, to that type's hierarchy. */
function lookup(summaries: Summaries, name: string, path: string, site?: Site, project?: JavaProject): Summary[] {
  let all = summaries.get(name) ?? [];
  if (site) {
    all = all.filter(s => s.arity === undefined || [...site.argc].some(n => n === s.arity || (s.varargs && n >= s.arity! - 1)));
    const classes = site.types && project?.related(site.types);
    if (classes) all = all.filter(s => s.cls === undefined || classes.has(s.cls));
  }
  const own = all.filter(s => s.path === path);
  if (own.length) return own;
  const lang = family(path), same = all.filter(s => family(s.path) === lang);
  return new Set(same.map(s => s.path)).size > 2 ? [] : same;
}

interface Fn { name: string; path: string; startLine: number; lines: string[]; params: Param[]; route: boolean; summary: Summary; skipHead: boolean }
/** Parsed Java methods: only the body is analysed (the head is blanked), so a method named like a sink is not its own sink. */
function javaFunctions(path: string, java: JavaFile): Fn[] {
  const all = java.text.split(/\r?\n/);
  return java.methods.map(m => {
    const [openLine, openColumn, closeLine, closeColumn] = m.body;
    const lines = all.slice(m.startLine - 1, m.endLine).map((line, k) => {
      const row = m.startLine - 1 + k;
      if (row === closeLine) line = line.slice(0, closeColumn + 1);
      return row < openLine ? "" : row === openLine ? " ".repeat(openColumn) + line.slice(openColumn) : line;
    });
    return {m, lines};
  }).map(({m, lines}) => ({name: m.name, path, startLine: m.startLine, lines, params: m.params, skipHead: false,
    route: all.slice(Math.max(0, m.startLine - 4), m.startLine - 1).some(l => ROUTE.test(l)),
    summary: {path, sinks: new Map(), returns: new Set(), markup: new Set(), source: false, cls: m.cls, arity: m.params.length, varargs: m.varargs}}));
}

function functions(file: TaintFile): Fn[] {
  const all = file.text.split(/\r?\n/);
  const fns: Fn[] = [];
  for (const name of definedNames(file.text)) {
    const snippet = definitionSnippet(file.text, name, 300);
    if (!snippet) continue;
    const head = snippet.text.split("\n")[0];
    // Multi-line calls ("new String(", "x = foo(") look like declarations; a definition has a body.
    if (new RegExp("(?:\\bnew\\s+|[=.]\\s*)" + name + "\\s*\\(").test(head) || (BRACES.test(file.path) && !/\{/.test(snippet.text.split(";")[0]))) continue;
    const above = all.slice(Math.max(0, snippet.startLine - 4), snippet.startLine - 1);
    fns.push({name, path: file.path, startLine: snippet.startLine, skipHead: true, lines: snippet.text.split("\n"), params: params(snippet.text, file.path),
      route: above.some(l => ROUTE.test(l)), summary: {path: file.path, sinks: new Map(), returns: new Set(), markup: new Set(), source: false}});
  }
  return fns;
}

interface Hit extends Reach { origin: number }
interface Ctx { kind: "plain" | "cond" | "dead" | "switch"; value?: Value; live?: boolean; matched?: boolean }
interface Slots { list?: (number | undefined)[]; keys: Map<string, number | undefined>; depth: number }

/** Follows tainted variables through one body; returns every sink reached (directly or through summarised calls) and whether taint is returned. */
function analyse(lines: readonly string[], firstLine: number, path: string, initial: ReadonlyMap<string, number>, summaries: Summaries, skipFirst: boolean, project?: JavaProject): {hits: Hit[]; returned?: number; markup?: number} {
  const tainted = new Map(initial), htmlSafe = new Set<string>(), writers = new Set<string>(), consts = new Map<string, Value>(), slots = new Map<string, Slots>();
  const lits: string[] = [], hits: Hit[] = [], stack: Ctx[] = [], ifs = new Map<number, boolean | undefined>();
  const body = lines.join("\n"), braces = BRACES.test(path);
  let returned: number | undefined, markup: number | undefined, pending: Ctx | undefined, span = [0, 0];
  /** Syntax-tree view of the calls of name in the current statement (Java only). */
  const site = (name: string): Site => project?.resolve(path, name, span[0], span[1]);
  const live = () => stack.every(c => c.kind !== "dead" && (c.kind !== "switch" || c.live));
  /** Whether an update may not happen: a conditional block was entered since the variable's block (from). */
  const weak = (from = 0) => stack.slice(from).some(c => c.kind === "cond" || (c.kind === "switch" && c.value === undefined));
  const constant = (expr: string): Value | undefined => {
    const e = expr.trim().replace(/^\((?:int|long|short|char|String)\)\s*/, "");
    const lit = /^"@(\d+)"$/.exec(e);
    if (lit) return lits[+lit[1]];
    if (/^[A-Za-z_$][\w$]*$/.test(e) && consts.has(e)) return consts.get(e);
    const at = /^([A-Za-z_$][\w$]*)\.charAt\(\s*(\d+)\s*\)$/.exec(e), s = at && consts.get(at[1]);
    if (at) return typeof s === "string" && +at[2] < s.length ? s[+at[2]] : undefined;
    return evaluate(e, consts);
  };
  /** cond ? a : b with a constant condition becomes the taken branch. */
  const ternary = (expr: string): string => {
    let level = 0, q = -1, nested = 0;
    for (let i = 0; i < expr.length; i++) {
      const ch = expr[i];
      if ("([{".includes(ch)) level++;
      else if (")]}".includes(ch)) level--;
      else if (level === 0 && ch === "?" && !/[?.]/.test(expr[i + 1] ?? "") && expr[i - 1] !== "?") { if (q < 0) q = i; else nested++; }
      else if (level === 0 && ch === ":" && q >= 0 && expr[i + 1] !== ":" && nested-- === 0) {
        const v = constant(expr.slice(0, q));
        return v === true ? ternary(expr.slice(q + 1, i)) : v === false ? ternary(expr.slice(i + 1)) : expr;
      }
    }
    return expr;
  };
  const origin = (input: string, line: number, kind?: SinkKind): number | undefined => {
    let expr = ternary(input), found: number | undefined;
    const xss = kind === "xss";
    if ((xss && HTML_ESCAPE.test(expr)) || (!HTML_ESCAPE.test(expr) && SANITIZER.test(expr))) return undefined;
    if (SOURCE.test(expr)) return line;
    // Reads of tracked collection slots and calls of analysed functions only carry what actually flows through them.
    expr = expr.replace(/\b([A-Za-z_$][\w$]*)\.get\(\s*("@\d+"|\d+)\s*\)/g, (m, name: string, key: string) => {
      const s = slots.get(name);
      if (!s) return m;
      found ??= /^\d/.test(key) ? s.list?.[+key] : s.keys.get(lits[+key.slice(2, -1)]);
      return "\"\"";
    });
    for (let guard = 0; guard < 20; guard++) {
      const call = [...expr.matchAll(/(?:\bthis\.|\bself\.|\bnew\s+[\w$.]+\s*\([^()]*\)\s*\.|\b[A-Z][\w$]*\.|(?<![\w$.]))([A-Za-z_$][\w$]*)\s*\(/g)]
        .find(m => summaries.has(m[1]) && !/^(?:new|if|for|while|switch|return|catch)$/.test(m[1]));
      if (!call) break;
      const open = call.index! + call[0].length - 1, args = splitArgs(expr, open);
      for (const s of lookup(summaries, call[1], path, site(call[1]), project)) {
        if (s.source) found ??= line;
        for (const i of xss ? s.markup : s.returns) if (args[i] !== undefined) found ??= origin(args[i], line, kind);
      }
      expr = expr.slice(0, call.index) + "\"\"" + expr.slice(closing(expr, open) + 1);
    }
    if (found !== undefined) return found;
    for (const word of expr.match(/[A-Za-z_$][\w$]*/g) ?? []) if (tainted.has(word) && !(xss && htmlSafe.has(word))) return tainted.get(word);
    return undefined;
  };
  const assign = (name: string, op: string, rhs: string, line: number, isWeak: boolean) => {
    const from = origin(rhs, line), value = op === "=" && !isWeak ? constant(ternary(rhs)) : undefined;
    if (value !== undefined) consts.set(name, value); else consts.delete(name);
    if (op === "=" && !isWeak && CONTAINER.test(rhs.trim())) slots.set(name, {list: [], keys: new Map(), depth: stack.length}); else if (op === "=" || from !== undefined) slots.delete(name);
    if (/\b(?:getWriter|getOutputStream)\(\)\s*$/.test(rhs)) writers.add(name); else if (op === "=") writers.delete(name);
    const strong = op === "=" && !isWeak, keep = strong || !tainted.has(name) || htmlSafe.has(name);
    if (from !== undefined && keep && origin(rhs, line, "xss") === undefined) htmlSafe.add(name); else if (from !== undefined || strong) htmlSafe.delete(name);
    if (from !== undefined) tainted.set(name, from);
    else if (strong) tainted.delete(name);
  };
  const mutate = (name: string, method: string, args: string[], line: number, isWeak: boolean) => {
    const from = origin(args.join(","), line), s = slots.get(name);
    if (s) isWeak = weak(s.depth);
    if (s && !isWeak && method === "add" && args.length === 1 && s.list) s.list.push(origin(args[0], line));
    else if (s && !isWeak && method === "put" && args.length === 2 && /^\s*"@\d+"\s*$/.test(args[0])) s.keys.set(lits[+args[0].trim().slice(2, -1)], origin(args[1], line));
    else if (s && !isWeak && method === "remove" && /^\s*\d+\s*$/.test(args[0] ?? "") && s.list) s.list.splice(+args[0], 1);
    else if (s && !isWeak && method === "clear") slots.set(name, {list: [], keys: new Map(), depth: s.depth});
    else slots.delete(name);
    if (from !== undefined) tainted.set(name, from);
  };
  const sinks = (input: string, line: number) => {
    // A writer kept in a variable (out = response.getWriter()) is the same sink as the inline call.
    const text = writers.size ? input.replace(new RegExp("(?<![\\w$.])(?:" + [...writers].join("|") + ")\\.(?=(?:print|println|write|format|printf|append)\\s*\\()", "g"), "getWriter().") : input;
    for (const sink of SINKS) {
      if ((sink.lang && !sink.lang.test(path)) || (sink.when && !sink.when.test(text)) || (sink.scope && !sink.scope.test(body))) continue;
      for (const m of text.matchAll(sink.call)) {
        // Database handles are objects (stmt.execute, cursor.execute); Helper.execute(...) is a static call into application code.
        if (sink.kind === "sql" && /(?<![\w$.])[A-Z][\w$]*\.$/.test(text.slice(0, m.index! + 1))) continue;
        const method = /(?<!\bnew\s+)\b([A-Za-z_$][\w$]*)\s*\($/.exec(m[0])?.[1], types = method && RECEIVER[sink.kind] ? site(method)?.types : undefined;
        if (types && project && ![...types].some(t => [...project.ancestors(t)].some(a => RECEIVER[sink.kind]!.test(a)))) continue;
        const end = m.index! + m[0].length, args = m[0].endsWith("(") ? splitArgs(text, end - 1) : [text.slice(end)];
        const from = origin(sink.all ? args.join(",") : args[0] ?? "", line, sink.kind);
        if (from !== undefined) hits.push({kind: sink.kind, path, line, via: [], origin: from});
      }
    }
  };
  const calls = (text: string, line: number) => {
    for (const m of text.matchAll(/([A-Za-z_$][\w$]*)\s*\(/g)) {
      if (/\b(?:function|def|fun|func)\s+$/.test(text.slice(0, m.index))) continue;
      const args = splitArgs(text, m.index! + m[0].length - 1);
      for (const s of lookup(summaries, m[1], path, site(m[1]), project)) for (const [i, reach] of s.sinks) {
        const from = args[i] === undefined ? undefined : origin(args[i], line, reach.kind);
        if (from !== undefined) hits.push({...reach, via: [m[1], ...reach.via], origin: from});
      }
    }
  };
  const enter = (ctx: Ctx, rest: string, line: number, first: boolean) => {
    const r = rest.trim();
    if (!r) { pending = ctx; return; }
    stack.push(ctx);
    if (r.startsWith("{")) step(r.slice(1), line, first);
    else { step(r, line, first); stack.pop(); }
  };
  const step = (input: string, line: number, first: boolean): void => {
    let text = input;
    if (braces) while (/^\s*\}/.test(text)) { stack.pop(); text = text.replace(/^\s*\}/, ""); }
    if (!text.trim()) return;
    if (pending) { const ctx = pending; pending = undefined; return enter(ctx, text, line, first); }
    const top = stack[stack.length - 1], label = /^\s*(?:case\s+([^:]+?)|default)\s*:(?!:)([\s\S]*)$/.exec(text);
    if (braces && label && top?.kind === "switch" && stack.slice(0, -1).every(c => c.kind !== "dead")) {
      if (top.value !== undefined) {
        const v = label[1] === undefined ? undefined : constant(label[1]);
        const hit = label[1] === undefined ? !top.matched : v === undefined || v === top.value;
        if (hit) top.live = top.matched = true;
      }
      return step(label[2], line, first);
    }
    if (!live()) {
      if (braces) for (const ch of text) if (ch === "{") stack.push({kind: "dead"}); else if (ch === "}") stack.pop();
      return;
    }
    if (braces && top?.kind === "switch" && top.value !== undefined && /^\s*(?:break|return|throw|continue)\b/.test(text)) top.live = false;
    // Whole-file passes meet every method in turn: locals of one method must not taint a same-named variable or parameter of the next.
    // A function's own head (int execute(Connection c)) names it; it is not a call of the sink with that name.
    if (first && !braces && /^\s*(?:async\s+)?(?:def|fn|func|function)\b/.test(text)) return;
    const head = first && braces ? DECL.exec(text) : null;
    if (head) {
      stack.push({kind: "plain"});
      const rest = text.slice(head[0].length);
      return rest.trim() ? step(rest, line, first) : undefined;
    }
    const decl = braces && !first && initial.size === 0 ? DECL.exec(text) : null;
    if (decl) {
      tainted.clear(); htmlSafe.clear(); writers.clear(); consts.clear(); slots.clear();
      stack.push({kind: "plain"});
      const rest = text.slice(decl[0].length);
      return rest.trim() ? step(rest, line, first) : undefined;
    }
    const header = braces ? /^\s*(?:(else\s+if|if|for|while|switch|catch|synchronized)\s*\(|(else|do|try|finally)\b)/.exec(text) : null;
    if (header) {
      const d = stack.length;
      if (header[2]) {
        const prev = ifs.get(d);
        const kind = header[2] !== "else" ? "plain" : prev === true ? "dead" : prev === false ? "plain" : "cond";
        return enter({kind}, text.slice(header.index + header[0].length), line, first);
      }
      const open = header[0].length - 1, close = closing(text, open), cond = text.slice(open + 1, close);
      if (!first) { sinks(text.slice(0, close + 1), line); calls(text.slice(0, close + 1), line); } else sinks(text.slice(0, close + 1), line);
      const rest = text.slice(close + 1);
      if (header[1] === "switch") return enter({kind: "switch", value: constant(cond), live: constant(cond) === undefined, matched: false}, rest, line, first);
      if (header[1] === "for") {
        const each = /([A-Za-z_$][\w$]*)\s*(?::|\s+of\s+|\s+in\s+)([^;]+)$/.exec(cond);
        if (each && !first) assign(each[1], "=", each[2], line, true);
      }
      if (header[1] !== "if" && header[1] !== "else if") return enter({kind: "cond"}, rest, line, first);
      const prev = header[1] === "if" ? false : ifs.get(d), v = prev === true ? undefined : constant(cond);
      const kind = prev === true || v === false ? "dead" : v === true && prev === false ? "plain" : "cond";
      ifs.set(d, prev === true || v === true ? true : prev === false && v === false ? false : undefined);
      return enter({kind}, rest, line, first);
    }
    sinks(text, line);
    if (!first) {
      calls(text, line);
      const isWeak = weak();
      const ret = /^\s*return\b([\s\S]*)$/.exec(text), destructure = /^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(.+)$/.exec(text);
      const assignment = ASSIGN.exec(text), mutation = /^\s*([A-Za-z_$][\w$]*)\.(\w+)\s*\(/.exec(text), element = /^\s*([A-Za-z_$][\w$]*)\s*\[[^\]]*\]\s*=(?!=)([\s\S]+)$/.exec(text);
      if (ret && ret[1].trim()) { returned ??= origin(ret[1], line); markup ??= origin(ret[1], line, "xss"); }
      else if (destructure) {
        const from = origin(destructure[2], line);
        if (from !== undefined) for (const name of destructure[1].split(",")) { const n = name.split(":").pop()!.trim(); if (n) tainted.set(n, from); }
      } else if (assignment) assign(assignment[2], assignment[3], assignment[4], line, isWeak && !assignment[1].trim());
      else if (mutation && MUTATOR.test(mutation[2])) mutate(mutation[1], mutation[2], splitArgs(text, mutation.index + mutation[0].length - 1), line, isWeak);
      else if (element) { const from = origin(element[2], line); if (from !== undefined) tainted.set(element[1], from); }
    }
    if (braces) {
      let level = 0;
      for (const ch of text) if (ch === "{") { stack.push({kind: "plain"}); level++; } else if (ch === "}" && level-- > 0) stack.pop(); else if (ch === "}") stack.pop();
    }
  };
  for (const s of statements(lines, lits)) { span = [firstLine + s.index, firstLine + s.end]; step(s.text, firstLine + s.index, skipFirst && s.index === 0); }
  return {hits, returned, markup};
}

export function taintFlows(files: readonly TaintFile[]): TaintFlow[] {
  const sources = files.slice(0, MAX_FILES).filter(f => f.text.length <= 200_000);
  const trees = new Map<string, JavaFile>();
  for (const f of sources) {
    const tree = /\.java$/i.test(f.path) ? parseJava(f.text) : undefined;
    if (tree) trees.set(f.path, tree);
  }
  const project = trees.size ? new JavaProject(trees) : undefined;
  // Parsed Java files are analysed with comments blanked out, so commented-out code is neither a source nor a sink.
  const text = (f: TaintFile) => trees.get(f.path)?.text ?? f.text;
  const fns = sources.flatMap(f => trees.has(f.path) ? javaFunctions(f.path, trees.get(f.path)!) : functions(f));
  const summaries: Summaries = new Map();
  for (const fn of fns) summaries.set(fn.name, [...(summaries.get(fn.name) ?? []), fn.summary]);
  for (let round = 0; round < 6; round++) {
    let changed = false;
    for (const fn of fns) {
      const s = fn.summary;
      if (!s.source && analyse(fn.lines, fn.startLine, fn.path, new Map(), summaries, fn.skipHead, project).returned !== undefined) changed = s.source = true;
      fn.params.forEach((p, i) => {
        if (!p.name || (s.sinks.has(i) && s.markup.has(i))) return;
        const result = analyse(fn.lines, fn.startLine, fn.path, new Map([[p.name, fn.startLine]]), summaries, fn.skipHead, project);
        const hit = result.hits.find(h => !h.via.includes(fn.name));
        if (hit && !s.sinks.has(i)) { s.sinks.set(i, {kind: hit.kind, path: hit.path, line: hit.line, via: hit.via}); changed = true; }
        if (result.returned !== undefined && !s.returns.has(i)) { s.returns.add(i); changed = true; }
        if (result.markup !== undefined && !s.markup.has(i)) { s.markup.add(i); changed = true; }
      });
    }
    if (!changed) break;
  }
  const flows = new Map<string, TaintFlow>();
  const add = (path: string, hits: Hit[]) => {
    for (const h of hits) {
      const key = h.kind + "|" + h.path + ":" + h.line;
      const flow = {kind: h.kind, source: {path, line: h.origin}, sink: {path: h.path, line: h.line}, via: h.via};
      const known = flows.get(key);
      if (!known || flow.via.length > known.via.length) flows.set(key, flow);
    }
  };
  for (const fn of fns) {
    const entry = fn.params.filter(p => p.name && (p.annotated || fn.route));
    if (entry.length) add(fn.path, analyse(fn.lines, fn.startLine, fn.path, new Map(entry.map(p => [p.name, fn.startLine])), summaries, fn.skipHead, project).hits);
  }
  for (const file of sources) if (SOURCE.test(text(file))) add(file.path, analyse(text(file).split(/\r?\n/), 1, file.path, new Map(), summaries, false, project).hits);
  return [...flows.values()].sort((a, b) => a.sink.path.localeCompare(b.sink.path) || a.sink.line - b.sink.line);
}

const LABEL: Record<SinkKind, string> = {sql: "SQL injection", command: "Command injection", code: "Code injection", path: "Path traversal", ssrf: "Server-side request forgery",
  xss: "Cross-site scripting", ldap: "LDAP injection", xpath: "XPath injection", "trust-boundary": "Trust boundary violation"};
export function flowTitle(flow: TaintFlow): string {
  return LABEL[flow.kind] + ": request input reaches this sink" + (flow.via.length ? " through " + flow.via.join(" → ") : "");
}
export const flowSeverity = (flow: TaintFlow): "high" | "medium" => ["sql", "command", "code", "ldap", "xpath"].includes(flow.kind) ? "high" : "medium";
