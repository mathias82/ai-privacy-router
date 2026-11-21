import { test } from "node:test";
import { strict as assert } from "node:assert";
import { initJavaParser, taintFlows, TaintFile } from "../taint";

const servlet = (body: string[]): TaintFile => ({path: "web/Entry.java", text: [
  "class Entry {",
  "  void doGet(HttpServletRequest request) throws Exception {",
  "    String id = request.getParameter(\"id\");",
  ...body.map(l => "    " + l),
  "  }",
  "}"].join("\n")});
const flows = (files: TaintFile[]) => taintFlows(files).map(f => [f.kind, f.sink.path, f.sink.line, f.via.join(">")]);

test("the Java parser loads from the bundled vendor folder", async () => {
  assert.equal(await initJavaParser(), true);
});

test("a typed receiver resolves the call to its own class, even when many classes share the method name", async () => {
  await initJavaParser();
  const quiet = [1, 2, 3].map(n => ({path: "jobs/Job" + n + ".java", text: "class Job" + n + " {\n  void execute(String s) {\n    System.out.println(s);\n  }\n}"}));
  const repo = {path: "data/Repo.java", text: "class Repo {\n  private java.sql.Statement st;\n  void execute(String s) throws Exception {\n    st.executeQuery(\"SELECT * FROM t WHERE id=\" + s);\n  }\n}"};
  assert.deepEqual(flows([servlet(["Job1 job = new Job1();", "job.execute(id);", "ExecutorService pool = null;", "pool.execute(id);"]), repo, ...quiet]), []);
  assert.deepEqual(flows([servlet(["Repo repo = new Repo();", "repo.execute(id);"]), repo, ...quiet]), [["sql", "data/Repo.java", 4, "execute"]]);
  assert.deepEqual(flows([servlet(["new Repo().execute(id);"]), repo, ...quiet]), [["sql", "data/Repo.java", 4, "execute"]]);
});

test("overloads are matched by argument count", async () => {
  await initJavaParser();
  const store = {path: "data/Store.java", text: [
    "class Store {",
    "  Connection c;",
    "  void save(String s) {",
    "    System.out.println(s);",
    "  }",
    "  void save(String table, String s) throws Exception {",
    "    c.createStatement().execute(\"INSERT INTO \" + table + \" VALUES(\" + s + \")\");",
    "  }",
    "}"].join("\n")};
  assert.deepEqual(flows([servlet(["Store store = new Store();", "store.save(id);"]), store]), []);
  assert.deepEqual(flows([servlet(["Store store = new Store();", "store.save(\"t\", id);"]), store]), [["sql", "data/Store.java", 7, "save"]]);
});

test("annotated parameters are sources, plain parameters and same-named sink methods are not", async () => {
  await initJavaParser();
  const controller = {path: "web/Api.java", text: [
    "class Api {",
    "  private JdbcTemplate jdbc;",
    "  @GetMapping(\"/find\")",
    "  public List<Map<String, Object>> find(",
    "      @RequestParam(value = \"name\", required = false) String name,",
    "      String other) {",
    "    jdbc.queryForList(\"SELECT * FROM t WHERE a='\" + other + \"'\");",
    "    return jdbc.queryForList(\"SELECT * FROM t WHERE n='\" + name + \"'\");",
    "  }",
    "  public int query(String sql) {",
    "    return sql.length();",
    "  }",
    "}"].join("\n")};
  assert.deepEqual(flows([controller]), [["sql", "web/Api.java", 8, ""]]);
});

test("code in comments and text blocks is ignored", async () => {
  await initJavaParser();
  const file = servlet([
    "/* Statement st = null;",
    "   st.executeQuery(\"SELECT \" + id); */",
    "// Runtime.getRuntime().exec(id);",
    "String doc = \"\"\"",
    "    st.executeQuery(request.getParameter(\"x\"));",
    "    \"\"\";",
    "System.out.println(doc);"]);
  assert.deepEqual(flows([file]), []);
});

test("without the parser the line-based engine still runs", async () => {
  assert.equal(await initJavaParser("/nonexistent-hushavyr-vendor"), false);
  const file = servlet(["Statement st = null;", "st.executeQuery(\"SELECT * FROM t WHERE id=\" + id);"]);
  assert.deepEqual(flows([file]), [["sql", "web/Entry.java", 5, ""]]);
  // The line-based engine cannot tell this executor from a database handle.
  assert.equal(flows([servlet(["ExecutorService pool = null;", "pool.execute(id);"])]).length, 1);
  assert.equal(await initJavaParser(), true);
  assert.deepEqual(flows([servlet(["ExecutorService pool = null;", "pool.execute(id);"])]), []);
});
