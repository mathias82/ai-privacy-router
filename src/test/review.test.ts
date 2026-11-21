import { test } from "node:test";
import { strict as assert } from "node:assert";
import { validateReview, formatReview, reviewPrompt } from "../review";
const source = 'return Response.status(404).entity("{\\"error\\":\\"" + e.getTenantId() + "\\"}").build();';
function finding(title:string,evidence:string) { return {title,severity:"high",evidence,fix:"Use a JSON DTO",regressionTest:"Test tenant ID with a quote"}; }
test("rejects SQL injection claim without SQL sink", () => {
  const result = validateReview(JSON.stringify({findings:[finding("SQL Injection",source)]}),source);
  assert.equal(result.findings.length,0);assert.equal(result.rejected,1);
});
test("keeps SQL injection claim when the query string is SELECT *", () => {
  const js = `db.query("SELECT * FROM books WHERE author = '" + author + "'", cb);`;
  const result = validateReview(JSON.stringify({findings:[finding("SQL Injection",js)]}),js);
  assert.equal(result.findings.length,1);
});
test("rejects fabricated evidence", () => {
  const result = validateReview(JSON.stringify({findings:[finding("JSON escaping","this code does not exist")]}),source);
  assert.equal(result.findings.length,0);
});
test("keeps source-grounded finding as potential only", () => {
  const result = validateReview(JSON.stringify({findings:[finding("Unsafe JSON string concatenation",source)]}),source);
  assert.equal(result.findings.length,1);assert.equal(result.findings[0].status,"potential");
  assert.match(formatReview(result),/not confirmed/);
});
test("handles malformed JSON safely",()=>assert.match(formatReview(validateReview("invalid",source)),/not verified/));
test("review prompt requires source evidence",()=>assert.match(reviewPrompt("review",source),/exact verbatim substring/));

test("review prompt covers language-specific correctness",()=>{
 const files=[{path:"main.go",text:"func f() error { return nil }"},{path:"worker.rs",text:"fn main() {}"},{path:"handler.py",text:"def run(x): return x"}];
 const prompt=reviewPrompt("review correctness",files);
 for(const term of ["Java/Kotlin","JavaScript/TypeScript","Python","Go ignored errors","Rust Result/Option","C/C++","C#","SQL joins","shell quoting"])assert.ok(prompt.includes(term),term);
 for(const file of files)assert.ok(prompt.includes(file.path));
 assert.match(prompt,/A clean review is allowed/);
});
import { asksForExplanation } from "../review";
test("explanation requests are not treated as bug reviews", () => {
  assert.equal(asksForExplanation("explain me the code"), true);
  assert.equal(asksForExplanation("τι κάνει αυτός ο κώδικας;"), true);
  assert.equal(asksForExplanation("explain and find bugs"), false);
  assert.equal(asksForExplanation("can you check code?"), false);
});
test("review location is shown relative to the workspace, not as a file URI", () => {
  const js = `db.query("SELECT * FROM books WHERE author = '" + author + "'", cb);`;
  const result = validateReview(JSON.stringify({findings:[{...finding("SQL Injection",js), path:"file:///home/dev/shop/src/books.js"}]}),[{path:"file:///home/dev/shop/src/books.js",text:js}]);
  const text = formatReview(result, p => p.replace("file:///home/dev/shop/", ""));
  assert.match(text, /\*\*Location:\*\* .src\/books\.js:1./);
  assert.doesNotMatch(text, /file:/);
});
