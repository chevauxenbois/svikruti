const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const core = require("../core");

const ROOT = path.resolve("/repo");
const CHECK = {
  manifest: "privacy.yaml",
  summary: { open_findings: 2, open_by_severity: { HIGH: 1, MEDIUM: 1 } },
  findings: [
    { rule: "P001", title: "Personal data written to logs", detail: "Contact data is written to logs", fix: "Mask it", severity: "HIGH", status: "open", refs: ["services/payments/refund.js:8"], activity: "repayments" },
    { rule: "D007", title: "Processor record is incomplete", detail: "no contract", severity: "MEDIUM", status: "open", refs: [], processor: "msg91" },
    { rule: "P006", title: "AI", detail: "x", severity: "HIGH", status: "excepted", exception_reason: "approved", refs: ["a.py:3"] },
  ],
};

test("findings land on their files and record-level findings on privacy.yaml", () => {
  const manifestText = "processors:\n  - id: razorpay\n  - id: msg91\n";
  const out = core.toDiagnostics(CHECK, ROOT, { manifestText });
  const refund = out[path.join(ROOT, "services/payments/refund.js")];
  assert.strictEqual(refund[0].line, 7);
  assert.match(refund[0].message, /^P001 Personal data written to logs: .*\nFix: Mask it$/);
  assert.strictEqual(out[path.join(ROOT, "privacy.yaml")][0].line, 2);
  assert.strictEqual(out[path.join(ROOT, "a.py")], undefined);
});

test("severity floor and excepted findings", () => {
  assert.strictEqual(core.toDiagnostics(CHECK, ROOT, { minimumSeverity: "HIGH" })[path.join(ROOT, "privacy.yaml")], undefined);
  const shown = core.toDiagnostics(CHECK, ROOT, { showExcepted: true })[path.join(ROOT, "a.py")];
  assert.strictEqual(shown[0].excepted, true);
  assert.match(shown[0].message, /Exception: approved/);
});

test("arguments, refs, comments and status", () => {
  assert.deepStrictEqual(core.checkArgs("/r", "/o", ["rbi", "soc2"]), ["check", "--repo", "/r", "--out-dir", "/o", "--fail-on", "none", "--framework", "rbi", "--framework", "soc2"]);
  assert.deepStrictEqual(core.parseRef("a/b.py:12:semantic.x"), { file: "a/b.py", line: 11 });
  assert.deepStrictEqual(core.parseRef("privacy.yaml"), { file: "privacy.yaml", line: 0 });
  assert.strictEqual(core.suppressionComment("x.py", "P001", "    "), "    # svikruti-ignore[P001]: <reason, at least 10 characters>");
  assert.strictEqual(core.suppressionComment("x.ts", "D003", ""), "// svikruti-ignore[D003]: <reason, at least 10 characters>");
  assert.strictEqual(core.statusText(CHECK), "Svikruti: 2 findings (1 high)");
  assert.strictEqual(core.statusText({ summary: { open_findings: 0 } }), "Svikruti: clean");
});
