const test = require("node:test");
const assert = require("node:assert");
const { redact, redactMessages, find, installConsoleRedaction, uninstallConsoleRedaction } = require("..");

// Shared with the Python test suite: both implementations must agree.
const CASES = require("./cases.json");

test("matches the Python implementation on shared cases", () => {
  for (const [input, expected] of CASES) assert.strictEqual(redact(input), expected, input);
});

test("styles", () => {
  assert.strictEqual(redact("call 9876543210", { style: "partial" }), "call [PHONE ...3210]");
  assert.match(redact("a@b.com", { style: "hash", key: "k" }), /^\[EMAIL:[0-9a-f]{8}\]$/);
});

test("messages keep their shape", () => {
  const input = [{ role: "user", content: [{ type: "text", text: "PAN ABCPE1234F" }, { type: "image_url", image_url: { url: "http://x" } }] }];
  const out = redactMessages(input);
  assert.strictEqual(out[0].content[0].text, "PAN [PAN]");
  assert.strictEqual(out[0].content[1].image_url.url, "http://x");
  assert.strictEqual(input[0].content[0].text, "PAN ABCPE1234F");
});

test("console redaction", () => {
  const seen = [];
  const original = console.log;
  console.log = (msg) => seen.push(msg);
  installConsoleRedaction();
  console.log("refund for %s", "a@b.com");
  uninstallConsoleRedaction();
  console.log = original;
  assert.deepStrictEqual(seen, ["refund for [EMAIL]"]);
  assert.strictEqual(find("nothing here").length, 0);
});
