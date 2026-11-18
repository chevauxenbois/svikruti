"use strict";
/**
 * svikruti-redact: strip personal data from text before it leaves the process.
 * Same detectors and output as the Python `svikruti.redact` module.
 *
 *   const { redact, redactMessages, installConsoleRedaction } = require("svikruti-redact");
 *   installConsoleRedaction();                         // console.log/info/warn/error/debug
 *   await openai.chat.completions.create({ model, messages: redactMessages(messages) });
 */
const crypto = require("crypto");

const D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
const digits = (v) => v.replace(/\D/g, "");
function verhoeff(n) { let c = 0; [...n].reverse().forEach((ch, i) => { c = D[c][P[i % 8][+ch]]; }); return c === 0; }
function luhn(n) { let t = 0; [...n].reverse().forEach((ch, i) => { let v = +ch; if (i % 2) { v *= 2; if (v > 9) v -= 9; } t += v; }); return t % 10 === 0; }
function iban(v) {
  const c = v.replace(/ /g, "").toUpperCase(); const r = c.slice(4) + c.slice(0, 4);
  let rem = 0; for (const ch of r) { const n = parseInt(ch, 36).toString(); for (const d of n) rem = (rem * 10 + +d) % 97; }
  return rem === 1;
}

const DETECTORS = [
  ["EMAIL", /(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])/g, null],
  ["IBAN", /(?<![A-Z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?(?![A-Z0-9])/g, iban],
  ["CARD", /(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])/g, (v) => { const d = digits(v); return d.length >= 13 && d.length <= 19 && luhn(d); }],
  ["AADHAAR", /(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)/g, (v) => verhoeff(digits(v))],
  ["PAN", /(?<![A-Z0-9])[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z](?![A-Z0-9])/g, null],
  ["IFSC", /(?<![A-Z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Z0-9])/g, null],
  ["UPI", /(?<![\w.+-])[A-Za-z0-9._-]{2,}@[A-Za-z]{2,}(?![\w.@-])/g, null],
  ["SSN", /(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)/g, null],
  ["PHONE", /(?<![\w+])(?:\+91[ -]?|0091[ -]?|0)?[6-9]\d{4}[ -]?\d{5}(?!\d)|(?<![\w+])\+(?:[1-9]\d{0,2})[ -]?(?:\(?\d{1,4}\)?[ -]?){2,4}\d{2,4}(?!\d)/g, (v) => { const n = digits(v).length; return n >= 10 && n <= 15; }],
  ["IP", /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])/g, (v) => !v.startsWith("0.") && !v.startsWith("127.") && v !== "255.255.255.255"],
];
const KINDS = DETECTORS.map(([k]) => k);

function find(text, kinds) {
  if (typeof text !== "string" || !text) return [];
  const wanted = new Set((kinds || KINDS).map((k) => k.toUpperCase()));
  const taken = [];
  for (const [kind, pattern, check] of DETECTORS) {
    if (!wanted.has(kind)) continue;
    for (const m of text.matchAll(pattern)) {
      const start = m.index, end = start + m[0].length;
      if (check && !check(m[0])) continue;
      if (taken.some((o) => start < o.end && o.start < end)) continue;
      if (kind === "IP" && /(?:version|ver|release|build|v)[\s:=]*$/i.test(text.slice(Math.max(0, start - 12), start))) continue;
      taken.push({ kind, start, end, value: m[0] });
    }
  }
  return taken.sort((a, b) => a.start - b.start);
}

function replacement(match, style, key) {
  const compact = match.value.replace(/[\s-]/g, "");
  if (style === "partial") return `[${match.kind} ...${compact.slice(-4)}]`;
  if (style === "hash") {
    const data = compact.toLowerCase();
    const h = key ? crypto.createHmac("sha256", key).update(data).digest("hex") : crypto.createHash("sha256").update(data).digest("hex");
    return `[${match.kind}:${h.slice(0, 8)}]`;
  }
  return `[${match.kind}]`;
}

function redact(text, options = {}) {
  if (typeof text !== "string" || !text) return text;
  const style = options.style || "label";
  if (!["label", "partial", "hash"].includes(style)) throw new Error("style must be 'label', 'partial' or 'hash'");
  const key = options.key || process.env.SVIKRUTI_REDACT_KEY || "";
  let out = "", cursor = 0;
  for (const m of find(text, options.kinds)) { out += text.slice(cursor, m.start) + replacement(m, style, key); cursor = m.end; }
  return out + text.slice(cursor);
}

function redactValue(value, options = {}, depth = 0) {
  if (depth > 20) return value;
  if (typeof value === "string") return redact(value, options);
  if (Array.isArray(value)) return value.map((v) => redactValue(v, options, depth + 1));
  if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    const out = {}; for (const [k, v] of Object.entries(value)) out[k] = redactValue(v, options, depth + 1); return out;
  }
  return value;
}

/** Chat messages (OpenAI, Anthropic, Gemini, Vercel AI SDK shapes) with text content redacted. Input is not modified. */
function redactMessages(messages, options = {}) {
  return messages.map((m) => {
    if (typeof m === "string") return redact(m, options);
    if (!m || typeof m !== "object") return m;
    const copy = { ...m };
    for (const field of ["content", "parts", "text"]) if (field in copy) copy[field] = redactValue(copy[field], options);
    return copy;
  });
}

const METHODS = ["log", "info", "warn", "error", "debug", "trace"];
let originals = null;
/** Redact everything written through console.* in this process. */
function installConsoleRedaction(options = {}) {
  if (originals) return;
  originals = {};
  const util = require("util");
  for (const name of METHODS) {
    const original = console[name];
    originals[name] = original;
    console[name] = (...args) => original.call(console, redact(util.format(...args), options));
  }
}
function uninstallConsoleRedaction() {
  if (!originals) return;
  for (const [name, fn] of Object.entries(originals)) console[name] = fn;
  originals = null;
}

/** For pino: `pino({ hooks: { logMethod: pinoLogMethod() } })`. */
function pinoLogMethod(options = {}) {
  return function (args, method) { return method.apply(this, args.map((a) => redactValue(a, options))); };
}

module.exports = { KINDS, find, redact, redactValue, redactMessages, installConsoleRedaction, uninstallConsoleRedaction, pinoLogMethod };
