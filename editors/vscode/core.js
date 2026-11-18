"use strict";
/**
 * Pure logic for the extension: no `vscode` import, so it is unit-tested with node --test.
 */
const path = require("path");

const SEVERITY_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

/** CLI arguments for one check run. */
function checkArgs(root, outDir, frameworks) {
  const args = ["check", "--repo", root, "--out-dir", outDir, "--fail-on", "none"];
  for (const id of frameworks || []) args.push("--framework", id);
  return args;
}

/** "services/payments/refund.js:9" -> { file, line } (line is 0-based; missing line -> 0). */
function parseRef(ref) {
  const match = /^(.*?):(\d+)(?::.*)?$/.exec(String(ref));
  if (!match) return { file: String(ref), line: 0 };
  return { file: match[1], line: Math.max(0, parseInt(match[2], 10) - 1) };
}

/** Line of `- id: <activity>` (or a processor id) in the manifest, so record-level findings land somewhere useful. */
function manifestLine(manifestText, finding) {
  const lines = (manifestText || "").split(/\r?\n/);
  for (const key of [finding.activity, finding.processor].filter(Boolean)) {
    const index = lines.findIndex((line) => new RegExp(`^\\s*-?\\s*id:\\s*["']?${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["']?\\s*$`).test(line));
    if (index >= 0) return index;
  }
  return 0;
}

/**
 * privacy-check.json -> { "<abs file>": [ { line, severity, rule, message, excepted } ] }.
 * A finding with several refs appears on each; record-level findings go on privacy.yaml.
 */
function toDiagnostics(check, root, options = {}) {
  const minimum = SEVERITY_RANK[(options.minimumSeverity || "LOW").toUpperCase()] || 1;
  const manifestRel = check.manifest ? path.relative(root, path.resolve(root, check.manifest)) || "privacy.yaml" : "privacy.yaml";
  const out = {};
  for (const finding of check.findings || []) {
    const excepted = finding.status && finding.status !== "open";
    if (excepted && !options.showExcepted) continue;
    if ((SEVERITY_RANK[finding.severity] || 1) < minimum && !excepted) continue;
    const message = `${finding.rule} ${finding.title}: ${finding.detail}` + (finding.fix ? `\nFix: ${finding.fix}` : "") + (excepted && finding.exception_reason ? `\nException: ${finding.exception_reason}` : "");
    const refs = (finding.refs || []).filter((ref) => !/^privacy\.(ya?ml|json)$/.test(ref));
    const targets = refs.length ? refs.slice(0, 8).map(parseRef) : [{ file: manifestRel, line: manifestLine(options.manifestText, finding) }];
    for (const target of targets) {
      const file = path.resolve(root, target.file);
      (out[file] = out[file] || []).push({ line: target.line, severity: finding.severity, rule: finding.rule, message, excepted, fingerprint: finding.fingerprint });
    }
  }
  return out;
}

const COMMENT = { ".py": "#", ".rb": "#", ".yaml": "#", ".yml": "#", ".sh": "#", ".pl": "#", ".r": "#" };
/** Inline suppression comment for a line in this language, as `svikruti check` expects it. */
function suppressionComment(fileName, rule, indent) {
  const prefix = COMMENT[path.extname(fileName).toLowerCase()] || "//";
  return `${indent}${prefix} svikruti-ignore[${rule}]: <reason, at least 10 characters>`;
}

/** One-line status text. */
function statusText(check) {
  const summary = (check && check.summary) || {};
  const open = summary.open_findings || 0;
  const bySeverity = summary.open_by_severity || {};
  const worst = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].find((level) => bySeverity[level]);
  return open ? `Svikruti: ${open} finding${open === 1 ? "" : "s"}${worst ? ` (${bySeverity[worst]} ${worst.toLowerCase()})` : ""}` : "Svikruti: clean";
}

module.exports = { checkArgs, parseRef, manifestLine, toDiagnostics, suppressionComment, statusText, SEVERITY_RANK };
