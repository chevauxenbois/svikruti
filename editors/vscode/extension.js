"use strict";
const vscode = require("vscode");
const cp = require("child_process");
const fs = require("fs");
const path = require("path");
const core = require("./core");

const MANIFESTS = ["privacy.yaml", "privacy.yml", "privacy.json"];
let diagnostics, status, output, running = null, timer = null, lastReport = null;

function config() { return vscode.workspace.getConfiguration("svikruti"); }

function workspaceRoot() {
  const folders = vscode.workspace.workspaceFolders || [];
  for (const folder of folders) if (MANIFESTS.some((name) => fs.existsSync(path.join(folder.uri.fsPath, name)))) return folder.uri.fsPath;
  return folders.length ? folders[0].uri.fsPath : null;
}

function toSeverity(level, excepted) {
  if (excepted) return vscode.DiagnosticSeverity.Hint;
  if (level === "CRITICAL" || level === "HIGH") return vscode.DiagnosticSeverity.Error;
  if (level === "MEDIUM") return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

function runCheck(context, reason) {
  const root = workspaceRoot();
  if (!root) return;
  if (!MANIFESTS.some((name) => fs.existsSync(path.join(root, name)))) {
    status.text = "Svikruti: no privacy.yaml";
    status.command = "svikruti.init";
    status.show();
    return;
  }
  if (running) running.kill();
  const outDir = path.join(context.globalStorageUri.fsPath, Buffer.from(root).toString("hex").slice(-40));
  fs.mkdirSync(outDir, { recursive: true });
  const args = core.checkArgs(root, outDir, config().get("frameworks"));
  status.text = "$(sync~spin) Svikruti: checking";
  status.show();
  output.appendLine(`[${new Date().toISOString()}] ${reason}: ${config().get("command")} ${args.join(" ")}`);
  const child = cp.spawn(config().get("command"), args, { cwd: root });
  running = child;
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.on("error", (error) => {
    running = null;
    status.text = "$(warning) Svikruti: CLI not found";
    vscode.window.showErrorMessage(`Svikruti CLI not found (${error.message}). Run \`pip install svikruti\` or set svikruti.command.`);
  });
  child.on("close", (code) => {
    if (running !== child) return; // superseded by a newer run
    running = null;
    if (code !== 0 && code !== 3) {
      status.text = "$(warning) Svikruti: check failed";
      output.appendLine(stderr);
      return;
    }
    const reportPath = path.join(outDir, "privacy-check.json");
    let check;
    try { check = JSON.parse(fs.readFileSync(reportPath, "utf8")); } catch (error) { output.appendLine(String(error)); return; }
    lastReport = path.join(outDir, "privacy-check.html");
    const manifestPath = MANIFESTS.map((name) => path.join(root, name)).find((p) => fs.existsSync(p));
    const byFile = core.toDiagnostics(check, root, {
      minimumSeverity: config().get("minimumSeverity"),
      showExcepted: config().get("showExcepted"),
      manifestText: manifestPath ? fs.readFileSync(manifestPath, "utf8") : "",
    });
    diagnostics.clear();
    for (const [file, items] of Object.entries(byFile)) {
      diagnostics.set(vscode.Uri.file(file), items.map((item) => {
        const range = new vscode.Range(item.line, 0, item.line, Number.MAX_SAFE_INTEGER);
        const diagnostic = new vscode.Diagnostic(range, item.message, toSeverity(item.severity, item.excepted));
        diagnostic.source = "svikruti";
        diagnostic.code = item.rule;
        return diagnostic;
      }));
    }
    status.text = core.statusText(check);
    status.command = "svikruti.openReport";
    status.tooltip = "Open the privacy check report";
    for (const warning of stderr.split(/\r?\n/).filter((line) => line.startsWith("warning:"))) output.appendLine(warning);
  });
}

class SuppressionActions {
  provideCodeActions(document, range, context) {
    return context.diagnostics.filter((d) => d.source === "svikruti" && !/^privacy\.(ya?ml|json)$/.test(path.basename(document.fileName))).map((d) => {
      const line = document.lineAt(d.range.start.line);
      const indent = line.text.slice(0, line.firstNonWhitespaceCharacterIndex);
      const action = new vscode.CodeAction(`Suppress ${d.code} on this line (svikruti-ignore)`, vscode.CodeActionKind.QuickFix);
      action.edit = new vscode.WorkspaceEdit();
      action.edit.insert(document.uri, new vscode.Position(d.range.start.line, 0), core.suppressionComment(document.fileName, d.code, indent) + "\n");
      action.diagnostics = [d];
      return action;
    });
  }
}

function activate(context) {
  diagnostics = vscode.languages.createDiagnosticCollection("svikruti");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  output = vscode.window.createOutputChannel("Svikruti");
  context.subscriptions.push(diagnostics, status, output);
  context.subscriptions.push(
    vscode.commands.registerCommand("svikruti.check", () => runCheck(context, "manual")),
    vscode.commands.registerCommand("svikruti.clear", () => { diagnostics.clear(); status.text = "Svikruti"; }),
    vscode.commands.registerCommand("svikruti.openReport", () => {
      if (lastReport && fs.existsSync(lastReport)) vscode.env.openExternal(vscode.Uri.file(lastReport));
      else vscode.window.showInformationMessage("Run Svikruti: Run privacy check first.");
    }),
    vscode.commands.registerCommand("svikruti.init", () => {
      const root = workspaceRoot();
      if (!root) return;
      const terminal = vscode.window.createTerminal("Svikruti");
      terminal.show();
      terminal.sendText(`${config().get("command")} init --repo "${root}"`);
    }),
    vscode.languages.registerCodeActionsProvider({ scheme: "file" }, new SuppressionActions(), { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
    vscode.workspace.onDidSaveTextDocument(() => {
      if (!config().get("runOnSave")) return;
      clearTimeout(timer);
      timer = setTimeout(() => runCheck(context, "save"), 1200);
    }),
  );
  runCheck(context, "open");
}

function deactivate() { if (running) running.kill(); }

module.exports = { activate, deactivate };
