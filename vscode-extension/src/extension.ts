/**
 * PQC Scanner — VS Code Extension
 *
 * Detects quantum-vulnerable cryptography in real-time.
 * Shows inline diagnostics and provides quick-fix code actions.
 *
 * Requires pqc-scanner Python package installed:
 *   pip install pqc-scanner
 */

import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';

const DIAGNOSTIC_SOURCE = 'pqc-scanner';
const diagnosticCollection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_SOURCE);

// Severity mapping from scanner to VS Code
const severityMap: Record<string, vscode.DiagnosticSeverity> = {
    'CRITICAL': vscode.DiagnosticSeverity.Error,
    'HIGH': vscode.DiagnosticSeverity.Error,
    'MEDIUM': vscode.DiagnosticSeverity.Warning,
    'LOW': vscode.DiagnosticSeverity.Information,
    'INFO': vscode.DiagnosticSeverity.Hint,
};

interface ScanFinding {
    severity: string;
    algorithm: string;
    file: string;
    line: number;
    code_snippet: string;
    description: string;
    recommendation: string;
    pqc_replacement: string;
}

interface ScanResult {
    findings: ScanFinding[];
    risk_score: number;
    files_scanned: number;
}

export function activate(context: vscode.ExtensionContext) {
    console.log('PQC Scanner extension activated');

    // Status bar item showing risk score
    const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBar.command = 'pqc-scanner.scanFile';
    statusBar.text = '$(shield) PQC';
    statusBar.tooltip = 'Click to scan for quantum-vulnerable crypto';
    statusBar.show();
    context.subscriptions.push(statusBar);

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('pqc-scanner.scanFile', () => scanCurrentFile(statusBar)),
        vscode.commands.registerCommand('pqc-scanner.scanWorkspace', () => scanWorkspace(statusBar)),
        vscode.commands.registerCommand('pqc-scanner.showDashboard', () => showDashboard(context)),
    );

    // Scan on save (if enabled)
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((doc) => {
            const config = vscode.workspace.getConfiguration('pqc-scanner');
            if (config.get<boolean>('scanOnSave', true)) {
                scanDocument(doc, statusBar);
            }
        })
    );

    // Register code action provider for quick fixes
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            ['python', 'java', 'go', 'javascript', 'typescript', 'rust', 'c', 'cpp'],
            new PQCCodeActionProvider(),
            { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
        )
    );

    // Clean up diagnostics when files are closed
    context.subscriptions.push(
        vscode.workspace.onDidCloseTextDocument((doc) => {
            diagnosticCollection.delete(doc.uri);
        })
    );
}

async function scanCurrentFile(statusBar: vscode.StatusBarItem) {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active file to scan');
        return;
    }
    await scanDocument(editor.document, statusBar);
}

async function scanDocument(doc: vscode.TextDocument, statusBar: vscode.StatusBarItem) {
    const supportedLangs = ['python', 'java', 'go', 'javascript', 'typescript', 'rust', 'c', 'cpp'];
    if (!supportedLangs.includes(doc.languageId)) {
        return;
    }

    statusBar.text = '$(sync~spin) PQC scanning...';

    try {
        const result = await runScanner(doc.uri.fsPath);
        const diagnostics = resultToDiagnostics(result, doc);
        diagnosticCollection.set(doc.uri, diagnostics);

        const findingCount = result.findings.length;
        if (findingCount === 0) {
            statusBar.text = '$(shield) PQC ✓';
            statusBar.tooltip = 'No quantum-vulnerable crypto detected';
        } else {
            const critical = result.findings.filter(f => f.severity === 'CRITICAL').length;
            statusBar.text = `$(shield) PQC: ${findingCount} findings`;
            if (critical > 0) {
                statusBar.text += ` (${critical} critical)`;
            }
            statusBar.tooltip = `Risk Score: ${result.risk_score}/100`;
        }
    } catch (err: any) {
        statusBar.text = '$(shield) PQC';
        console.error('PQC Scanner error:', err.message);
    }
}

async function scanWorkspace(statusBar: vscode.StatusBarItem) {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders) {
        vscode.window.showWarningMessage('No workspace open');
        return;
    }

    statusBar.text = '$(sync~spin) PQC scanning workspace...';

    try {
        const result = await runScanner(folders[0].uri.fsPath);

        // Group findings by file
        const byFile = new Map<string, ScanFinding[]>();
        for (const f of result.findings) {
            const key = f.file;
            if (!byFile.has(key)) { byFile.set(key, []); }
            byFile.get(key)!.push(f);
        }

        // Set diagnostics per file
        diagnosticCollection.clear();
        for (const [filePath, findings] of byFile) {
            const uri = vscode.Uri.file(filePath);
            try {
                const doc = await vscode.workspace.openTextDocument(uri);
                const diags = resultToDiagnostics({ findings, risk_score: 0, files_scanned: 0 }, doc);
                diagnosticCollection.set(uri, diags);
            } catch {
                // File might not be openable
            }
        }

        const total = result.findings.length;
        statusBar.text = `$(shield) PQC: ${total} findings (${byFile.size} files)`;
        vscode.window.showInformationMessage(
            `PQC Scanner: ${total} quantum-vulnerable findings in ${result.files_scanned} files. Risk: ${result.risk_score}/100`
        );
    } catch (err: any) {
        statusBar.text = '$(shield) PQC';
        vscode.window.showErrorMessage(`PQC Scanner error: ${err.message}`);
    }
}

function runScanner(filePath: string): Promise<ScanResult> {
    return new Promise((resolve, reject) => {
        const config = vscode.workspace.getConfiguration('pqc-scanner');
        const pythonPath = config.get<string>('pythonPath', 'python');
        const severity = config.get<string>('severity', 'low');

        // Run pqc-scanner in JSON mode
        const scannerPath = path.join(__dirname, '..', '..', 'phases', 'phase6_scanner', 'pqc_scanner.py');
        const args = [scannerPath, 'scan', filePath, '--format', 'json', '--severity', severity];

        cp.execFile(pythonPath, args, { maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
            if (err && err.code !== 1 && err.code !== 2) {
                // Exit code 1 = findings, 2 = critical findings — both are OK
                reject(new Error(`Scanner failed: ${stderr || err.message}`));
                return;
            }

            try {
                // stdout might have info messages before JSON — find the JSON part
                const jsonStart = stdout.indexOf('{');
                if (jsonStart === -1) {
                    resolve({ findings: [], risk_score: 0, files_scanned: 0 });
                    return;
                }
                const data = JSON.parse(stdout.slice(jsonStart));
                resolve({
                    findings: data.findings || [],
                    risk_score: data.risk_score || 0,
                    files_scanned: data.files_scanned || 0,
                });
            } catch (parseErr: any) {
                reject(new Error(`Failed to parse scanner output: ${parseErr.message}`));
            }
        });
    });
}

function resultToDiagnostics(result: ScanResult, doc: vscode.TextDocument): vscode.Diagnostic[] {
    const diagnostics: vscode.Diagnostic[] = [];

    for (const finding of result.findings) {
        // Normalize file path comparison
        const findingFile = path.normalize(finding.file);
        const docFile = path.normalize(doc.uri.fsPath);
        if (findingFile !== docFile && !findingFile.endsWith(path.basename(docFile))) {
            continue;
        }

        const line = Math.max(0, finding.line - 1);
        const lineText = line < doc.lineCount ? doc.lineAt(line).text : '';
        const range = new vscode.Range(line, 0, line, lineText.length);

        const severity = severityMap[finding.severity] ?? vscode.DiagnosticSeverity.Warning;

        const diag = new vscode.Diagnostic(
            range,
            `${finding.algorithm}: ${finding.description}`,
            severity
        );
        diag.source = DIAGNOSTIC_SOURCE;
        diag.code = finding.algorithm;

        // Add related information with fix suggestion
        diag.relatedInformation = [
            new vscode.DiagnosticRelatedInformation(
                new vscode.Location(doc.uri, range),
                `Fix: ${finding.recommendation}. Use: ${finding.pqc_replacement}`
            ),
        ];

        diagnostics.push(diag);
    }

    return diagnostics;
}

async function showDashboard(context: vscode.ExtensionContext) {
    const panel = vscode.window.createWebviewPanel(
        'pqcDashboard',
        'PQC Scanner Dashboard',
        vscode.ViewColumn.One,
        { enableScripts: true }
    );

    const folders = vscode.workspace.workspaceFolders;
    if (!folders) {
        panel.webview.html = '<h1>No workspace open</h1>';
        return;
    }

    try {
        const config = vscode.workspace.getConfiguration('pqc-scanner');
        const pythonPath = config.get<string>('pythonPath', 'python');
        const scannerPath = path.join(__dirname, '..', '..', 'phases', 'phase6_scanner', 'pqc_scanner.py');

        // Generate dashboard HTML
        const result = cp.execFileSync(pythonPath, [
            scannerPath, 'scan', folders[0].uri.fsPath,
            '--format', 'dashboard', '-o', '-'
        ], { maxBuffer: 50 * 1024 * 1024 }).toString();

        panel.webview.html = result;
    } catch (err: any) {
        panel.webview.html = `<h1>Error generating dashboard</h1><pre>${err.message}</pre>`;
    }
}

/**
 * Code Action Provider — Quick Fixes for PQC findings
 */
class PQCCodeActionProvider implements vscode.CodeActionProvider {
    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        for (const diag of context.diagnostics) {
            if (diag.source !== DIAGNOSTIC_SOURCE) { continue; }

            const algo = diag.code as string;
            const lineText = document.lineAt(diag.range.start.line).text;

            // Tier 1 — Deterministic fixes
            const fixes = getTier1Fixes(algo, lineText);
            for (const fix of fixes) {
                const action = new vscode.CodeAction(
                    `PQC Fix: ${fix.label}`,
                    vscode.CodeActionKind.QuickFix
                );
                action.diagnostics = [diag];
                action.isPreferred = true;

                const edit = new vscode.WorkspaceEdit();
                const fullRange = document.lineAt(diag.range.start.line).range;
                edit.replace(document.uri, fullRange, fix.replacement);
                action.edit = edit;

                actions.push(action);
            }

            // Tier 2 — Template suggestion (adds TODO comment above)
            if (['RSA', 'ECDSA', 'ECDH'].includes(algo)) {
                const action = new vscode.CodeAction(
                    `PQC: Add migration TODO for ${algo}`,
                    vscode.CodeActionKind.QuickFix
                );
                action.diagnostics = [diag];

                const edit = new vscode.WorkspaceEdit();
                const pos = new vscode.Position(diag.range.start.line, 0);
                const indent = lineText.match(/^\s*/)?.[0] || '';
                edit.insert(document.uri, pos,
                    `${indent}# TODO(pqc-migration): Replace ${algo} with PQC equivalent (ML-KEM/ML-DSA)\n`
                );
                action.edit = edit;

                actions.push(action);
            }
        }

        return actions;
    }
}

interface QuickFix {
    label: string;
    replacement: string;
}

function getTier1Fixes(algo: string, lineText: string): QuickFix[] {
    const fixes: QuickFix[] = [];

    if (algo === 'MD5') {
        if (lineText.includes('hashlib.md5')) {
            fixes.push({
                label: 'Replace MD5 with SHA-256',
                replacement: lineText.replace(/hashlib\.md5/g, 'hashlib.sha256'),
            });
        }
        if (lineText.includes("hashlib.new('md5')") || lineText.includes('hashlib.new("md5")')) {
            fixes.push({
                label: 'Replace MD5 with SHA-256',
                replacement: lineText.replace(/hashlib\.new\(['"]md5['"]\)/g, "hashlib.new('sha256')"),
            });
        }
    }

    if (algo === 'SHA-1') {
        if (lineText.includes('hashlib.sha1')) {
            fixes.push({
                label: 'Replace SHA-1 with SHA-256',
                replacement: lineText.replace(/hashlib\.sha1/g, 'hashlib.sha256'),
            });
        }
    }

    if (algo === '3DES') {
        if (lineText.includes('DES.new') || lineText.includes('DES3.new')) {
            fixes.push({
                label: 'Replace DES/3DES with AES',
                replacement: lineText.replace(/DES3?\.new/g, 'AES.new'),
            });
        }
    }

    return fixes;
}

export function deactivate() {
    diagnosticCollection.dispose();
}
