import * as crypto from 'crypto';
import * as vscode from 'vscode';
import { ParsedCertificateArtifact, ParsedCertificateDetails, parseCertificateInputFromFile } from '../certificates/certificateUtils';

/**
 * Read-only custom editor that renders certificate files (PEM/DER/CRT/CER/...) as a formatted detail
 * view instead of raw bytes/base64. Registered with `priority: "option"` so text editing remains the
 * default and users can "Reopen Editor With… → Certificate Viewer".
 */
export class CertificateEditorProvider implements vscode.CustomReadonlyEditorProvider {
    public static readonly viewType = 'certificateUtil.certificateViewer';

    public static register(context: vscode.ExtensionContext): vscode.Disposable {
        return vscode.window.registerCustomEditorProvider(CertificateEditorProvider.viewType, new CertificateEditorProvider(), {
            webviewOptions: { retainContextWhenHidden: true },
            supportsMultipleEditorsPerDocument: true,
        });
    }

    public openCustomDocument(uri: vscode.Uri): vscode.CustomDocument {
        return { uri, dispose: () => undefined };
    }

    public resolveCustomEditor(document: vscode.CustomDocument, webviewPanel: vscode.WebviewPanel): void {
        webviewPanel.webview.options = { enableScripts: false };
        try {
            const artifact = parseCertificateInputFromFile(document.uri.fsPath);
            webviewPanel.webview.html = this.renderArtifact(artifact);
        } catch (error) {
            webviewPanel.webview.html = this.renderError(error instanceof Error ? error.message : String(error));
        }
    }

    private renderArtifact(artifact: ParsedCertificateArtifact): string {
        if (!artifact.certificates.length) {
            return this.renderError(
                `No X.509 certificate could be parsed from this ${artifact.encoding} file. It may be a key, CSR, or an encrypted keystore.`
            );
        }
        const cards = artifact.certificates.map((certificate, index) => this.renderCertificate(certificate, index)).join('');
        const warnings = artifact.warnings.length
            ? `<div class="warnings"><strong>Warnings</strong><ul>${artifact.warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join('')}</ul></div>`
            : '';
        return this.htmlShell(`${warnings}${cards}`);
    }

    private renderCertificate(certificate: ParsedCertificateDetails, index: number): string {
        const rows: Array<[string, string]> = [
            ['Subject', certificate.subject],
            ['Issuer', certificate.issuer],
            ['Valid From', certificate.validFrom],
            ['Valid To', certificate.validTo],
            ['Serial Number', certificate.serialNumber],
            ['Type', certificate.type],
            ['Public Key', certificate.algorithm],
            ['Signature Algorithm', certificate.signatureAlgorithm],
            ['SANs', certificate.subjectAltNames.join(', ') || 'None'],
            ['Self-Signed', String(certificate.isSelfSigned)],
            ['CA', String(certificate.isCertificateAuthority)],
            ['SHA-256', certificate.fingerprint256],
        ];
        const body = rows
            .map(([key, value]) => `<div class="k">${escapeHtml(key)}</div><div class="v">${escapeHtml(value)}</div>`)
            .join('');
        return `<section class="card"><h2>Certificate ${index + 1}: ${escapeHtml(certificate.subjectCommonName || 'Unknown')}</h2><div class="grid">${body}</div></section>`;
    }

    private renderError(message: string): string {
        return this.htmlShell(`<div class="error">${escapeHtml(message)}</div>`);
    }

    private htmlShell(content: string): string {
        const nonce = crypto.randomBytes(16).toString('base64url');
        const csp = `default-src 'none'; style-src 'nonce-${nonce}';`;
        return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<style nonce="${nonce}">
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 16px; }
    h2 { font-size: 1.05rem; margin: 0 0 8px; }
    .card { border: 1px solid var(--vscode-panel-border); border-radius: 6px; padding: 12px 16px; margin-bottom: 14px; }
    .grid { display: grid; grid-template-columns: max-content 1fr; gap: 4px 14px; }
    .k { font-weight: 600; color: var(--vscode-descriptionForeground); }
    .v { word-break: break-all; font-family: var(--vscode-editor-font-family, monospace); }
    .error { color: var(--vscode-errorForeground); }
    .warnings { border: 1px solid var(--vscode-inputValidation-warningBorder, var(--vscode-panel-border)); border-radius: 6px; padding: 8px 12px; margin-bottom: 14px; }
</style>
</head>
<body>${content}</body>
</html>`;
    }
}

function escapeHtml(value: string): string {
    return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
