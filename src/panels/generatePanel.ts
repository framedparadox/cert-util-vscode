import * as crypto from 'crypto';
import * as path from 'path';
import * as vscode from 'vscode';
import {
    CertificateSubject,
    KEY_ALGORITHMS,
    KeyAlgorithm,
    generateCsr,
    generateKeyPair,
    generateSelfSignedCertificate,
} from '../certificates/generation';

const MAX_SAVE_TEXT_BYTES = 1024 * 1024;

type GenerateOperation = 'self-signed' | 'csr' | 'key-pair';

interface GenerateMessage {
    command: string;
    operation?: string;
    keyAlgorithm?: string;
    commonName?: string;
    organization?: string;
    organizationalUnit?: string;
    country?: string;
    state?: string;
    locality?: string;
    email?: string;
    subjectAltNames?: string;
    validityDays?: number;
    isCertificateAuthority?: boolean;
    text?: string;
    suggestedName?: string;
}

interface GenerateOutputFile {
    label: string;
    suggestedName: string;
    content: string;
}

export class GeneratePanel {
    public static readonly viewType = 'certificateUtilGenerate';
    private static currentPanel: GeneratePanel | undefined;

    private readonly panel: vscode.WebviewPanel;
    private readonly disposables: vscode.Disposable[] = [];

    private constructor(panel: vscode.WebviewPanel) {
        this.panel = panel;
        this.panel.webview.html = this.getWebviewContent();
        this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
        this.panel.webview.onDidReceiveMessage((message) => this.handleMessage(message as GenerateMessage), null, this.disposables);
    }

    public static render(extensionUri: vscode.Uri) {
        if (GeneratePanel.currentPanel) {
            GeneratePanel.currentPanel.panel.reveal(vscode.ViewColumn.One);
            return;
        }

        const panel = vscode.window.createWebviewPanel(GeneratePanel.viewType, 'Generate Certificate', vscode.ViewColumn.One, {
            enableScripts: true,
            retainContextWhenHidden: true,
        });
        GeneratePanel.currentPanel = new GeneratePanel(panel);
    }

    private async handleMessage(message: GenerateMessage) {
        try {
            switch (message.command) {
                case 'generate':
                    await this.handleGenerate(message);
                    return;
                case 'saveText':
                    if (typeof message.text === 'string' && typeof message.suggestedName === 'string') {
                        await this.handleSaveText(message.text, message.suggestedName);
                    }
                    return;
            }
        } catch (error) {
            this.panel.webview.postMessage({
                command: 'error',
                message: error instanceof Error ? error.message : String(error),
            });
        }
    }

    private async handleGenerate(message: GenerateMessage) {
        const operation = this.resolveOperation(message.operation);
        const keyAlgorithm = this.resolveKeyAlgorithm(message.keyAlgorithm);
        const subject = this.buildSubject(message);
        const subjectAltNames = (message.subjectAltNames ?? '')
            .split(/[\n,]/)
            .map((value) => value.trim())
            .filter((value) => value.length > 0);
        const isCertificateAuthority = Boolean(message.isCertificateAuthority);

        const files: GenerateOutputFile[] = [];
        let summary = '';

        if (operation === 'key-pair') {
            const pair = await generateKeyPair(keyAlgorithm);
            files.push(
                { label: 'Private Key', suggestedName: 'private-key.pem', content: pair.privateKeyPem },
                { label: 'Public Key', suggestedName: 'public-key.pem', content: pair.publicKeyPem }
            );
            summary = `Generated a ${keyAlgorithm} key pair.`;
        } else if (operation === 'csr') {
            const result = await generateCsr({ keyAlgorithm, subject, subjectAltNames, isCertificateAuthority });
            files.push(
                { label: 'Certificate Signing Request', suggestedName: 'request.csr', content: result.csrPem },
                { label: 'Private Key', suggestedName: 'private-key.pem', content: result.privateKeyPem }
            );
            summary = `Generated a ${keyAlgorithm} certificate signing request for ${subject.commonName}.`;
        } else {
            const validityDays = this.resolveValidityDays(message.validityDays);
            const result = await generateSelfSignedCertificate({
                keyAlgorithm,
                subject,
                subjectAltNames,
                isCertificateAuthority,
                validityDays,
            });
            files.push(
                { label: 'Certificate', suggestedName: 'certificate.pem', content: result.certificatePem },
                { label: 'Private Key', suggestedName: 'private-key.pem', content: result.privateKeyPem }
            );
            summary = `Generated a self-signed ${keyAlgorithm} certificate for ${subject.commonName}, valid for ${validityDays} days.`;
        }

        this.panel.webview.postMessage({ command: 'result', summary, files });
    }

    private async handleSaveText(text: string, suggestedName: string) {
        if (Buffer.byteLength(text) > MAX_SAVE_TEXT_BYTES) {
            throw new Error('The generated output exceeds the 1 MB save limit.');
        }
        const safeName = path.basename(suggestedName) || 'output.pem';
        const target = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file(path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '', safeName)),
            saveLabel: 'Save',
        });
        if (!target) {
            return;
        }
        await vscode.workspace.fs.writeFile(target, Buffer.from(text, 'utf8'));
        void vscode.window.showInformationMessage(`Saved ${path.basename(target.fsPath)}`);
    }

    private resolveOperation(operation?: string): GenerateOperation {
        return operation === 'csr' || operation === 'key-pair' ? operation : 'self-signed';
    }

    private resolveKeyAlgorithm(value?: string): KeyAlgorithm {
        return KEY_ALGORITHMS.includes(value as KeyAlgorithm) ? (value as KeyAlgorithm) : 'EC-P256';
    }

    private resolveValidityDays(value?: number): number {
        return typeof value === 'number' && Number.isFinite(value) && value > 0 ? Math.floor(value) : 365;
    }

    private buildSubject(message: GenerateMessage): CertificateSubject {
        const commonName = (message.commonName ?? '').trim();
        if (!commonName) {
            throw new Error('A common name (CN) is required.');
        }
        return {
            commonName,
            organization: message.organization?.trim() || undefined,
            organizationalUnit: message.organizationalUnit?.trim() || undefined,
            country: message.country?.trim() || undefined,
            state: message.state?.trim() || undefined,
            locality: message.locality?.trim() || undefined,
            email: message.email?.trim() || undefined,
        };
    }

    private dispose() {
        GeneratePanel.currentPanel = undefined;
        this.panel.dispose();
        while (this.disposables.length) {
            this.disposables.pop()?.dispose();
        }
    }

    private getWebviewContent(): string {
        const nonce = crypto.randomBytes(16).toString('base64url');
        const csp = `default-src 'none'; base-uri 'none'; form-action 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';`;
        const algorithmOptions = KEY_ALGORITHMS.map((algorithm) => `<option value="${algorithm}">${algorithm}</option>`).join('');

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="${csp}">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Generate Certificate</title>
    <style nonce="${nonce}">
        body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 16px; }
        h1 { font-size: 1.3rem; }
        fieldset { border: 1px solid var(--vscode-panel-border); border-radius: 6px; margin-bottom: 16px; padding: 12px 16px; }
        legend { font-weight: 600; padding: 0 6px; }
        label { display: block; margin: 8px 0 2px; font-size: 0.85rem; }
        input, select { width: 100%; box-sizing: border-box; padding: 6px 8px; background: var(--vscode-input-background); color: var(--vscode-input-foreground); border: 1px solid var(--vscode-input-border, var(--vscode-panel-border)); border-radius: 4px; }
        .row { display: flex; gap: 12px; }
        .row > div { flex: 1; }
        .checkbox { display: flex; align-items: center; gap: 8px; margin-top: 10px; }
        .checkbox input { width: auto; }
        button { margin-top: 12px; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; background: var(--vscode-button-background); color: var(--vscode-button-foreground); }
        button.secondary { background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground); }
        .result-card { border: 1px solid var(--vscode-panel-border); border-radius: 6px; padding: 12px; margin-top: 12px; }
        pre { white-space: pre-wrap; word-break: break-all; background: var(--vscode-textCodeBlock-background); padding: 10px; border-radius: 4px; max-height: 220px; overflow: auto; }
        .muted { color: var(--vscode-descriptionForeground); }
        .error { color: var(--vscode-errorForeground); margin-top: 10px; }
        .hidden { display: none; }
        .actions { display: flex; gap: 8px; }
    </style>
</head>
<body>
    <h1>Generate Certificate</h1>
    <p class="muted">Create key pairs, certificate signing requests, and self-signed certificates locally. Private keys never leave your machine.</p>

    <fieldset>
        <legend>Operation</legend>
        <label for="operation">What do you want to generate?</label>
        <select id="operation">
            <option value="self-signed">Self-Signed Certificate</option>
            <option value="csr">Certificate Signing Request (CSR)</option>
            <option value="key-pair">Key Pair Only</option>
        </select>
        <label for="keyAlgorithm">Key Algorithm</label>
        <select id="keyAlgorithm">${algorithmOptions}</select>
        <div id="validity-row">
            <label for="validityDays">Validity (days)</label>
            <input id="validityDays" type="number" min="1" value="365">
        </div>
        <div class="checkbox" id="ca-row">
            <input id="isCertificateAuthority" type="checkbox">
            <label for="isCertificateAuthority" style="margin:0;">Certificate Authority (CA)</label>
        </div>
    </fieldset>

    <fieldset id="subject-fieldset">
        <legend>Subject</legend>
        <label for="commonName">Common Name (CN) *</label>
        <input id="commonName" type="text" placeholder="example.com">
        <div class="row">
            <div><label for="organization">Organization (O)</label><input id="organization" type="text"></div>
            <div><label for="organizationalUnit">Org Unit (OU)</label><input id="organizationalUnit" type="text"></div>
        </div>
        <div class="row">
            <div><label for="locality">Locality (L)</label><input id="locality" type="text"></div>
            <div><label for="state">State (ST)</label><input id="state" type="text"></div>
            <div><label for="country">Country (C)</label><input id="country" type="text" maxlength="2" placeholder="US"></div>
        </div>
        <label for="email">Email</label>
        <input id="email" type="text">
        <label for="subjectAltNames">Subject Alternative Names (comma or newline separated)</label>
        <input id="subjectAltNames" type="text" placeholder="DNS:example.com, DNS:www.example.com, IP:10.0.0.1">
    </fieldset>

    <button id="generate-btn">Generate</button>
    <div id="error" class="error hidden"></div>
    <div id="results"></div>

    <script nonce="${nonce}">
        (function () {
            const vscode = acquireVsCodeApi();
            const stash = new Map();
            const operation = document.getElementById('operation');
            const validityRow = document.getElementById('validity-row');
            const subjectFieldset = document.getElementById('subject-fieldset');
            const errorEl = document.getElementById('error');

            function escapeHtml(value) {
                const div = document.createElement('div');
                div.textContent = value == null ? '' : String(value);
                return div.innerHTML;
            }

            function syncOperation() {
                const isKeyPair = operation.value === 'key-pair';
                subjectFieldset.classList.toggle('hidden', isKeyPair);
                validityRow.classList.toggle('hidden', operation.value !== 'self-signed');
            }

            operation.addEventListener('change', syncOperation);
            syncOperation();

            document.getElementById('generate-btn').addEventListener('click', function () {
                errorEl.classList.add('hidden');
                document.getElementById('results').innerHTML = '<p class="muted">Generating…</p>';
                vscode.postMessage({
                    command: 'generate',
                    operation: operation.value,
                    keyAlgorithm: document.getElementById('keyAlgorithm').value,
                    commonName: document.getElementById('commonName').value,
                    organization: document.getElementById('organization').value,
                    organizationalUnit: document.getElementById('organizationalUnit').value,
                    locality: document.getElementById('locality').value,
                    state: document.getElementById('state').value,
                    country: document.getElementById('country').value,
                    email: document.getElementById('email').value,
                    subjectAltNames: document.getElementById('subjectAltNames').value,
                    validityDays: Number(document.getElementById('validityDays').value),
                    isCertificateAuthority: document.getElementById('isCertificateAuthority').checked
                });
            });

            function renderResults(payload) {
                stash.clear();
                const parts = ['<div class="result-card"><strong>' + escapeHtml(payload.summary) + '</strong></div>'];
                payload.files.forEach(function (file, index) {
                    const copyKey = 'copy-' + index;
                    const saveKey = 'save-' + index;
                    stash.set(copyKey, file.content);
                    stash.set(saveKey, file);
                    parts.push(
                        '<div class="result-card">' +
                        '<h3>' + escapeHtml(file.label) + '</h3>' +
                        '<pre>' + escapeHtml(file.content) + '</pre>' +
                        '<div class="actions">' +
                        '<button class="secondary" data-copy="' + copyKey + '">Copy</button>' +
                        '<button class="secondary" data-save="' + saveKey + '">Save…</button>' +
                        '</div></div>'
                    );
                });
                document.getElementById('results').innerHTML = parts.join('');
            }

            document.getElementById('results').addEventListener('click', function (event) {
                const copyKey = event.target.getAttribute('data-copy');
                const saveKey = event.target.getAttribute('data-save');
                if (copyKey && stash.has(copyKey)) {
                    navigator.clipboard.writeText(stash.get(copyKey));
                } else if (saveKey && stash.has(saveKey)) {
                    const file = stash.get(saveKey);
                    vscode.postMessage({ command: 'saveText', text: file.content, suggestedName: file.suggestedName });
                }
            });

            window.addEventListener('message', function (event) {
                const message = event.data;
                if (message.command === 'result') {
                    renderResults(message);
                } else if (message.command === 'error') {
                    document.getElementById('results').innerHTML = '';
                    errorEl.textContent = message.message;
                    errorEl.classList.remove('hidden');
                }
            });
        })();
    </script>
</body>
</html>`;
    }
}
