import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import {
    ExternalToolAvailability,
    ParsedCertificateDetails,
    parseCertificateInputFromFile,
    parseCertificateInputFromText,
} from '../certificates/certificateUtils';
// node-forge-backed keystore parsing is loaded lazily (dynamic import in the handlers below) so the
// library is not evaluated at activation. Only the type is imported here (erased at runtime).
import type { ParsedKeystore } from '../certificates/keystoreParser';
import {
    buildDerToPemCommand,
    buildJksExportCommand,
    buildJksPemExportCommands,
    buildJksToPkcs12Command,
    buildPemToDerCommand,
    buildPkcs12ExportCommand,
    buildPkcs12PemExportCommands,
    detectExternalToolAvailability,
    inspectPkcs12File,
    inspectPkcs7File,
    listJksAliases,
} from '../certificates/externalTools';

type OperationTab = 'convert' | 'keystore';
type KeystoreType = 'auto' | 'jks' | 'pkcs12';
const PICK_TARGETS = new Set(['convert-bundle-path', 'convert-cert-path', 'convert-key-path', 'keystore-path']);

interface LaunchRequest {
    initialTab?: OperationTab;
}

function isWebviewMessage(value: unknown): value is Record<string, unknown> & { command: string } {
    return typeof value === 'object' && value !== null && typeof (value as { command?: unknown }).command === 'string';
}

function optionalString(value: unknown): string | undefined {
    return typeof value === 'string' ? value : undefined;
}

function normalizePassword(password: string | undefined): string | undefined {
    if (password && password.length > 1024) {
        throw new Error('Passwords are limited to 1024 characters.');
    }
    return password ? password : undefined;
}

function readFileAsText(filePath: string): string | undefined {
    try {
        return fs.readFileSync(filePath, 'utf8');
    } catch {
        return undefined;
    }
}

/** Maximum size for a keystore file read into memory for native parsing. */
const MAX_KEYSTORE_FILE_BYTES = 10 * 1024 * 1024;

function readKeystoreFile(filePath: string): Buffer {
    const size = fs.statSync(filePath).size;
    if (size > MAX_KEYSTORE_FILE_BYTES) {
        throw new Error(`Keystore file exceeds the ${MAX_KEYSTORE_FILE_BYTES / (1024 * 1024)} MB limit.`);
    }
    return fs.readFileSync(filePath);
}

export class CertificateOperationsPanel {
    private static currentPanel: CertificateOperationsPanel | undefined;

    private readonly panel: vscode.WebviewPanel;
    private readonly disposables: vscode.Disposable[] = [];
    private readonly capabilities: Promise<ExternalToolAvailability>;
    private pendingLaunchRequest?: LaunchRequest;
    private lastResult?: {
        command: 'convertResult' | 'keystoreResult';
        payload: {
            title: string;
            summary: string;
            command?: string;
            body?: string;
            warnings?: string[];
        };
    };

    private constructor(panel: vscode.WebviewPanel, launchRequest?: LaunchRequest) {
        this.panel = panel;
        this.pendingLaunchRequest = launchRequest;
        this.capabilities = detectExternalToolAvailability();

        this.panel.webview.html = this.getWebviewContent();
        this.panel.onDidDispose(() => this.dispose(), null, this.disposables);

        this.panel.webview.onDidReceiveMessage(
            async (message) => {
                if (!isWebviewMessage(message)) {
                    return;
                }

                switch (message.command) {
                    case 'ready':
                        await this.postCapabilities();
                        if (this.lastResult) {
                            this.panel.webview.postMessage(this.lastResult);
                        }
                        this.runPendingLaunchRequest();
                        return;
                    case 'pickPath':
                        if (typeof message.target === 'string' && PICK_TARGETS.has(message.target)) {
                            await this.handlePickPath(message.target);
                        }
                        return;
                    case 'convertAction':
                        await this.handleConvertAction(message);
                        return;
                    case 'keystoreAction':
                        await this.handleKeystoreAction(message);
                        return;
                }
            },
            null,
            this.disposables
        );
    }

    public static render(extensionUri: vscode.Uri, launchRequest?: LaunchRequest) {
        if (CertificateOperationsPanel.currentPanel) {
            CertificateOperationsPanel.currentPanel.pendingLaunchRequest = launchRequest;
            CertificateOperationsPanel.currentPanel.panel.reveal(vscode.ViewColumn.One);
            void CertificateOperationsPanel.currentPanel.postCapabilities();
            CertificateOperationsPanel.currentPanel.runPendingLaunchRequest();
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            'certificateOperationsPanel',
            'Certificate Conversion & Keystore',
            vscode.ViewColumn.One,
            {
                enableScripts: true,
                localResourceRoots: [],
            }
        );

        panel.iconPath = vscode.Uri.joinPath(extensionUri, 'resources', 'icons', 'conversion-keystore.svg');
        CertificateOperationsPanel.currentPanel = new CertificateOperationsPanel(panel, launchRequest);
    }

    public dispose() {
        CertificateOperationsPanel.currentPanel = undefined;
        this.panel.dispose();
        while (this.disposables.length) {
            this.disposables.pop()?.dispose();
        }
    }

    private async handlePickPath(target: string) {
        const selection = await vscode.window.showOpenDialog({
            canSelectFiles: true,
            canSelectFolders: false,
            canSelectMany: false,
            openLabel: 'Select File',
        });

        if (!selection?.[0]) {
            return;
        }

        this.panel.webview.postMessage({
            command: 'pathSelected',
            target,
            path: selection[0].fsPath,
        });
    }

    private async handleConvertAction(message: Record<string, unknown>) {
        try {
            const bundlePath = optionalString(message.bundlePath)?.trim();
            const certPath = optionalString(message.certPath)?.trim();
            const keyPath = optionalString(message.keyPath)?.trim();
            const outputPath = optionalString(message.outputPath)?.trim();
            const password = normalizePassword(optionalString(message.password));

            switch (message.action) {
                case 'pemToDer':
                    if (!certPath) {
                        throw new Error('Certificate path is required.');
                    }
                    this.postTextResult('convert', {
                        title: 'PEM to DER Command',
                        summary: 'Run this OpenSSL command to convert a PEM certificate to DER.',
                        command: buildPemToDerCommand(certPath, outputPath || 'certificate.der'),
                    });
                    return;
                case 'derToPem':
                    if (!certPath) {
                        throw new Error('Certificate path is required.');
                    }
                    this.postTextResult('convert', {
                        title: 'DER to PEM Command',
                        summary: 'Run this OpenSSL command to convert a DER certificate to PEM.',
                        command: buildDerToPemCommand(certPath, outputPath || 'certificate.pem'),
                    });
                    return;
                case 'inspectPkcs12': {
                    if (!bundlePath) {
                        throw new Error('Bundle file path is required.');
                    }
                    // Parse natively (node-forge) so inspection works without OpenSSL installed; fall
                    // back to the OpenSSL recipe only if native parsing fails for an unsupported file.
                    try {
                        const { parsePkcs12 } = await import('../certificates/keystoreParser.js');
                        const parsed = parsePkcs12(readKeystoreFile(bundlePath), password ?? '');
                        this.postTextResult('convert', {
                            title: 'PKCS#12 Inspection',
                            summary: 'Parsed natively without OpenSSL.',
                            body: this.formatKeystoreSummary(parsed),
                            warnings: parsed.warnings,
                        });
                    } catch (nativeError) {
                        const result = await inspectPkcs12File(bundlePath, password);
                        this.postTextResult('convert', {
                            title: 'PKCS#12 Inspection',
                            summary: `${result.summary} (native parse failed: ${nativeError instanceof Error ? nativeError.message : String(nativeError)})`,
                            command: result.command,
                            body: result.rawOutput,
                            warnings: result.warnings,
                        });
                    }
                    return;
                }
                case 'inspectPkcs7': {
                    if (!bundlePath) {
                        throw new Error('Bundle file path is required.');
                    }
                    try {
                        const { parsePkcs7 } = await import('../certificates/keystoreParser.js');
                        const parsed = parsePkcs7(readKeystoreFile(bundlePath));
                        this.postTextResult('convert', {
                            title: 'PKCS#7 Inspection',
                            summary: 'Parsed natively without OpenSSL.',
                            body: this.formatKeystoreSummary(parsed),
                            warnings: parsed.warnings,
                        });
                    } catch (nativeError) {
                        const result = await inspectPkcs7File(bundlePath);
                        this.postTextResult('convert', {
                            title: 'PKCS#7 Inspection',
                            summary: `${result.summary} (native parse failed: ${nativeError instanceof Error ? nativeError.message : String(nativeError)})`,
                            command: result.command,
                            body: result.rawOutput,
                            warnings: result.warnings,
                        });
                    }
                    return;
                }
                case 'buildPkcs12':
                    if (!certPath || !keyPath) {
                        throw new Error('Certificate path and private key path are required.');
                    }
                    this.postTextResult('convert', {
                        title: 'PKCS#12 Export Command',
                        summary: 'Run this OpenSSL command to build a PKCS#12 bundle from a certificate and private key.',
                        command: buildPkcs12ExportCommand(certPath, keyPath, outputPath || 'certificate.p12', password),
                    });
                    return;
                case 'inspectCsr': {
                    const filePath = certPath || bundlePath;
                    if (!filePath) {
                        throw new Error('Certificate path or bundle path is required.');
                    }
                    const artifact = parseCertificateInputFromFile(filePath);
                    if (artifact.kind !== 'csr') {
                        throw new Error('The selected file is not classified as a CSR.');
                    }
                    this.postTextResult('convert', {
                        title: 'CSR Inspection',
                        summary: 'The selected file is classified as a certificate signing request.',
                        body: artifact.rawText || readFileAsText(filePath) || artifact.blockTypes.join(', '),
                        warnings: artifact.warnings,
                    });
                    return;
                }
                default:
                    throw new Error(`Unsupported conversion action: ${String(message.action)}`);
            }
        } catch (error) {
            this.postError('convert', 'Conversion action failed.', error);
        }
    }

    private async handleKeystoreAction(message: Record<string, unknown>) {
        try {
            const keystorePath = optionalString(message.keystorePath)?.trim();
            if (!keystorePath) {
                throw new Error('Keystore path is required.');
            }

            const alias = optionalString(message.alias)?.trim();
            const password = normalizePassword(optionalString(message.password));
            const requestedKeystoreType = message.keystoreType;
            const keystoreType = this.resolveKeystoreType(
                keystorePath,
                requestedKeystoreType === 'jks' || requestedKeystoreType === 'pkcs12' ? requestedKeystoreType : 'auto'
            );

            switch (message.action) {
                case 'listAliases': {
                    const result = await listJksAliases(keystorePath, password);
                    this.postTextResult('keystore', {
                        title: 'JKS Alias Listing',
                        summary: result.summary,
                        command: result.command,
                        body: result.rawOutput,
                    });
                    return;
                }
                case 'exportCert':
                    if (!alias) {
                        throw new Error('Alias is required to export a certificate.');
                    }
                    this.postTextResult('keystore', {
                        title: 'JKS Export Certificate Command',
                        summary: 'Run this keytool command to export a PEM certificate from the JKS keystore.',
                        command: buildJksExportCommand(keystorePath, alias),
                    });
                    return;
                case 'convertToPkcs12':
                    this.postTextResult('keystore', {
                        title: 'JKS to PKCS#12 Command',
                        summary: 'Run this keytool command to convert the JKS keystore to a PKCS#12 bundle.',
                        command: buildJksToPkcs12Command(keystorePath),
                    });
                    return;
                case 'exportPemPair': {
                    const certificateOutputPath = optionalString(message.certificateOutputPath)?.trim() || 'certificate.pem';
                    const keyOutputPath = optionalString(message.keyOutputPath)?.trim() || 'private-key.pem';
                    const pkcs12OutputPath = optionalString(message.pkcs12OutputPath)?.trim() || 'keystore-export.p12';
                    const command =
                        keystoreType === 'jks'
                            ? this.buildJksPemExportCommand(
                                  keystorePath,
                                  alias,
                                  pkcs12OutputPath,
                                  certificateOutputPath,
                                  keyOutputPath,
                                  password
                              )
                            : buildPkcs12PemExportCommands(keystorePath, certificateOutputPath, keyOutputPath, password);

                    const warnings = ['The private key command writes an unencrypted PEM key. Protect the output file.'];
                    if (keystoreType === 'jks' && password) {
                        warnings.push(
                            'The keytool command reads the store password from a file. Create it first, e.g. `printf %s "<password>" > storepass.txt`, and delete it afterwards.'
                        );
                    }

                    this.postTextResult('keystore', {
                        title: 'Export Certificate and Key as PEM',
                        summary:
                            keystoreType === 'jks'
                                ? 'Run these commands to convert the JKS alias to PKCS#12, then export the certificate and private key as PEM.'
                                : 'Run these OpenSSL commands to export the certificate and private key as PEM from the PFX/PKCS#12 bundle.',
                        command,
                        warnings,
                    });
                    return;
                }
                default:
                    throw new Error(`Unsupported keystore action: ${String(message.action)}`);
            }
        } catch (error) {
            this.postError('keystore', 'Keystore action failed.', error);
        }
    }

    private buildJksPemExportCommand(
        keystorePath: string,
        alias: string | undefined,
        pkcs12OutputPath: string,
        certificateOutputPath: string,
        keyOutputPath: string,
        password?: string
    ): string {
        if (!alias) {
            throw new Error('Alias is required to export a certificate and key from JKS.');
        }

        return buildJksPemExportCommands(keystorePath, alias, pkcs12OutputPath, certificateOutputPath, keyOutputPath, password);
    }

    private resolveKeystoreType(keystorePath: string, keystoreType: KeystoreType): Exclude<KeystoreType, 'auto'> {
        if (keystoreType !== 'auto') {
            return keystoreType;
        }

        const extension = path.extname(keystorePath).toLowerCase();
        return extension === '.jks' ? 'jks' : 'pkcs12';
    }

    /** Renders natively-parsed keystore certificates (and any private-key metadata) as readable text. */
    private formatKeystoreSummary(parsed: ParsedKeystore): string {
        const lines: string[] = [];
        if (parsed.privateKey) {
            const bits = typeof parsed.privateKey.bits === 'number' ? ` (${parsed.privateKey.bits}-bit)` : '';
            lines.push(`Private key: ${parsed.privateKey.algorithm}${bits}`, '');
        }

        if (!parsed.certificatePems.length) {
            lines.push('No certificates found.');
            return lines.join('\n');
        }

        const artifact = parseCertificateInputFromText(parsed.certificatePems.join('\n'), {
            kind: 'file',
            label: 'keystore',
        });
        artifact.certificates.forEach((certificate: ParsedCertificateDetails, index: number) => {
            lines.push(
                `Certificate ${index + 1}: ${certificate.subjectCommonName || certificate.subject}`,
                `  Subject:    ${certificate.subject}`,
                `  Issuer:     ${certificate.issuer}`,
                `  Valid:      ${certificate.validFrom}  ->  ${certificate.validTo}`,
                `  Serial:     ${certificate.serialNumber}`,
                `  Key:        ${certificate.algorithm}`,
                `  Signature:  ${certificate.signatureAlgorithm}`,
                `  SHA-256:    ${certificate.fingerprint256}`,
                ''
            );
        });
        return lines.join('\n').trimEnd();
    }

    private runPendingLaunchRequest() {
        if (!this.pendingLaunchRequest?.initialTab) {
            return;
        }

        this.panel.webview.postMessage({
            command: 'activateTab',
            tab: this.pendingLaunchRequest.initialTab,
        });
        this.pendingLaunchRequest = undefined;
    }

    private async postCapabilities() {
        this.panel.webview.postMessage({
            command: 'capabilities',
            payload: await this.capabilities,
        });
    }

    private postTextResult(
        tab: OperationTab,
        payload: {
            title: string;
            summary: string;
            command?: string;
            body?: string;
            warnings?: string[];
        }
    ) {
        this.lastResult = {
            command: tab === 'convert' ? 'convertResult' : 'keystoreResult',
            payload,
        };
        this.panel.webview.postMessage(this.lastResult);
    }

    private postError(tab: OperationTab, summary: string, error: unknown) {
        const detail = error instanceof Error ? error.message : String(error);
        this.panel.webview.postMessage({
            command: 'error',
            payload: {
                tab,
                summary,
                detail,
            },
        });
    }

    private getWebviewContent(): string {
        const nonce = crypto.randomBytes(16).toString('base64url');
        const csp = `default-src 'none'; base-uri 'none'; form-action 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';`;

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="${csp}">
    <title>Certificate Conversion & Keystore</title>
    <style nonce="${nonce}">
        :root {
            color-scheme: light dark;
        }
        * {
            box-sizing: border-box;
        }
        body {
            margin: 0;
            padding: 20px;
            font-family: var(--vscode-font-family);
            color: var(--vscode-foreground);
            background: var(--vscode-editor-background);
        }
        h1 {
            margin: 0 0 10px;
            font-size: 24px;
        }
        p.lead {
            margin: 0 0 18px;
            color: var(--vscode-descriptionForeground);
            max-width: 960px;
        }
        .tabs,
        .actions,
        .issue-list,
        .warning-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }
        .tabs {
            margin-bottom: 16px;
        }
        .tab {
            border: 1px solid var(--vscode-input-border);
            background: transparent;
            color: inherit;
            padding: 8px 12px;
            border-radius: 999px;
            cursor: pointer;
        }
        .tab.active {
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .panel,
        .result-panel,
        .capability {
            border: 1px solid var(--vscode-panel-border);
            border-radius: 10px;
            background: var(--vscode-sideBar-background);
            padding: 14px;
        }
        .form-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 12px;
        }
        .field,
        .field-wide {
            display: flex;
            flex-direction: column;
            gap: 6px;
            margin-bottom: 12px;
        }
        .field-wide {
            grid-column: 1 / -1;
        }
        label {
            font-size: 12px;
            font-weight: 600;
        }
        input,
        select,
        button {
            font: inherit;
        }
        input,
        select {
            width: 100%;
            padding: 9px 10px;
            border: 1px solid var(--vscode-input-border);
            border-radius: 8px;
            background: var(--vscode-input-background);
            color: var(--vscode-input-foreground);
        }
        button {
            border: 1px solid var(--vscode-button-border, var(--vscode-input-border));
            border-radius: 8px;
            padding: 9px 12px;
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            cursor: pointer;
        }
        button.secondary {
            background: var(--vscode-button-secondaryBackground);
            color: var(--vscode-button-secondaryForeground);
        }
        button.ghost {
            background: transparent;
            color: inherit;
        }
        .result-panel {
            margin-top: 14px;
        }
        .result-panel:empty {
            display: none;
        }
        .result-panel h3 {
            margin-top: 0;
        }
        .muted {
            color: var(--vscode-descriptionForeground);
        }
        .section-card {
            border: 1px solid var(--vscode-panel-border);
            border-radius: 10px;
            padding: 12px;
            margin-top: 12px;
        }
        .section-card h4 {
            margin: 0 0 8px;
        }
        pre {
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            background: var(--vscode-textCodeBlock-background);
            border-radius: 8px;
            padding: 12px;
            font-family: var(--vscode-editor-font-family);
            font-size: 12px;
        }
        .warning-list {
            margin: 0;
            padding: 0;
            list-style: none;
        }
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 4px 10px;
            font-size: 11px;
            font-weight: 600;
            border-radius: 12px;
            border: 1px solid;
        }
        .badge.valid {
            background-color: var(--vscode-diffEditor-insertedTextBackground, transparent);
            color: var(--vscode-testing-iconPassed, var(--vscode-charts-green));
            border-color: var(--vscode-testing-iconPassed, var(--vscode-charts-green));
        }
        .badge.expiring {
            background-color: var(--vscode-inputValidation-warningBackground, transparent);
            color: var(--vscode-editorWarning-foreground);
            border-color: var(--vscode-inputValidation-warningBorder, var(--vscode-editorWarning-foreground));
        }
        .badge.expired {
            background-color: var(--vscode-inputValidation-errorBackground, transparent);
            color: var(--vscode-editorError-foreground);
            border-color: var(--vscode-inputValidation-errorBorder, var(--vscode-editorError-foreground));
        }
        .badge-icon {
            width: 12px;
            height: 12px;
        }
        .capabilities {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
            margin-top: 12px;
        }
        @media (max-width: 720px) {
            .form-grid {
                grid-template-columns: 1fr;
            }
            .field-wide {
                grid-column: auto;
            }
        }
    </style>
</head>
<body>
    <h1>Certificate Conversion & Keystore</h1>
    <p class="lead">Convert certificate formats, inspect PKCS bundles, and generate keystore export commands for JKS, PFX, and PKCS#12 files.</p>

    <div class="tabs" role="tablist" aria-label="Certificate operation tools">
        <button id="convert-tab" class="tab active" type="button" role="tab" aria-selected="true" aria-controls="convert" data-tab="convert">Convert</button>
        <button id="keystore-tab" class="tab" type="button" role="tab" aria-selected="false" aria-controls="keystore" tabindex="-1" data-tab="keystore">Keystore</button>
    </div>

    <section class="tab-content active" id="convert" role="tabpanel" aria-labelledby="convert-tab">
        <div class="panel">
            <div class="form-grid">
                <div class="field">
                    <label for="convert-bundle-path">Bundle File Path</label>
                    <input id="convert-bundle-path" type="text" maxlength="4096" placeholder="/path/to/bundle.p12 or bundle.p7b">
                    <div class="actions">
                        <button class="secondary" data-pick-target="convert-bundle-path">Choose Bundle File</button>
                    </div>
                </div>
                <div class="field">
                    <label for="convert-password">Bundle Password (optional)</label>
                    <input id="convert-password" type="password" maxlength="1024" autocomplete="off" placeholder="PKCS#12 password">
                </div>
                <div class="field">
                    <label for="convert-cert-path">Certificate Path</label>
                    <input id="convert-cert-path" type="text" maxlength="4096" placeholder="/path/to/certificate.crt">
                    <div class="actions">
                        <button class="secondary" data-pick-target="convert-cert-path">Choose Certificate</button>
                    </div>
                </div>
                <div class="field">
                    <label for="convert-key-path">Private Key Path</label>
                    <input id="convert-key-path" type="text" maxlength="4096" placeholder="/path/to/private.key">
                    <div class="actions">
                        <button class="secondary" data-pick-target="convert-key-path">Choose Key</button>
                    </div>
                </div>
                <div class="field">
                    <label for="convert-output-path">Output Path</label>
                    <input id="convert-output-path" type="text" maxlength="4096" placeholder="certificate.p12">
                </div>
            </div>
            <div class="actions">
                <button id="pem-to-der-btn">Build PEM to DER</button>
                <button class="secondary" id="der-to-pem-btn">Build DER to PEM</button>
                <button class="secondary" id="inspect-pkcs12-btn">Inspect PKCS#12</button>
                <button class="secondary" id="inspect-pkcs7-btn">Inspect PKCS#7</button>
                <button class="secondary" id="inspect-csr-btn">Inspect CSR</button>
                <button class="ghost" id="build-pkcs12-btn">Build PKCS#12</button>
            </div>
        </div>
        <div class="result-panel" id="convert-result" aria-live="polite"></div>
    </section>

    <section class="tab-content" id="keystore" role="tabpanel" aria-labelledby="keystore-tab" hidden>
        <div class="panel">
            <div class="form-grid">
                <div class="field-wide">
                    <label for="keystore-path">Keystore / PFX / PKCS#12 Path</label>
                    <input id="keystore-path" type="text" maxlength="4096" placeholder="/path/to/keystore.jks, bundle.pfx, or bundle.p12">
                    <div class="actions">
                        <button class="secondary" data-pick-target="keystore-path">Choose Store File</button>
                    </div>
                </div>
                <div class="field">
                    <label for="keystore-type">Store Type</label>
                    <select id="keystore-type">
                        <option value="auto">Auto from extension</option>
                        <option value="jks">JKS</option>
                        <option value="pkcs12">PFX / PKCS#12</option>
                    </select>
                </div>
                <div class="field">
                    <label for="keystore-alias">Alias (required for JKS key export)</label>
                    <input id="keystore-alias" type="text" maxlength="1024" placeholder="certificate-alias">
                </div>
                <div class="field">
                    <label for="keystore-password">Store Password (optional)</label>
                    <input id="keystore-password" type="password" maxlength="1024" autocomplete="off">
                </div>
                <div class="field">
                    <label for="keystore-cert-output">Certificate PEM Output</label>
                    <input id="keystore-cert-output" type="text" maxlength="4096" placeholder="certificate.pem">
                </div>
                <div class="field">
                    <label for="keystore-key-output">Private Key PEM Output</label>
                    <input id="keystore-key-output" type="text" maxlength="4096" placeholder="private-key.pem">
                </div>
                <div class="field">
                    <label for="keystore-p12-output">Intermediate PKCS#12 Output</label>
                    <input id="keystore-p12-output" type="text" maxlength="4096" placeholder="keystore-export.p12">
                </div>
            </div>
            <div class="actions">
                <button id="jks-list-btn">List JKS Aliases</button>
                <button class="secondary" id="jks-export-btn">Export Cert Command</button>
                <button class="secondary" id="jks-convert-btn">Convert JKS to PKCS#12</button>
                <button class="ghost" id="export-pem-pair-btn">Export Certificate + Key PEM</button>
            </div>
            <div class="capabilities" id="capabilities"></div>
        </div>
        <div class="result-panel" id="keystore-result" aria-live="polite"></div>
    </section>

    <script nonce="${nonce}">
        const vscode = acquireVsCodeApi();
        const copyStore = new Map();
        let copyId = 0;

        // Prune stale entries on every re-render to prevent unbounded Map growth.
        function clearCopyStore() {
            copyStore.clear();
            copyId = 0;
        }

        function setActiveTab(tabName) {
            document.querySelectorAll('.tab').forEach((tab) => {
                const isActive = tab.dataset.tab === tabName;
                tab.classList.toggle('active', isActive);
                tab.setAttribute('aria-selected', String(isActive));
                tab.tabIndex = isActive ? 0 : -1;
            });
            document.querySelectorAll('.tab-content').forEach((content) => {
                const isActive = content.id === tabName;
                content.classList.toggle('active', isActive);
                content.toggleAttribute('hidden', !isActive);
            });
        }

        function stashCopy(text) {
            const key = 'copy-' + copyId++;
            copyStore.set(key, text);
            return key;
        }

        function escapeHtml(value) {
            return String(value)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function renderStatusPill(kind, text) {
            const config = {
                valid: {
                    className: 'valid',
                    icon: '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>'
                },
                warning: {
                    className: 'expiring',
                    icon: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line>'
                },
                error: {
                    className: 'expired',
                    icon: '<circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line>'
                }
            };
            const status = config[kind] || config.warning;
            return '<span class="badge ' + status.className + '">' +
                '<svg class="badge-icon" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">' + status.icon + '</svg>' +
                escapeHtml(text) +
            '</span>';
        }

        function renderCapabilities(capabilities) {
            const host = document.getElementById('capabilities');
            host.innerHTML = ['openssl', 'keytool']
                .map((tool) => {
                    const data = capabilities[tool];
                    return '<div class="capability">' +
                        '<strong>' + escapeHtml(tool) + '</strong>' +
                        '<div class="muted">' + escapeHtml(data.available ? (data.version || 'Available') : (data.error || 'Unavailable')) + '</div>' +
                    '</div>';
                })
                .join('');
        }

        function renderTextResult(hostId, payload, title) {
            clearCopyStore();
            const host = document.getElementById(hostId);
            const commandKey = payload.command ? stashCopy(payload.command) : undefined;
            const bodyKey = payload.body ? stashCopy(payload.body) : undefined;
            host.innerHTML =
                '<h3>' + escapeHtml(payload.title || title) + '</h3>' +
                renderStatusPill('valid', 'Ready') +
                '<p class="muted">' + escapeHtml(payload.summary) + '</p>' +
                (payload.warnings && payload.warnings.length
                    ? '<ul class="warning-list">' + payload.warnings.map((warning) => '<li>' + renderStatusPill('warning', warning) + '</li>').join('') + '</ul>'
                    : '') +
                (payload.command ? '<div class="section-card"><h4>Command</h4><pre>' + escapeHtml(payload.command) + '</pre><div class="actions"><button class="secondary" data-copy-key="' + commandKey + '">Copy Command</button></div></div>' : '') +
                (payload.body ? '<div class="section-card"><h4>Output</h4><pre>' + escapeHtml(payload.body) + '</pre><div class="actions"><button class="secondary" data-copy-key="' + bodyKey + '">Copy Output</button></div></div>' : '');
        }

        function showError(payload) {
            const host = document.getElementById(payload.tab + '-result');
            if (!host) {
                return;
            }
            host.innerHTML = '<h3>Error</h3>' + renderStatusPill('error', payload.summary) + '<pre>' + escapeHtml(payload.detail) + '</pre>';
        }

        function getConvertPayload(action) {
            return {
                command: 'convertAction',
                action,
                bundlePath: document.getElementById('convert-bundle-path').value,
                password:
                    action === 'inspectPkcs12' || action === 'buildPkcs12'
                        ? document.getElementById('convert-password').value
                        : undefined,
                certPath: document.getElementById('convert-cert-path').value,
                keyPath: document.getElementById('convert-key-path').value,
                outputPath: document.getElementById('convert-output-path').value,
            };
        }

        function getKeystorePayload(action) {
            return {
                command: 'keystoreAction',
                action,
                keystorePath: document.getElementById('keystore-path').value,
                keystoreType: document.getElementById('keystore-type').value,
                alias: document.getElementById('keystore-alias').value,
                password: document.getElementById('keystore-password').value,
                certificateOutputPath: document.getElementById('keystore-cert-output').value,
                keyOutputPath: document.getElementById('keystore-key-output').value,
                pkcs12OutputPath: document.getElementById('keystore-p12-output').value,
            };
        }

        function postConvertAction(action) {
            vscode.postMessage(getConvertPayload(action));
            if (action === 'inspectPkcs12' || action === 'buildPkcs12') {
                document.getElementById('convert-password').value = '';
            }
        }

        function postKeystoreAction(action) {
            vscode.postMessage(getKeystorePayload(action));
            document.getElementById('keystore-password').value = '';
        }

        const tabs = Array.from(document.querySelectorAll('.tab'));
        tabs.forEach((tab) => {
            tab.addEventListener('click', () => setActiveTab(tab.dataset.tab));
            tab.addEventListener('keydown', (event) => {
                const currentIndex = tabs.indexOf(tab);
                let nextIndex;
                if (event.key === 'ArrowRight') {
                    nextIndex = (currentIndex + 1) % tabs.length;
                } else if (event.key === 'ArrowLeft') {
                    nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
                } else if (event.key === 'Home') {
                    nextIndex = 0;
                } else if (event.key === 'End') {
                    nextIndex = tabs.length - 1;
                } else {
                    return;
                }
                event.preventDefault();
                setActiveTab(tabs[nextIndex].dataset.tab);
                tabs[nextIndex].focus();
            });
        });

        document.querySelectorAll('[data-pick-target]').forEach((button) => {
            button.addEventListener('click', () => {
                vscode.postMessage({
                    command: 'pickPath',
                    target: button.dataset.pickTarget,
                });
            });
        });

        document.addEventListener('click', (event) => {
            const target = event.target;
            if (!(target instanceof HTMLElement)) {
                return;
            }

            const copyKey = target.dataset.copyKey;
            if (copyKey) {
                const text = copyStore.get(copyKey);
                if (text) {
                    navigator.clipboard.writeText(text);
                }
            }
        });

        document.getElementById('pem-to-der-btn').addEventListener('click', () => {
            postConvertAction('pemToDer');
        });
        document.getElementById('der-to-pem-btn').addEventListener('click', () => {
            postConvertAction('derToPem');
        });
        document.getElementById('inspect-pkcs12-btn').addEventListener('click', () => {
            postConvertAction('inspectPkcs12');
        });
        document.getElementById('inspect-pkcs7-btn').addEventListener('click', () => {
            postConvertAction('inspectPkcs7');
        });
        document.getElementById('inspect-csr-btn').addEventListener('click', () => {
            postConvertAction('inspectCsr');
        });
        document.getElementById('build-pkcs12-btn').addEventListener('click', () => {
            postConvertAction('buildPkcs12');
        });

        document.getElementById('jks-list-btn').addEventListener('click', () => {
            postKeystoreAction('listAliases');
        });
        document.getElementById('jks-export-btn').addEventListener('click', () => {
            postKeystoreAction('exportCert');
        });
        document.getElementById('jks-convert-btn').addEventListener('click', () => {
            postKeystoreAction('convertToPkcs12');
        });
        document.getElementById('export-pem-pair-btn').addEventListener('click', () => {
            postKeystoreAction('exportPemPair');
        });

        window.addEventListener('message', (event) => {
            const message = event.data;
            switch (message.command) {
                case 'capabilities':
                    renderCapabilities(message.payload);
                    return;
                case 'pathSelected':
                    document.getElementById(message.target).value = message.path;
                    return;
                case 'activateTab':
                    setActiveTab(message.tab);
                    return;
                case 'convertResult':
                    setActiveTab('convert');
                    renderTextResult('convert-result', message.payload, 'Conversion Result');
                    return;
                case 'keystoreResult':
                    setActiveTab('keystore');
                    renderTextResult('keystore-result', message.payload, 'Keystore Result');
                    return;
                case 'error':
                    showError(message.payload);
                    return;
            }
        });

        vscode.postMessage({ command: 'ready' });
    </script>
</body>
</html>`;
    }
}
