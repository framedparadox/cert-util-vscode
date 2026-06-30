import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import {
    CertificateArtifactKind,
    ExternalToolAvailability,
    ParsedCertificateArtifact,
    ParsedCertificateDetails,
    ValidationPurpose,
    analyzeCertificateChain,
    parseCertificateInputFromFile,
    parseCertificateInputFromText,
    validateArtifact,
} from '../certificates/certificateUtils';
import { detectExternalToolAvailability, inspectRemoteCertificate, verifyWithOpenSsl } from '../certificates/externalTools';
import { getConfig } from '../config';

interface LaunchRequest {
    type: 'inspect-active' | 'inspect-file' | 'inspect-remote' | 'open-tab';
    initialTab?: ToolTab;
    filePath?: string;
    remoteTarget?: string;
}

type ToolTab = 'inspect' | 'validate' | 'chain' | 'remote';
const PICK_TARGETS = new Set(['inspect-file-path', 'validate-ca-file', 'validate-ca-path']);
const VALIDATION_PURPOSES = new Set<ValidationPurpose>(['serverAuth', 'clientAuth', 'codeSigning', 'emailProtection']);
const MAX_WEBVIEW_TEXT_BYTES = 1024 * 1024;
const MAX_PASTED_TEXT_BYTES = 512 * 1024;

function isWebviewMessage(value: unknown): value is Record<string, unknown> & { command: string } {
    return typeof value === 'object' && value !== null && typeof (value as { command?: unknown }).command === 'string';
}

function optionalString(value: unknown): string | undefined {
    return typeof value === 'string' ? value : undefined;
}

interface WebviewArtifactCertificate {
    summary: {
        subjectCommonName: string;
        issuerCommonName: string;
        serialNumber: string;
        validFrom: string;
        validTo: string;
        type: string;
        format: string;
        isCertificateAuthority: boolean;
        isSelfSigned: boolean;
    };
    identity: {
        subject: string;
        issuer: string;
        subjectAltNames: string[];
    };
    usage: {
        keyUsage: string[];
        extendedKeyUsage: string[];
        purposeHints: ValidationPurpose[];
    };
    crypto: {
        fingerprint: string;
        fingerprint256: string;
        fingerprint512: string;
        signatureAlgorithm: string;
        publicKeyAlgorithm: string;
        bits?: number;
    };
    distribution: {
        infoAccessEntries: string[];
        ocspUrls: string[];
        caIssuersUrls: string[];
        crlDistributionPoints: string[];
    };
    extensions: {
        authorityKeyIdentifier?: string;
        subjectKeyIdentifier?: string;
        basicConstraintsPathLength?: number;
        certificatePolicies: string[];
        nameConstraintsPermitted: string[];
        nameConstraintsExcluded: string[];
        hasEmbeddedScts: boolean;
    };
    raw: {
        pem: string;
        json: string;
    };
}

interface WebviewArtifactPayload {
    kind: CertificateArtifactKind;
    encoding: string;
    sourceLabel: string;
    filePath?: string;
    warnings: string[];
    blockTypes: string[];
    certificates: WebviewArtifactCertificate[];
    chain?: WebviewChainPayload;
}

interface WebviewChainPayload {
    entries: Array<{
        index: number;
        role: string;
        subjectCommonName: string;
        issuerCommonName: string;
        serialNumber: string;
        isSelfSigned: boolean;
        signatureVerified?: boolean;
    }>;
    warnings: string[];
    duplicateSerialNumbers: string[];
    leafIndex?: number;
    rootIndex?: number;
}

export class CertificatePanel {
    private static currentPanel: CertificatePanel | undefined;

    private readonly panel: vscode.WebviewPanel;
    private readonly disposables: vscode.Disposable[] = [];
    private readonly capabilities: Promise<ExternalToolAvailability>;
    private currentArtifact: ParsedCertificateArtifact | undefined;
    private pendingLaunchRequest?: LaunchRequest;

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
                        if (this.currentArtifact) {
                            this.panel.webview.postMessage({
                                command: 'artifactInspected',
                                payload: this.serializeArtifact(this.currentArtifact),
                            });
                        }
                        await this.runPendingLaunchRequest();
                        return;
                    case 'pickPath':
                        if (
                            typeof message.target === 'string' &&
                            PICK_TARGETS.has(message.target) &&
                            (message.kind === 'file' || message.kind === 'folder')
                        ) {
                            await this.handlePickPath(message.target, message.kind);
                        }
                        return;
                    case 'inspectSource':
                        await this.handleInspectSource(message);
                        return;
                    case 'validateCurrent':
                        await this.handleValidateCurrent(message);
                        return;
                    case 'analyzeCurrent':
                        this.handleAnalyzeCurrent();
                        return;
                    case 'inspectRemote':
                        if (typeof message.target === 'string') {
                            await this.handleInspectRemote(message.target);
                        }
                        return;
                    case 'saveText':
                        if (typeof message.text === 'string' && typeof message.suggestedName === 'string') {
                            await this.handleSaveText(message.text, message.suggestedName);
                        }
                        return;
                }
            },
            null,
            this.disposables
        );
    }

    public static render(extensionUri: vscode.Uri, launchRequest?: LaunchRequest) {
        if (CertificatePanel.currentPanel) {
            CertificatePanel.currentPanel.pendingLaunchRequest = launchRequest;
            CertificatePanel.currentPanel.panel.reveal(vscode.ViewColumn.One);
            void CertificatePanel.currentPanel.postCapabilities();
            void CertificatePanel.currentPanel.runPendingLaunchRequest();
            return;
        }

        const panel = vscode.window.createWebviewPanel('certificatePanel', 'Certificate Tools', vscode.ViewColumn.One, {
            enableScripts: true,
            localResourceRoots: [],
        });

        panel.iconPath = vscode.Uri.joinPath(extensionUri, 'resources', 'icons', 'certificate.svg');
        CertificatePanel.currentPanel = new CertificatePanel(panel, launchRequest);
    }

    public dispose() {
        CertificatePanel.currentPanel = undefined;
        this.panel.dispose();
        while (this.disposables.length) {
            this.disposables.pop()?.dispose();
        }
    }

    private async handlePickPath(target: string, kind: 'file' | 'folder') {
        const selection = await vscode.window.showOpenDialog({
            canSelectFiles: kind === 'file',
            canSelectFolders: kind === 'folder',
            canSelectMany: false,
            openLabel: kind === 'folder' ? 'Select Folder' : 'Select File',
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

    private async handleInspectSource(message: Record<string, unknown>) {
        try {
            let artifact: ParsedCertificateArtifact;
            const sourceMode = message.sourceMode;
            const filePath = optionalString(message.filePath);
            const text = optionalString(message.text);
            switch (message.sourceMode) {
                case 'file':
                    if (!filePath?.trim()) {
                        throw new Error('Choose a file to inspect.');
                    }
                    artifact = parseCertificateInputFromFile(filePath.trim());
                    break;
                case 'active':
                    artifact = this.parseActiveEditorArtifact();
                    break;
                case 'paste':
                    if (!text?.trim()) {
                        throw new Error('Paste certificate content to inspect.');
                    }
                    if (Buffer.byteLength(text) > MAX_PASTED_TEXT_BYTES) {
                        throw new Error(`Pasted content exceeds the ${MAX_PASTED_TEXT_BYTES / 1024} KB limit. Use a file path instead.`);
                    }
                    artifact = parseCertificateInputFromText(text, {
                        kind: 'pasted',
                        label: 'Pasted input',
                    });
                    break;
                default:
                    throw new Error(`Unsupported inspection source: ${String(sourceMode)}`);
            }

            this.currentArtifact = artifact;
            this.panel.webview.postMessage({
                command: 'artifactInspected',
                payload: this.serializeArtifact(artifact),
            });
        } catch (error) {
            this.postError('inspect', 'Inspection failed.', error);
        }
    }

    private async handleValidateCurrent(message: Record<string, unknown>) {
        if (!this.currentArtifact) {
            this.postError('validate', 'No certificate is loaded.', 'Inspect a certificate or chain first.');
            return;
        }

        const hostname = optionalString(message.hostname)?.trim() || undefined;
        const purpose =
            typeof message.purpose === 'string' && VALIDATION_PURPOSES.has(message.purpose as ValidationPurpose)
                ? (message.purpose as ValidationPurpose)
                : undefined;
        const caFile = optionalString(message.caFile)?.trim() || undefined;
        const caPath = optionalString(message.caPath)?.trim() || undefined;
        const validation = validateArtifact(this.currentArtifact, {
            hostname,
            purpose,
            warningThresholdDays: getConfig().expiryWarningDays,
        });

        const issues = [...validation.issues];
        let command = '';
        let rawOutput = '';

        if (caFile || caPath) {
            // Select the leaf the same way validateArtifact does (via chain.leafIndex) so OpenSSL
            // trust verification and the native checks operate on the same certificate even when
            // the bundle is out of order. Every other certificate is treated as an untrusted
            // intermediate.
            const certificates = this.currentArtifact.certificates;
            const leafIndex = this.currentArtifact.chain?.leafIndex ?? 0;
            const leafPem = certificates[leafIndex]?.pem;
            const chainPem = certificates
                .filter((_, index) => index !== leafIndex)
                .map((certificate) => certificate.pem)
                .join('\n');
            if (leafPem) {
                const trustResult = await verifyWithOpenSsl(leafPem, chainPem || undefined, caFile, caPath);
                issues.push(...trustResult.issues);
                command = trustResult.command;
                rawOutput = trustResult.rawOutput;
            }
        }

        if (message.checkRevocation) {
            const certificates = this.currentArtifact.certificates;
            const leafIndex = this.currentArtifact.chain?.leafIndex ?? 0;
            const leaf = certificates[leafIndex];
            if (leaf) {
                const issuer = certificates.find((candidate, index) => index !== leafIndex && candidate.subject === leaf.issuer);
                // Loaded on demand so pkijs/asn1js are not evaluated unless a revocation check is run.
                const { checkRevocation } = await import('../certificates/revocation.js');
                const revocation = await checkRevocation(leaf.pem, issuer?.pem);
                issues.push({
                    severity: revocation.status === 'revoked' ? 'error' : 'info',
                    code: `revocation-${revocation.status}`,
                    message: `Revocation check (${revocation.method}): ${revocation.detail}`,
                });
            }
        }

        const valid = !issues.some((issue) => issue.severity === 'error');
        this.panel.webview.postMessage({
            command: 'validationResult',
            payload: {
                status: validation.status,
                valid,
                // Recompute summary to reflect any additional issues (e.g. from OpenSSL trust
                // verification) that were added after the initial validateArtifact call.
                summary: valid ? 'Certificate validation passed with no errors.' : 'Certificate validation detected one or more errors.',
                issues,
                command,
                rawOutput,
            },
        });
    }

    private handleAnalyzeCurrent() {
        if (!this.currentArtifact?.certificates.length) {
            this.postError('chain', 'No certificate chain is loaded.', 'Inspect a certificate bundle or remote endpoint first.');
            return;
        }

        const chain = analyzeCertificateChain(this.currentArtifact.certificates);
        this.panel.webview.postMessage({
            command: 'chainResult',
            payload: chain ? this.serializeChain(chain) : undefined,
        });
    }

    private async handleInspectRemote(target: string) {
        try {
            const result = await inspectRemoteCertificate(target);
            this.currentArtifact = result.artifact;
            this.panel.webview.postMessage({
                command: 'remoteResult',
                payload: {
                    artifact: this.serializeArtifact(result.artifact),
                    command: result.command,
                    rawOutput: result.rawOutput,
                    warnings: result.warnings,
                },
            });
        } catch (error) {
            this.postError('remote', 'Remote inspection failed.', error);
        }
    }

    private async handleSaveText(text: string, suggestedName: string) {
        try {
            if (Buffer.byteLength(text) > MAX_WEBVIEW_TEXT_BYTES) {
                throw new Error('The requested output exceeds the 1 MB save limit.');
            }

            const safeName = path.basename(suggestedName) || 'certificate.txt';
            const target = await vscode.window.showSaveDialog({
                defaultUri: vscode.Uri.file(path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '', safeName)),
                saveLabel: 'Save Output',
            });
            if (!target) {
                return;
            }

            await vscode.workspace.fs.writeFile(target, Buffer.from(text, 'utf8'));
            void vscode.window.showInformationMessage(`Saved ${path.basename(target.fsPath)}`);
        } catch (error) {
            this.postError('inspect', 'Save failed.', error);
        }
    }

    private parseActiveEditorArtifact(): ParsedCertificateArtifact {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            throw new Error('No active editor is open.');
        }

        const document = editor.document;
        const text = document.getText();
        if (!document.isDirty && document.uri.scheme === 'file' && fs.existsSync(document.uri.fsPath)) {
            return parseCertificateInputFromFile(document.uri.fsPath, 'active-editor');
        }

        if (!text.trim()) {
            throw new Error('The active editor is empty.');
        }
        if (Buffer.byteLength(text) > MAX_WEBVIEW_TEXT_BYTES) {
            throw new Error('The active editor exceeds the 1 MB inspection limit. Choose the certificate file instead.');
        }

        return parseCertificateInputFromText(text, {
            kind: 'active-editor',
            label: `Active editor: ${document.fileName || document.uri.toString()}`,
        });
    }

    private async postCapabilities() {
        this.panel.webview.postMessage({
            command: 'capabilities',
            payload: await this.capabilities,
        });
    }

    private async runPendingLaunchRequest() {
        const request = this.pendingLaunchRequest;
        if (!request) {
            return;
        }

        this.pendingLaunchRequest = undefined;

        try {
            if (request.initialTab) {
                this.panel.webview.postMessage({
                    command: 'activateTab',
                    tab: request.initialTab,
                });
            }

            switch (request.type) {
                case 'open-tab':
                    return;
                case 'inspect-active':
                    this.currentArtifact = this.parseActiveEditorArtifact();
                    this.panel.webview.postMessage({
                        command: 'artifactInspected',
                        payload: this.serializeArtifact(this.currentArtifact),
                    });
                    return;
                case 'inspect-file':
                    if (!request.filePath) {
                        return;
                    }
                    this.currentArtifact = parseCertificateInputFromFile(request.filePath);
                    this.panel.webview.postMessage({
                        command: 'artifactInspected',
                        payload: this.serializeArtifact(this.currentArtifact),
                    });
                    return;
                case 'inspect-remote':
                    if (!request.remoteTarget) {
                        return;
                    }
                    await this.handleInspectRemote(request.remoteTarget);
                    return;
            }
        } catch (error) {
            this.postError('inspect', 'Automatic inspection failed.', error);
        }
    }

    private serializeArtifact(artifact: ParsedCertificateArtifact): WebviewArtifactPayload {
        return {
            kind: artifact.kind,
            encoding: artifact.encoding,
            sourceLabel: artifact.source.label,
            filePath: artifact.filePath,
            warnings: artifact.warnings,
            blockTypes: artifact.blockTypes,
            certificates: artifact.certificates.map((certificate) => this.serializeCertificate(certificate)),
            chain: artifact.chain ? this.serializeChain(artifact.chain) : undefined,
        };
    }

    private serializeCertificate(certificate: ParsedCertificateDetails): WebviewArtifactCertificate {
        return {
            summary: {
                subjectCommonName: certificate.subjectCommonName,
                issuerCommonName: certificate.issuerCommonName,
                serialNumber: certificate.serialNumber,
                validFrom: certificate.validFrom,
                validTo: certificate.validTo,
                type: certificate.type,
                format: certificate.format,
                isCertificateAuthority: certificate.isCertificateAuthority,
                isSelfSigned: certificate.isSelfSigned,
            },
            identity: {
                subject: certificate.subject,
                issuer: certificate.issuer,
                subjectAltNames: certificate.subjectAltNames,
            },
            usage: {
                keyUsage: certificate.keyUsage,
                extendedKeyUsage: certificate.extendedKeyUsage,
                purposeHints: certificate.purposeHints,
            },
            crypto: {
                fingerprint: certificate.fingerprint,
                fingerprint256: certificate.fingerprint256,
                fingerprint512: certificate.fingerprint512,
                signatureAlgorithm: certificate.signatureAlgorithm,
                publicKeyAlgorithm: certificate.publicKeyAlgorithm,
                bits: certificate.bits,
            },
            distribution: {
                infoAccessEntries: certificate.infoAccessEntries,
                ocspUrls: certificate.ocspUrls,
                caIssuersUrls: certificate.caIssuersUrls,
                crlDistributionPoints: certificate.crlDistributionPoints,
            },
            extensions: {
                authorityKeyIdentifier: certificate.authorityKeyIdentifier,
                subjectKeyIdentifier: certificate.subjectKeyIdentifier,
                basicConstraintsPathLength: certificate.basicConstraintsPathLength,
                certificatePolicies: certificate.certificatePolicies,
                nameConstraintsPermitted: certificate.nameConstraintsPermitted,
                nameConstraintsExcluded: certificate.nameConstraintsExcluded,
                hasEmbeddedScts: certificate.hasEmbeddedScts,
            },
            raw: {
                pem: certificate.pem,
                json: JSON.stringify(certificate, null, 2),
            },
        };
    }

    private serializeChain(chain: NonNullable<ParsedCertificateArtifact['chain']>): WebviewChainPayload {
        return {
            entries: chain.entries,
            warnings: chain.warnings,
            duplicateSerialNumbers: chain.duplicateSerialNumbers,
            leafIndex: chain.leafIndex,
            rootIndex: chain.rootIndex,
        };
    }

    private postError(tab: string, summary: string, error: unknown) {
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
    <title>Certificate Tools</title>
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
        .capabilities {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
            margin-top: 12px;
        }
        .capability,
        .panel,
        .result-panel {
            border: 1px solid var(--vscode-panel-border);
            border-radius: 10px;
            background: var(--vscode-sideBar-background);
        }
        .capability,
        .panel,
        .result-panel {
            padding: 14px;
        }
        .tabs {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
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
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
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
        textarea,
        select,
        button {
            font: inherit;
        }
        input,
        textarea,
        select {
            width: 100%;
            padding: 9px 10px;
            border: 1px solid var(--vscode-input-border);
            border-radius: 8px;
            background: var(--vscode-input-background);
            color: var(--vscode-input-foreground);
        }
        textarea {
            min-height: 160px;
            resize: vertical;
        }
        .actions {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 6px;
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
            margin-bottom: 10px;
        }
        .muted {
            color: var(--vscode-descriptionForeground);
        }
        .issue-list,
        .warning-list,
        .chip-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin: 0;
            padding: 0;
            list-style: none;
        }
        .badge,
        .chip,
        .issue {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 4px 10px;
            font-size: 11px;
            font-weight: 600;
            border-radius: 12px;
            border: 1px solid;
        }
        .badge.valid,
        .issue.valid,
        .issue.info {
            background-color: var(--vscode-diffEditor-insertedTextBackground, transparent);
            color: var(--vscode-testing-iconPassed, var(--vscode-charts-green));
            border-color: var(--vscode-testing-iconPassed, var(--vscode-charts-green));
        }
        .badge.expiring,
        .issue.warning {
            background-color: var(--vscode-inputValidation-warningBackground, transparent);
            color: var(--vscode-editorWarning-foreground);
            border-color: var(--vscode-inputValidation-warningBorder, var(--vscode-editorWarning-foreground));
        }
        .badge.expired,
        .issue.error {
            background-color: var(--vscode-inputValidation-errorBackground, transparent);
            color: var(--vscode-editorError-foreground);
            border-color: var(--vscode-inputValidation-errorBorder, var(--vscode-editorError-foreground));
        }
        .badge-icon {
            width: 12px;
            height: 12px;
            flex: 0 0 auto;
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
        .kv {
            display: grid;
            grid-template-columns: minmax(140px, 220px) 1fr;
            gap: 8px 12px;
        }
        .kv strong {
            color: var(--vscode-descriptionForeground);
        }
        .info-footer {
            margin-top: 12px;
        }
        .info-toggle {
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .doc-panel {
            margin-top: 10px;
            border: 1px dashed var(--vscode-panel-border);
            border-radius: 10px;
            padding: 12px;
            background: color-mix(in srgb, var(--vscode-sideBar-background) 82%, transparent);
        }
        .doc-panel h4 {
            margin: 0 0 8px;
        }
        .doc-panel p,
        .doc-panel ul {
            margin: 0 0 8px;
        }
        .doc-panel ul {
            padding-left: 18px;
        }
        @media (max-width: 720px) {
            .kv {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <h1>Certificate Tools</h1>
    <p class="lead">Inspect certificates and bundles, validate hostname and purpose, analyze chains, and fetch remote TLS certificates without leaving VS Code.</p>

    <div class="tabs" role="tablist" aria-label="Certificate tools">
        <button id="inspect-tab" class="tab active" type="button" role="tab" aria-selected="true" aria-controls="inspect" data-tab="inspect">Inspect</button>
        <button id="validate-tab" class="tab" type="button" role="tab" aria-selected="false" aria-controls="validate" tabindex="-1" data-tab="validate">Validate</button>
        <button id="chain-tab" class="tab" type="button" role="tab" aria-selected="false" aria-controls="chain" tabindex="-1" data-tab="chain">Chain</button>
        <button id="remote-tab" class="tab" type="button" role="tab" aria-selected="false" aria-controls="remote" tabindex="-1" data-tab="remote">Remote</button>
    </div>

    <section class="tab-content active" id="inspect" role="tabpanel" aria-labelledby="inspect-tab">
        <div class="panel">
            <div class="grid">
                <div class="field-wide">
                    <label for="inspect-file-path">Certificate File</label>
                    <input id="inspect-file-path" type="text" maxlength="4096" placeholder="/path/to/certificate.crt or bundle.p12">
                    <div class="actions">
                        <button class="secondary" data-pick-target="inspect-file-path" data-pick-kind="file">Choose File</button>
                    </div>
                </div>
                <div class="field-wide">
                    <label for="inspect-text">Certificate, Bundle, CSR, or Key</label>
                    <textarea id="inspect-text" maxlength="${MAX_PASTED_TEXT_BYTES}" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
                </div>
            </div>
            <div class="actions">
                <button id="inspect-btn">Inspect</button>
                <button class="secondary" id="clear-inspect-btn">Clear</button>
            </div>
        </div>
        <div class="result-panel" id="inspect-result" aria-live="polite"></div>
        <div class="info-footer">
            <button class="ghost info-toggle" type="button" aria-expanded="false" aria-controls="inspect-docs" data-doc-target="inspect-docs">Info</button>
            <div class="doc-panel" id="inspect-docs" hidden>
                <h4>Inspect Tool Details</h4>
                <p>Use this tool to classify the current artifact before validation or chain analysis. It accepts pasted text or a picked file.</p>
                <ul>
                    <li>Best for PEM, DER, certificate bundles, CSRs, private keys, PKCS#7, PKCS#12, and JKS detection.</li>
                    <li>Structured output shows subject, issuer, SANs, usage, fingerprints, and raw PEM or JSON views.</li>
                    <li>If a bundle contains multiple certificates, each entry is shown separately and chain warnings are surfaced below the result.</li>
                </ul>
                <div class="capabilities" id="capabilities"></div>
            </div>
        </div>
    </section>

    <section class="tab-content" id="validate" role="tabpanel" aria-labelledby="validate-tab" hidden>
        <div class="panel">
            <div class="grid">
                <div class="field">
                    <label for="validate-hostname">Hostname</label>
                    <input id="validate-hostname" type="text" maxlength="253" placeholder="example.com">
                </div>
                <div class="field">
                    <label for="validate-purpose">Purpose</label>
                    <select id="validate-purpose">
                        <option value="">None</option>
                        <option value="serverAuth">serverAuth</option>
                        <option value="clientAuth">clientAuth</option>
                        <option value="codeSigning">codeSigning</option>
                        <option value="emailProtection">emailProtection</option>
                    </select>
                </div>
                <div class="field-wide">
                    <label for="validate-ca-file">CA File (optional)</label>
                    <input id="validate-ca-file" type="text" maxlength="4096" placeholder="/path/to/ca.pem">
                    <div class="actions">
                        <button class="secondary" data-pick-target="validate-ca-file" data-pick-kind="file">Choose CA File</button>
                    </div>
                </div>
                <div class="field-wide">
                    <label for="validate-ca-path">CA Directory (optional)</label>
                    <input id="validate-ca-path" type="text" maxlength="4096" placeholder="/path/to/ca-directory">
                    <div class="actions">
                        <button class="secondary" data-pick-target="validate-ca-path" data-pick-kind="folder">Choose CA Directory</button>
                    </div>
                </div>
            </div>
            <div class="field-wide">
                <label><input id="validate-revocation" type="checkbox"> Check revocation online (OCSP/CRL)</label>
            </div>
            <div class="actions">
                <button id="validate-btn">Validate Current Artifact</button>
            </div>
        </div>
        <div class="result-panel" id="validate-result" aria-live="polite"></div>
        <div class="info-footer">
            <button class="ghost info-toggle" type="button" aria-expanded="false" aria-controls="validate-docs" data-doc-target="validate-docs">Info</button>
            <div class="doc-panel" id="validate-docs" hidden>
                <h4>Validate Tool Details</h4>
                <p>Validation works on the currently loaded artifact. Inspect a certificate or bundle first, then optionally add hostname, purpose, or CA trust inputs.</p>
                <ul>
                    <li>Checks validity dates, self-signed status, CA vs leaf usage, hostname matching, and EKU purpose hints.</li>
                    <li>Optional CA file or CA directory inputs trigger OpenSSL trust verification when OpenSSL is available.</li>
                    <li>Results combine native parsing diagnostics with OpenSSL trust output instead of replacing one with the other.</li>
                </ul>
            </div>
        </div>
    </section>

    <section class="tab-content" id="chain" role="tabpanel" aria-labelledby="chain-tab" hidden>
        <div class="panel">
            <p class="muted">Analyze the currently loaded certificate or chain. The chain view identifies leaf, intermediate, and root candidates, and flags duplicates or missing issuers.</p>
            <div class="actions">
                <button id="chain-btn">Analyze Chain</button>
            </div>
        </div>
        <div class="result-panel" id="chain-result" aria-live="polite"></div>
        <div class="info-footer">
            <button class="ghost info-toggle" type="button" aria-expanded="false" aria-controls="chain-docs" data-doc-target="chain-docs">Info</button>
            <div class="doc-panel" id="chain-docs" hidden>
                <h4>Chain Tool Details</h4>
                <p>Chain analysis helps explain whether a bundle is ordered and complete enough for trust validation.</p>
                <ul>
                    <li>Identifies likely leaf, intermediate, and root roles from subject and issuer relationships.</li>
                    <li>Flags duplicate serial numbers, missing issuers, and out-of-order bundles.</li>
                    <li>Use this before trust verification if a remote chain or pasted bundle looks incomplete.</li>
                </ul>
            </div>
        </div>
    </section>

    <section class="tab-content" id="remote" role="tabpanel" aria-labelledby="remote-tab" hidden>
        <div class="panel">
            <div class="grid">
                <div class="field-wide">
                    <label for="remote-target">Remote Host[:Port]</label>
                    <input id="remote-target" type="text" maxlength="300" placeholder="example.com:443">
                </div>
            </div>
            <div class="actions">
                <button id="remote-inspect-btn">Fetch Remote Certificate Chain</button>
            </div>
        </div>
        <div class="result-panel" id="remote-result" aria-live="polite"></div>
        <div class="info-footer">
            <button class="ghost info-toggle" type="button" aria-expanded="false" aria-controls="remote-docs" data-doc-target="remote-docs">Info</button>
            <div class="doc-panel" id="remote-docs" hidden>
                <h4>Remote Tool Details</h4>
                <p>Remote inspection uses OpenSSL <code>s_client</code> to fetch the presented TLS chain for a host and port.</p>
                <ul>
                    <li>Default port is 443 when no port is provided.</li>
                    <li>SNI is sent using the host portion of the endpoint so the returned chain matches virtual-hosted services more reliably.</li>
                    <li>The fetched chain is parsed back into the same inspection and chain views used for local artifacts.</li>
                </ul>
            </div>
        </div>
    </section>

    <script nonce="${nonce}">
        const vscode = acquireVsCodeApi();
        const copyStore = new Map();
        let copyId = 0;

        // Prune stale copy-store entries whenever a result panel is re-rendered so the
        // Map does not grow without bound across many inspect/validate cycles.
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

        function renderIssuePill(issue) {
            const kind = issue.severity === 'error' ? 'error' : (issue.severity === 'warning' ? 'warning' : 'valid');
            return '<li>' + renderStatusPill(kind, issue.message) + '</li>';
        }

        function renderArtifact(hostId, payload) {
            clearCopyStore();
            const host = document.getElementById(hostId);
            const warnings = payload.warnings.length
                ? '<div class="section-card"><h4>Warnings</h4><ul class="warning-list">' +
                    payload.warnings.map((warning) => '<li>' + renderStatusPill('warning', warning) + '</li>').join('') +
                    '</ul></div>'
                : '';

            const certificates = payload.certificates.length
                ? payload.certificates.map((certificate, index) => renderCertificateCard(certificate, index)).join('')
                : '<div class="section-card"><h4>Artifact Classification</h4><p class="muted">Detected kind: <strong>' + escapeHtml(payload.kind) + '</strong>. Block types: ' + escapeHtml(payload.blockTypes.join(', ') || 'none') + '.</p></div>';

            const chain = payload.chain ? renderChainCard(payload.chain) : '';
            host.innerHTML =
                '<h3>Inspection Result</h3>' +
                '<p class="muted">Kind: <strong>' + escapeHtml(payload.kind) + '</strong> · Encoding: <strong>' + escapeHtml(payload.encoding) + '</strong> · Source: ' + escapeHtml(payload.sourceLabel) + '</p>' +
                (payload.filePath ? '<p class="muted">File: ' + escapeHtml(payload.filePath) + '</p>' : '') +
                warnings +
                certificates +
                chain;
        }

        function renderExtensionsCard(extensions) {
            if (!extensions) {
                return '';
            }
            const pathLen = typeof extensions.basicConstraintsPathLength === 'number'
                ? String(extensions.basicConstraintsPathLength)
                : 'None';
            return '<div class="section-card"><h4>Extensions</h4><div class="kv">' +
                '<strong>Subject Key ID</strong><span>' + escapeHtml(extensions.subjectKeyIdentifier || 'None') + '</span>' +
                '<strong>Authority Key ID</strong><span>' + escapeHtml(extensions.authorityKeyIdentifier || 'None') + '</span>' +
                '<strong>Path Length</strong><span>' + escapeHtml(pathLen) + '</span>' +
                '<strong>Certificate Policies</strong><span>' + escapeHtml(extensions.certificatePolicies.join(', ') || 'None') + '</span>' +
                '<strong>Name Constraints (Permitted)</strong><span>' + escapeHtml(extensions.nameConstraintsPermitted.join(', ') || 'None') + '</span>' +
                '<strong>Name Constraints (Excluded)</strong><span>' + escapeHtml(extensions.nameConstraintsExcluded.join(', ') || 'None') + '</span>' +
                '<strong>Certificate Transparency</strong><span>' + escapeHtml(extensions.hasEmbeddedScts ? 'Embedded SCTs present' : 'None') + '</span>' +
                '</div></div>';
        }

        function renderCertificateCard(certificate, index) {
            const pemKey = stashCopy(certificate.raw.pem);
            const jsonKey = stashCopy(certificate.raw.json);
            const fpKey = stashCopy(certificate.crypto.fingerprint256 || certificate.crypto.fingerprint);
            return '<div class="section-card">' +
                '<h4>Certificate ' + (index + 1) + ': ' + escapeHtml(certificate.summary.subjectCommonName || 'Unknown Subject') + '</h4>' +
                '<div class="kv">' +
                    '<strong>Issuer</strong><span>' + escapeHtml(certificate.summary.issuerCommonName) + '</span>' +
                    '<strong>Serial Number</strong><span>' + escapeHtml(certificate.summary.serialNumber) + '</span>' +
                    '<strong>Valid From</strong><span>' + escapeHtml(certificate.summary.validFrom) + '</span>' +
                    '<strong>Valid To</strong><span>' + escapeHtml(certificate.summary.validTo) + '</span>' +
                    '<strong>Type</strong><span>' + escapeHtml(certificate.summary.type) + '</span>' +
                    '<strong>Public Key</strong><span>' + escapeHtml(certificate.crypto.publicKeyAlgorithm + (certificate.crypto.bits ? ' (' + certificate.crypto.bits + ' bits)' : '')) + '</span>' +
                    '<strong>Signature Algorithm</strong><span>' + escapeHtml(certificate.crypto.signatureAlgorithm) + '</span>' +
                    '<strong>Self-Signed</strong><span>' + escapeHtml(String(certificate.summary.isSelfSigned)) + '</span>' +
                    '<strong>CA</strong><span>' + escapeHtml(String(certificate.summary.isCertificateAuthority)) + '</span>' +
                '</div>' +
                '<div class="section-card"><h4>Identity</h4><div class="kv">' +
                    '<strong>Subject</strong><span>' + escapeHtml(certificate.identity.subject) + '</span>' +
                    '<strong>Issuer</strong><span>' + escapeHtml(certificate.identity.issuer) + '</span>' +
                    '<strong>SANs</strong><span>' + escapeHtml(certificate.identity.subjectAltNames.join(', ') || 'None') + '</span>' +
                '</div></div>' +
                '<div class="section-card"><h4>Usage</h4><div class="kv">' +
                    '<strong>Key Usage</strong><span>' + escapeHtml(certificate.usage.keyUsage.join(', ') || 'None') + '</span>' +
                    '<strong>Extended Key Usage</strong><span>' + escapeHtml(certificate.usage.extendedKeyUsage.join(', ') || 'None') + '</span>' +
                    '<strong>Purpose Hints</strong><span>' + escapeHtml(certificate.usage.purposeHints.join(', ') || 'None') + '</span>' +
                '</div></div>' +
                '<div class="section-card"><h4>Fingerprints</h4><div class="kv">' +
                    '<strong>SHA-1</strong><span>' + escapeHtml(certificate.crypto.fingerprint) + '</span>' +
                    '<strong>SHA-256</strong><span>' + escapeHtml(certificate.crypto.fingerprint256) + '</span>' +
                    '<strong>SHA-512</strong><span>' + escapeHtml(certificate.crypto.fingerprint512) + '</span>' +
                '</div></div>' +
                '<div class="section-card"><h4>Distribution and Access</h4><div class="kv">' +
                    '<strong>Info Access</strong><span>' + escapeHtml(certificate.distribution.infoAccessEntries.join(', ') || 'None') + '</span>' +
                    '<strong>OCSP</strong><span>' + escapeHtml(certificate.distribution.ocspUrls.join(', ') || 'None') + '</span>' +
                    '<strong>CA Issuers</strong><span>' + escapeHtml(certificate.distribution.caIssuersUrls.join(', ') || 'None') + '</span>' +
                    '<strong>CRL Distribution</strong><span>' + escapeHtml(certificate.distribution.crlDistributionPoints.join(', ') || 'None') + '</span>' +
                '</div></div>' +
                renderExtensionsCard(certificate.extensions) +
                '<div class="actions">' +
                    '<button class="secondary" data-copy-key="' + pemKey + '">Copy PEM</button>' +
                    '<button class="secondary" data-copy-key="' + jsonKey + '">Copy JSON</button>' +
                    '<button class="secondary" data-copy-key="' + fpKey + '">Copy Fingerprint</button>' +
                    '<button class="ghost" data-save-text="' + pemKey + '" data-save-name="certificate-' + (index + 1) + '.pem">Save PEM</button>' +
                '</div>' +
            '</div>';
        }

        function renderChainCard(chain) {
            const entries = chain.entries.map((entry) => {
                const signature = entry.signatureVerified === true
                    ? renderStatusPill('valid', 'Signature verified')
                    : entry.signatureVerified === false
                        ? renderStatusPill('error', 'Signature NOT verified')
                        : renderStatusPill('warning', 'Issuer not in chain');
                return '<div class="section-card">' +
                    '<h4>Entry ' + (entry.index + 1) + '</h4>' +
                    '<div class="kv">' +
                        '<strong>Role</strong><span>' + escapeHtml(entry.role) + '</span>' +
                        '<strong>Subject</strong><span>' + escapeHtml(entry.subjectCommonName) + '</span>' +
                        '<strong>Issuer</strong><span>' + escapeHtml(entry.issuerCommonName) + '</span>' +
                        '<strong>Serial</strong><span>' + escapeHtml(entry.serialNumber) + '</span>' +
                        '<strong>Signature</strong><span>' + signature + '</span>' +
                    '</div>' +
                '</div>';
            }).join('');
            const warnings = chain.warnings.length
                ? '<ul class="warning-list">' + chain.warnings.map((warning) => '<li>' + renderStatusPill('warning', warning) + '</li>').join('') + '</ul>'
                : '<p class="muted">No chain warnings.</p>';
            return '<div class="section-card"><h4>Chain Analysis</h4>' +
                '<p class="muted">Leaf index: ' + escapeHtml(String(chain.leafIndex ?? 'n/a')) + ' · Root index: ' + escapeHtml(String(chain.rootIndex ?? 'n/a')) + '</p>' +
                warnings +
                entries +
            '</div>';
        }

        function renderValidation(payload) {
            clearCopyStore();
            const host = document.getElementById('validate-result');
            const commandKey = payload.command ? stashCopy(payload.command) : undefined;
            const statusKind = payload.valid ? 'valid' : 'error';
            const issues = payload.issues.length
                ? payload.issues.map((issue) => renderIssuePill(issue)).join('')
                : '<li>' + renderStatusPill('valid', 'Valid') + '</li>';
            host.innerHTML =
                '<h3>Validation Result</h3>' +
                renderStatusPill(statusKind, payload.valid ? 'Valid' : 'Error') +
                '<p class="muted">' + escapeHtml(payload.summary) + '</p>' +
                '<ul class="issue-list">' +
                issues +
                '</ul>' +
                (payload.command ? '<div class="section-card"><h4>OpenSSL Command</h4><pre>' + escapeHtml(payload.command) + '</pre><div class="actions"><button class="secondary" data-copy-key="' + commandKey + '">Copy Command</button></div></div>' : '') +
                (payload.rawOutput ? '<div class="section-card"><h4>Verifier Output</h4><pre>' + escapeHtml(payload.rawOutput) + '</pre></div>' : '');
        }

        function renderChain(payload) {
            const host = document.getElementById('chain-result');
            host.innerHTML = payload ? '<h3>Chain Result</h3>' + renderChainCard(payload) : '<h3>Chain Result</h3><p class="muted">No chain data is available.</p>';
        }

        function showError(payload) {
            const host = document.getElementById(payload.tab + '-result');
            if (!host) {
                return;
            }
            host.innerHTML = '<h3>Error</h3>' + renderStatusPill('error', payload.summary) + '<pre>' + escapeHtml(payload.detail) + '</pre>';
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

        document.querySelectorAll('.info-toggle').forEach((button) => {
            button.addEventListener('click', () => {
                const panel = document.getElementById(button.dataset.docTarget);
                if (!panel) {
                    return;
                }

                const shouldShow = panel.hasAttribute('hidden');
                if (shouldShow) {
                    panel.removeAttribute('hidden');
                    button.textContent = 'Hide Info';
                } else {
                    panel.setAttribute('hidden', '');
                    button.textContent = 'Info';
                }
                button.setAttribute('aria-expanded', String(shouldShow));
            });
        });

        document.querySelectorAll('[data-pick-target]').forEach((button) => {
            button.addEventListener('click', () => {
                vscode.postMessage({
                    command: 'pickPath',
                    target: button.dataset.pickTarget,
                    kind: button.dataset.pickKind,
                });
            });
        });

        document.addEventListener('click', (event) => {
            const target = event.target;
            if (!(target instanceof HTMLElement)) {
                return;
            }

            const copyKey = target.dataset.copyKey;
            const saveText = target.dataset.saveText;
            if (copyKey) {
                const text = copyStore.get(copyKey);
                if (text) {
                    navigator.clipboard.writeText(text);
                }
                return;
            }

            if (saveText) {
                const text = copyStore.get(saveText);
                if (text) {
                    vscode.postMessage({
                        command: 'saveText',
                        text,
                        suggestedName: target.dataset.saveName || 'certificate.txt',
                    });
                }
            }
        });

        document.getElementById('inspect-btn').addEventListener('click', () => {
            const filePath = document.getElementById('inspect-file-path').value;
            const text = document.getElementById('inspect-text').value;
            vscode.postMessage({
                command: 'inspectSource',
                sourceMode: filePath.trim() ? 'file' : 'paste',
                text,
                filePath,
            });
        });

        document.getElementById('clear-inspect-btn').addEventListener('click', () => {
            document.getElementById('inspect-text').value = '';
            document.getElementById('inspect-file-path').value = '';
            document.getElementById('inspect-result').innerHTML = '';
        });

        document.getElementById('validate-btn').addEventListener('click', () => {
            vscode.postMessage({
                command: 'validateCurrent',
                hostname: document.getElementById('validate-hostname').value,
                purpose: document.getElementById('validate-purpose').value,
                caFile: document.getElementById('validate-ca-file').value,
                caPath: document.getElementById('validate-ca-path').value,
                checkRevocation: document.getElementById('validate-revocation').checked,
            });
        });

        document.getElementById('chain-btn').addEventListener('click', () => {
            vscode.postMessage({ command: 'analyzeCurrent' });
        });

        document.getElementById('remote-inspect-btn').addEventListener('click', () => {
            vscode.postMessage({
                command: 'inspectRemote',
                target: document.getElementById('remote-target').value,
            });
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
                case 'artifactInspected':
                    setActiveTab('inspect');
                    renderArtifact('inspect-result', message.payload);
                    return;
                case 'validationResult':
                    setActiveTab('validate');
                    renderValidation(message.payload);
                    return;
                case 'chainResult':
                    setActiveTab('chain');
                    renderChain(message.payload);
                    return;
                case 'remoteResult':
                    setActiveTab('remote');
                    renderArtifact('remote-result', message.payload.artifact);
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
