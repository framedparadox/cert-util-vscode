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
import {
    buildDerToPemCommand,
    buildJksExportCommand,
    buildJksToPkcs12Command,
    buildPemToDerCommand,
    buildPkcs12ExportCommand,
    detectExternalToolAvailability,
    inspectPkcs12File,
    inspectPkcs7File,
    inspectRemoteCertificate,
    listJksAliases,
    verifyWithOpenSsl,
} from '../certificates/externalTools';

interface LaunchRequest {
    type: 'inspect-active' | 'inspect-file' | 'inspect-remote' | 'open-tab';
    initialTab?: ToolTab;
    filePath?: string;
    remoteTarget?: string;
}

type ToolTab = 'inspect' | 'validate' | 'chain' | 'convert' | 'keystore' | 'remote';

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
    }>;
    warnings: string[];
    duplicateSerialNumbers: string[];
    leafIndex?: number;
    rootIndex?: number;
}

export class CertificatePanel {
    public static currentPanel: CertificatePanel | undefined;

    private readonly panel: vscode.WebviewPanel;
    private readonly disposables: vscode.Disposable[] = [];
    private readonly capabilities: ExternalToolAvailability;
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
                switch (message.command) {
                    case 'ready':
                        this.postCapabilities();
                        await this.runPendingLaunchRequest();
                        return;
                    case 'pickPath':
                        await this.handlePickPath(message.target, message.kind);
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
                    case 'convertAction':
                        await this.handleConvertAction(message);
                        return;
                    case 'keystoreAction':
                        await this.handleKeystoreAction(message);
                        return;
                    case 'inspectRemote':
                        await this.handleInspectRemote(message.target);
                        return;
                    case 'saveText':
                        await this.handleSaveText(message.text, message.suggestedName);
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
            CertificatePanel.currentPanel.postCapabilities();
            void CertificatePanel.currentPanel.runPendingLaunchRequest();
            return;
        }

        const panel = vscode.window.createWebviewPanel('certificatePanel', 'Certificate Tools', vscode.ViewColumn.One, {
            enableScripts: true,
            retainContextWhenHidden: true,
            localResourceRoots: [extensionUri],
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

    private async handleInspectSource(message: { sourceMode: 'paste' | 'file' | 'active'; text?: string; filePath?: string }) {
        try {
            let artifact: ParsedCertificateArtifact;
            switch (message.sourceMode) {
                case 'file':
                    if (!message.filePath?.trim()) {
                        throw new Error('Choose a file to inspect.');
                    }
                    artifact = parseCertificateInputFromFile(message.filePath.trim());
                    break;
                case 'active':
                    artifact = this.parseActiveEditorArtifact();
                    break;
                case 'paste':
                default:
                    if (!message.text?.trim()) {
                        throw new Error('Paste certificate content to inspect.');
                    }
                    artifact = parseCertificateInputFromText(message.text, {
                        kind: 'pasted',
                        label: 'Pasted input',
                    });
                    break;
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

    private async handleValidateCurrent(message: {
        hostname?: string;
        purpose?: ValidationPurpose;
        caFile?: string;
        caPath?: string;
    }) {
        if (!this.currentArtifact) {
            this.postError('validate', 'No certificate is loaded.', 'Inspect a certificate or chain first.');
            return;
        }

        const validation = validateArtifact(this.currentArtifact, {
            hostname: message.hostname?.trim() || undefined,
            purpose: message.purpose || undefined,
        });

        const issues = [...validation.issues];
        let command = '';
        let rawOutput = '';

        if (message.caFile || message.caPath) {
            const leafPem = this.currentArtifact.certificates[0]?.pem;
            const chainPem = this.currentArtifact.certificates.slice(1).map((certificate) => certificate.pem).join('\n');
            if (leafPem) {
                const trustResult = verifyWithOpenSsl(leafPem, chainPem || undefined, message.caFile, message.caPath);
                issues.push(...trustResult.issues);
                command = trustResult.command;
                rawOutput = trustResult.rawOutput;
            }
        }

        this.panel.webview.postMessage({
            command: 'validationResult',
            payload: {
                status: validation.status,
                valid: !issues.some((issue) => issue.severity === 'error'),
                summary: validation.summary,
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

    private async handleConvertAction(message: {
        action: string;
        password?: string;
        certPath?: string;
        keyPath?: string;
        outputPath?: string;
    }) {
        try {
            switch (message.action) {
                case 'pemToDer':
                    await this.saveCurrentCertificateAsDer();
                    return;
                case 'derToPem':
                    await this.saveCurrentCertificatePem();
                    return;
                case 'inspectPkcs12':
                    await this.handleInspectExternalBundle('pkcs12', message.outputPath, message.password);
                    return;
                case 'inspectPkcs7':
                    await this.handleInspectExternalBundle('pkcs7', message.outputPath);
                    return;
                case 'buildPkcs12':
                    if (!message.certPath?.trim() || !message.keyPath?.trim()) {
                        throw new Error('Certificate path and private key path are required.');
                    }
                    this.postTextResult('convert', {
                        title: 'PKCS#12 Export Command',
                        summary: 'Use this command to build a PKCS#12 bundle from a certificate and private key.',
                        command: buildPkcs12ExportCommand(
                            message.certPath.trim(),
                            message.keyPath.trim(),
                            message.outputPath?.trim() || 'certificate.p12',
                            message.password
                        ),
                    });
                    return;
                case 'inspectCsr':
                    await this.handleInspectCsr();
                    return;
                default:
                    throw new Error(`Unsupported conversion action: ${message.action}`);
            }
        } catch (error) {
            this.postError('convert', 'Conversion action failed.', error);
        }
    }

    private async handleKeystoreAction(message: { action: string; keystorePath?: string; alias?: string; password?: string }) {
        try {
            const keystorePath = message.keystorePath?.trim();
            if (!keystorePath) {
                throw new Error('Keystore path is required.');
            }

            switch (message.action) {
                case 'listAliases': {
                    const result = listJksAliases(keystorePath, message.password);
                    this.postTextResult('keystore', {
                        title: 'JKS Alias Listing',
                        summary: result.summary,
                        command: result.command,
                        body: result.rawOutput,
                    });
                    return;
                }
                case 'exportCert':
                    if (!message.alias?.trim()) {
                        throw new Error('Alias is required to export a certificate.');
                    }
                    this.postTextResult('keystore', {
                        title: 'JKS Export Certificate Command',
                        summary: 'Run this command to export a PEM certificate from the JKS keystore.',
                        command: buildJksExportCommand(keystorePath, message.alias.trim()),
                    });
                    return;
                case 'convertToPkcs12':
                    this.postTextResult('keystore', {
                        title: 'JKS to PKCS#12 Command',
                        summary: 'Run this command to convert the JKS keystore to a PKCS#12 bundle.',
                        command: buildJksToPkcs12Command(keystorePath),
                    });
                    return;
                default:
                    throw new Error(`Unsupported keystore action: ${message.action}`);
            }
        } catch (error) {
            this.postError('keystore', 'Keystore action failed.', error);
        }
    }

    private async handleInspectRemote(target: string) {
        try {
            const result = inspectRemoteCertificate(target);
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
        const target = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file(path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '', suggestedName)),
            saveLabel: 'Save Output',
        });
        if (!target) {
            return;
        }

        await vscode.workspace.fs.writeFile(target, Buffer.from(text, 'utf8'));
        void vscode.window.showInformationMessage(`Saved ${path.basename(target.fsPath)}`);
    }

    private parseActiveEditorArtifact(): ParsedCertificateArtifact {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            throw new Error('No active editor is open.');
        }

        const document = editor.document;
        const text = document.getText();
        if (document.uri.scheme === 'file' && fs.existsSync(document.uri.fsPath)) {
            return parseCertificateInputFromFile(document.uri.fsPath, 'active-editor');
        }

        if (!text.trim()) {
            throw new Error('The active editor is empty.');
        }

        return parseCertificateInputFromText(text, {
            kind: 'active-editor',
            label: `Active editor: ${document.fileName || document.uri.toString()}`,
        });
    }

    private async saveCurrentCertificateAsDer() {
        const certificate = this.requireCurrentCertificate();
        const target = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file(path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '', 'certificate.der')),
            filters: {
                DER: ['der'],
            },
        });
        if (!target) {
            return;
        }

        await vscode.workspace.fs.writeFile(target, Buffer.from(certificate.raw.pemToDerBuffer ?? Buffer.alloc(0)));
        const command = this.currentArtifact?.filePath
            ? buildPemToDerCommand(this.currentArtifact.filePath, target.fsPath)
            : undefined;
        this.postTextResult('convert', {
            title: 'Saved DER Certificate',
            summary: `The first certificate in the current artifact was saved to ${target.fsPath}.`,
            command,
        });
    }

    private async saveCurrentCertificatePem() {
        const certificate = this.requireCurrentCertificate();
        const target = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file(path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '', 'certificate.pem')),
            filters: {
                PEM: ['pem', 'crt', 'cer'],
            },
        });
        if (!target) {
            return;
        }

        await vscode.workspace.fs.writeFile(target, Buffer.from(certificate.raw.pem, 'utf8'));
        const command =
            this.currentArtifact?.filePath && this.currentArtifact.encoding === 'DER'
                ? buildDerToPemCommand(this.currentArtifact.filePath, target.fsPath)
                : undefined;
        this.postTextResult('convert', {
            title: 'Saved PEM Certificate',
            summary: `The first certificate in the current artifact was saved to ${target.fsPath}.`,
            command,
        });
    }

    private async handleInspectExternalBundle(kind: 'pkcs12' | 'pkcs7', candidatePath?: string, password?: string) {
        const filePath = candidatePath?.trim() || this.currentArtifact?.filePath;
        if (!filePath) {
            throw new Error('Choose a file to inspect first.');
        }

        const result = kind === 'pkcs12' ? inspectPkcs12File(filePath, password) : inspectPkcs7File(filePath);
        const payload = {
            title: kind === 'pkcs12' ? 'PKCS#12 Inspection' : 'PKCS#7 Inspection',
            summary: result.summary,
            command: result.command,
            body: result.rawOutput,
            warnings: result.warnings,
            artifact: result.certificates?.length
                ? this.serializeArtifact(
                      parseCertificateInputFromText(
                          result.certificates.map((certificate) => certificate.pem).join('\n'),
                          {
                              kind: 'file',
                              label: path.basename(filePath),
                              filePath,
                          }
                      )
                  )
                : undefined,
        };

        this.panel.webview.postMessage({
            command: 'convertResult',
            payload,
        });
    }

    private async handleInspectCsr() {
        if (!this.currentArtifact) {
            throw new Error('Inspect a CSR file or paste CSR content first.');
        }

        if (this.currentArtifact.kind !== 'csr') {
            throw new Error('The current artifact is not a CSR.');
        }

        this.postTextResult('convert', {
            title: 'CSR Inspection',
            summary: 'The current artifact is classified as a certificate signing request.',
            body: this.currentArtifact.rawText || this.currentArtifact.blockTypes.join(', '),
        });
    }

    private requireCurrentCertificate(): {
        raw: { pem: string; pemToDerBuffer: Buffer };
    } {
        const certificate = this.currentArtifact?.certificates[0];
        if (!certificate) {
            throw new Error('No certificate is loaded.');
        }

        return {
            raw: {
                pem: certificate.pem,
                pemToDerBuffer: new crypto.X509Certificate(certificate.pem).raw,
            },
        };
    }

    private postCapabilities() {
        this.panel.webview.postMessage({
            command: 'capabilities',
            payload: this.capabilities,
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

    private postTextResult(
        tab: 'convert' | 'keystore',
        payload: {
            title: string;
            summary: string;
            command?: string;
            body?: string;
            warnings?: string[];
        }
    ) {
        this.panel.webview.postMessage({
            command: tab === 'convert' ? 'convertResult' : 'keystoreResult',
            payload,
        });
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
        const webview = this.panel.webview;
        const nonce = crypto.randomBytes(16).toString('base64url');
        const csp = `default-src 'none'; img-src ${webview.cspSource} https: data:; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';`;

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="${csp}">
    <title>Certificate Tools</title>
    <style>
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
            margin-bottom: 18px;
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
        .chip,
        .issue {
            padding: 5px 8px;
            border-radius: 999px;
            font-size: 12px;
            background: var(--vscode-badge-background);
            color: var(--vscode-badge-foreground);
        }
        .issue.error {
            background: color-mix(in srgb, var(--vscode-errorForeground) 20%, transparent);
        }
        .issue.warning {
            background: color-mix(in srgb, var(--vscode-editorWarning-foreground) 20%, transparent);
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
    <p class="lead">Inspect certificates and bundles, validate hostname and purpose, analyze chains, inspect PKCS#7 and PKCS#12 artifacts, build keystore commands, and fetch remote TLS certificates without leaving VS Code.</p>

    <div class="capabilities" id="capabilities"></div>

    <div class="tabs">
        <button class="tab active" data-tab="inspect">Inspect</button>
        <button class="tab" data-tab="validate">Validate</button>
        <button class="tab" data-tab="chain">Chain</button>
        <button class="tab" data-tab="convert">Convert</button>
        <button class="tab" data-tab="keystore">Keystore</button>
        <button class="tab" data-tab="remote">Remote</button>
    </div>

    <section class="tab-content active" id="inspect">
        <div class="panel">
            <div class="grid">
                <div class="field">
                    <label for="inspect-source-mode">Input Source</label>
                    <select id="inspect-source-mode">
                        <option value="paste">Pasted Content</option>
                        <option value="active">Active Editor</option>
                        <option value="file">File Path</option>
                    </select>
                </div>
                <div class="field-wide">
                    <label for="inspect-file-path">Certificate File</label>
                    <input id="inspect-file-path" type="text" placeholder="/path/to/certificate.crt or bundle.p12">
                    <div class="actions">
                        <button class="secondary" data-pick-target="inspect-file-path" data-pick-kind="file">Choose File</button>
                        <button class="ghost" id="load-active-btn">Use Active Editor</button>
                    </div>
                </div>
                <div class="field-wide">
                    <label for="inspect-text">Pasted Certificate, Bundle, CSR, or Key</label>
                    <textarea id="inspect-text" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
                </div>
            </div>
            <div class="actions">
                <button id="inspect-btn">Inspect Artifact</button>
                <button class="secondary" id="clear-inspect-btn">Clear</button>
            </div>
        </div>
        <div class="result-panel" id="inspect-result"></div>
        <div class="info-footer">
            <button class="ghost info-toggle" data-doc-target="inspect-docs">Info</button>
            <div class="doc-panel" id="inspect-docs" hidden>
                <h4>Inspect Tool Details</h4>
                <p>Use this tool to classify the current artifact before you try validation or conversion. It accepts pasted text, a picked file, or the active editor.</p>
                <ul>
                    <li>Best for PEM, DER, certificate bundles, CSRs, private keys, PKCS#7, PKCS#12, and JKS detection.</li>
                    <li>Structured output shows subject, issuer, SANs, usage, fingerprints, and raw PEM or JSON views.</li>
                    <li>If a bundle contains multiple certificates, each entry is shown separately and chain warnings are surfaced below the result.</li>
                </ul>
            </div>
        </div>
    </section>

    <section class="tab-content" id="validate">
        <div class="panel">
            <div class="grid">
                <div class="field">
                    <label for="validate-hostname">Hostname</label>
                    <input id="validate-hostname" type="text" placeholder="example.com">
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
                    <input id="validate-ca-file" type="text" placeholder="/path/to/ca.pem">
                    <div class="actions">
                        <button class="secondary" data-pick-target="validate-ca-file" data-pick-kind="file">Choose CA File</button>
                    </div>
                </div>
                <div class="field-wide">
                    <label for="validate-ca-path">CA Directory (optional)</label>
                    <input id="validate-ca-path" type="text" placeholder="/path/to/ca-directory">
                    <div class="actions">
                        <button class="secondary" data-pick-target="validate-ca-path" data-pick-kind="folder">Choose CA Directory</button>
                    </div>
                </div>
            </div>
            <div class="actions">
                <button id="validate-btn">Validate Current Artifact</button>
            </div>
        </div>
        <div class="result-panel" id="validate-result"></div>
        <div class="info-footer">
            <button class="ghost info-toggle" data-doc-target="validate-docs">Info</button>
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

    <section class="tab-content" id="chain">
        <div class="panel">
            <p class="muted">Analyze the currently loaded certificate or chain. The chain view identifies leaf, intermediate, and root candidates, and flags duplicates or missing issuers.</p>
            <div class="actions">
                <button id="chain-btn">Analyze Chain</button>
            </div>
        </div>
        <div class="result-panel" id="chain-result"></div>
        <div class="info-footer">
            <button class="ghost info-toggle" data-doc-target="chain-docs">Info</button>
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

    <section class="tab-content" id="convert">
        <div class="panel">
            <div class="grid">
                <div class="field">
                    <label for="convert-bundle-path">Bundle File Path</label>
                    <input id="convert-bundle-path" type="text" placeholder="/path/to/bundle.p12 or bundle.p7b">
                    <div class="actions">
                        <button class="secondary" data-pick-target="convert-bundle-path" data-pick-kind="file">Choose Bundle File</button>
                    </div>
                </div>
                <div class="field">
                    <label for="convert-password">Bundle Password (optional)</label>
                    <input id="convert-password" type="password" placeholder="PKCS#12 password">
                </div>
                <div class="field">
                    <label for="convert-cert-path">Certificate Path</label>
                    <input id="convert-cert-path" type="text" placeholder="/path/to/certificate.crt">
                    <div class="actions">
                        <button class="secondary" data-pick-target="convert-cert-path" data-pick-kind="file">Choose Certificate</button>
                    </div>
                </div>
                <div class="field">
                    <label for="convert-key-path">Private Key Path</label>
                    <input id="convert-key-path" type="text" placeholder="/path/to/private.key">
                    <div class="actions">
                        <button class="secondary" data-pick-target="convert-key-path" data-pick-kind="file">Choose Key</button>
                    </div>
                </div>
                <div class="field">
                    <label for="convert-output-path">Output Path</label>
                    <input id="convert-output-path" type="text" placeholder="certificate.p12">
                </div>
            </div>
            <div class="actions">
                <button id="pem-to-der-btn">Save Current as DER</button>
                <button class="secondary" id="der-to-pem-btn">Save Current as PEM</button>
                <button class="secondary" id="inspect-pkcs12-btn">Inspect PKCS#12</button>
                <button class="secondary" id="inspect-pkcs7-btn">Inspect PKCS#7</button>
                <button class="secondary" id="inspect-csr-btn">Inspect CSR</button>
                <button class="ghost" id="build-pkcs12-btn">Build PKCS#12 Command</button>
            </div>
        </div>
        <div class="result-panel" id="convert-result"></div>
        <div class="info-footer">
            <button class="ghost info-toggle" data-doc-target="convert-docs">Info</button>
            <div class="doc-panel" id="convert-docs" hidden>
                <h4>Convert Tool Details</h4>
                <p>This section mixes local save actions with external-tool inspection and command generation.</p>
                <ul>
                    <li>Save the current certificate as PEM or DER after inspection.</li>
                    <li>Inspect PKCS#7 and PKCS#12 bundles through OpenSSL when it is available.</li>
                    <li>Build an OpenSSL PKCS#12 export command from a certificate path and private key path without storing key material in the extension.</li>
                </ul>
            </div>
        </div>
    </section>

    <section class="tab-content" id="keystore">
        <div class="panel">
            <div class="grid">
                <div class="field-wide">
                    <label for="keystore-path">JKS Keystore Path</label>
                    <input id="keystore-path" type="text" placeholder="/path/to/keystore.jks">
                    <div class="actions">
                        <button class="secondary" data-pick-target="keystore-path" data-pick-kind="file">Choose Keystore</button>
                    </div>
                </div>
                <div class="field">
                    <label for="keystore-alias">Alias</label>
                    <input id="keystore-alias" type="text" placeholder="certificate-alias">
                </div>
                <div class="field">
                    <label for="keystore-password">Store Password (optional)</label>
                    <input id="keystore-password" type="password">
                </div>
            </div>
            <div class="actions">
                <button id="jks-list-btn">List Aliases</button>
                <button class="secondary" id="jks-export-btn">Export Cert Command</button>
                <button class="secondary" id="jks-convert-btn">Convert to PKCS#12 Command</button>
            </div>
        </div>
        <div class="result-panel" id="keystore-result"></div>
        <div class="info-footer">
            <button class="ghost info-toggle" data-doc-target="keystore-docs">Info</button>
            <div class="doc-panel" id="keystore-docs" hidden>
                <h4>Keystore Tool Details</h4>
                <p>This section is intentionally command-oriented because JKS handling depends on Java keytool rather than Node.js certificate parsing.</p>
                <ul>
                    <li>List aliases when keytool is available.</li>
                    <li>Generate export and JKS-to-PKCS#12 conversion commands even when keytool is missing.</li>
                    <li>Use the alias export command to extract a PEM certificate that can then be inspected in the Inspect tool.</li>
                </ul>
            </div>
        </div>
    </section>

    <section class="tab-content" id="remote">
        <div class="panel">
            <div class="grid">
                <div class="field-wide">
                    <label for="remote-target">Remote Host[:Port]</label>
                    <input id="remote-target" type="text" placeholder="example.com:443">
                </div>
            </div>
            <div class="actions">
                <button id="remote-inspect-btn">Fetch Remote Certificate Chain</button>
            </div>
        </div>
        <div class="result-panel" id="remote-result"></div>
        <div class="info-footer">
            <button class="ghost info-toggle" data-doc-target="remote-docs">Info</button>
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

        function setActiveTab(tabName) {
            document.querySelectorAll('.tab').forEach((tab) => {
                tab.classList.toggle('active', tab.dataset.tab === tabName);
            });
            document.querySelectorAll('.tab-content').forEach((content) => {
                content.classList.toggle('active', content.id === tabName);
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

        function renderArtifact(hostId, payload) {
            const host = document.getElementById(hostId);
            const warnings = payload.warnings.length
                ? '<div class="section-card"><h4>Warnings</h4><ul class="warning-list">' +
                    payload.warnings.map((warning) => '<li class="issue warning">' + escapeHtml(warning) + '</li>').join('') +
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
                '</div></div>' +
                '<div class="actions">' +
                    '<button class="secondary" data-copy-key="' + pemKey + '">Copy PEM</button>' +
                    '<button class="secondary" data-copy-key="' + jsonKey + '">Copy JSON</button>' +
                    '<button class="secondary" data-copy-key="' + fpKey + '">Copy Fingerprint</button>' +
                    '<button class="ghost" data-save-text="' + pemKey + '" data-save-name="certificate-' + (index + 1) + '.pem">Save PEM</button>' +
                '</div>' +
            '</div>';
        }

        function renderChainCard(chain) {
            const entries = chain.entries.map((entry) =>
                '<div class="section-card">' +
                    '<h4>Entry ' + (entry.index + 1) + '</h4>' +
                    '<div class="kv">' +
                        '<strong>Role</strong><span>' + escapeHtml(entry.role) + '</span>' +
                        '<strong>Subject</strong><span>' + escapeHtml(entry.subjectCommonName) + '</span>' +
                        '<strong>Issuer</strong><span>' + escapeHtml(entry.issuerCommonName) + '</span>' +
                        '<strong>Serial</strong><span>' + escapeHtml(entry.serialNumber) + '</span>' +
                    '</div>' +
                '</div>'
            ).join('');
            const warnings = chain.warnings.length
                ? '<ul class="warning-list">' + chain.warnings.map((warning) => '<li class="issue warning">' + escapeHtml(warning) + '</li>').join('') + '</ul>'
                : '<p class="muted">No chain warnings.</p>';
            return '<div class="section-card"><h4>Chain Analysis</h4>' +
                '<p class="muted">Leaf index: ' + escapeHtml(String(chain.leafIndex ?? 'n/a')) + ' · Root index: ' + escapeHtml(String(chain.rootIndex ?? 'n/a')) + '</p>' +
                warnings +
                entries +
            '</div>';
        }

        function renderValidation(payload) {
            const host = document.getElementById('validate-result');
            const commandKey = payload.command ? stashCopy(payload.command) : undefined;
            host.innerHTML =
                '<h3>Validation Result</h3>' +
                '<p class="muted">' + escapeHtml(payload.summary) + '</p>' +
                '<ul class="issue-list">' +
                payload.issues.map((issue) => '<li class="issue ' + escapeHtml(issue.severity) + '">' + escapeHtml(issue.message) + '</li>').join('') +
                '</ul>' +
                (payload.command ? '<div class="section-card"><h4>OpenSSL Command</h4><pre>' + escapeHtml(payload.command) + '</pre><div class="actions"><button class="secondary" data-copy-key="' + commandKey + '">Copy Command</button></div></div>' : '') +
                (payload.rawOutput ? '<div class="section-card"><h4>Verifier Output</h4><pre>' + escapeHtml(payload.rawOutput) + '</pre></div>' : '');
        }

        function renderChain(payload) {
            const host = document.getElementById('chain-result');
            host.innerHTML = payload ? '<h3>Chain Result</h3>' + renderChainCard(payload) : '<h3>Chain Result</h3><p class="muted">No chain data is available.</p>';
        }

        function renderTextResult(hostId, payload, title) {
            const host = document.getElementById(hostId);
            const commandKey = payload.command ? stashCopy(payload.command) : undefined;
            const bodyKey = payload.body ? stashCopy(payload.body) : undefined;
            host.innerHTML =
                '<h3>' + escapeHtml(title) + '</h3>' +
                '<p class="muted">' + escapeHtml(payload.summary) + '</p>' +
                (payload.warnings && payload.warnings.length
                    ? '<ul class="warning-list">' + payload.warnings.map((warning) => '<li class="issue warning">' + escapeHtml(warning) + '</li>').join('') + '</ul>'
                    : '') +
                (payload.command ? '<div class="section-card"><h4>Command</h4><pre>' + escapeHtml(payload.command) + '</pre><div class="actions"><button class="secondary" data-copy-key="' + commandKey + '">Copy Command</button></div></div>' : '') +
                (payload.body ? '<div class="section-card"><h4>Output</h4><pre>' + escapeHtml(payload.body) + '</pre><div class="actions"><button class="secondary" data-copy-key="' + bodyKey + '">Copy Output</button></div></div>' : '') +
                (payload.artifact ? '<div class="section-card"><h4>Extracted Certificates</h4></div>' : '');
            if (payload.artifact) {
                renderArtifact(hostId, payload.artifact);
            }
        }

        function showError(payload) {
            const host = document.getElementById(payload.tab + '-result');
            if (!host) {
                return;
            }
            host.innerHTML = '<h3>Error</h3><p class="issue error">' + escapeHtml(payload.summary) + '</p><pre>' + escapeHtml(payload.detail) + '</pre>';
        }

        document.querySelectorAll('.tab').forEach((tab) => {
            tab.addEventListener('click', () => setActiveTab(tab.dataset.tab));
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

        document.getElementById('load-active-btn').addEventListener('click', () => {
            document.getElementById('inspect-source-mode').value = 'active';
        });

        document.getElementById('inspect-btn').addEventListener('click', () => {
            vscode.postMessage({
                command: 'inspectSource',
                sourceMode: document.getElementById('inspect-source-mode').value,
                text: document.getElementById('inspect-text').value,
                filePath: document.getElementById('inspect-file-path').value,
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
            });
        });

        document.getElementById('chain-btn').addEventListener('click', () => {
            vscode.postMessage({ command: 'analyzeCurrent' });
        });

        document.getElementById('pem-to-der-btn').addEventListener('click', () => {
            vscode.postMessage({ command: 'convertAction', action: 'pemToDer' });
        });
        document.getElementById('der-to-pem-btn').addEventListener('click', () => {
            vscode.postMessage({ command: 'convertAction', action: 'derToPem' });
        });
        document.getElementById('inspect-pkcs12-btn').addEventListener('click', () => {
            vscode.postMessage({
                command: 'convertAction',
                action: 'inspectPkcs12',
                outputPath: document.getElementById('convert-bundle-path').value,
                password: document.getElementById('convert-password').value,
            });
        });
        document.getElementById('inspect-pkcs7-btn').addEventListener('click', () => {
            vscode.postMessage({
                command: 'convertAction',
                action: 'inspectPkcs7',
                outputPath: document.getElementById('convert-bundle-path').value,
            });
        });
        document.getElementById('inspect-csr-btn').addEventListener('click', () => {
            vscode.postMessage({ command: 'convertAction', action: 'inspectCsr' });
        });
        document.getElementById('build-pkcs12-btn').addEventListener('click', () => {
            vscode.postMessage({
                command: 'convertAction',
                action: 'buildPkcs12',
                certPath: document.getElementById('convert-cert-path').value,
                keyPath: document.getElementById('convert-key-path').value,
                outputPath: document.getElementById('convert-output-path').value,
                password: document.getElementById('convert-password').value,
            });
        });

        document.getElementById('jks-list-btn').addEventListener('click', () => {
            vscode.postMessage({
                command: 'keystoreAction',
                action: 'listAliases',
                keystorePath: document.getElementById('keystore-path').value,
                password: document.getElementById('keystore-password').value,
            });
        });
        document.getElementById('jks-export-btn').addEventListener('click', () => {
            vscode.postMessage({
                command: 'keystoreAction',
                action: 'exportCert',
                keystorePath: document.getElementById('keystore-path').value,
                alias: document.getElementById('keystore-alias').value,
            });
        });
        document.getElementById('jks-convert-btn').addEventListener('click', () => {
            vscode.postMessage({
                command: 'keystoreAction',
                action: 'convertToPkcs12',
                keystorePath: document.getElementById('keystore-path').value,
            });
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
                case 'convertResult':
                    setActiveTab('convert');
                    renderTextResult('convert-result', message.payload, 'Conversion Result');
                    return;
                case 'keystoreResult':
                    setActiveTab('keystore');
                    renderTextResult('keystore-result', message.payload, 'Keystore Result');
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
