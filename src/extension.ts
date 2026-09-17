import * as path from 'path';
import * as vscode from 'vscode';
import { configureExternalTools, parseRemoteTarget } from './certificates/externalTools';
import {
    SUPPORTED_CERTIFICATE_EXTENSIONS,
    CLASSIFIED_ARTIFACT_EXTENSIONS,
    getCertificateStatus,
    parseCertificateInputFromFile,
} from './certificates/certificateUtils';
import { CONFIG_SECTION, getConfig } from './config';
import { buildWatchlistReport, fetchWatchlist } from './certificates/remoteWatch';
import { CertificateExpiryPanel, CertificateOperationsPanel, CertificatePanel, DocumentationPanel, GeneratePanel } from './panels';
import { CertificateDiffProvider, CertificateEditorProvider, CertificateToolsProvider } from './providers';

export function activate(context: vscode.ExtensionContext) {
    const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);

    // Apply OpenSSL/keytool path overrides on startup and whenever the relevant settings change.
    applyExternalToolConfig();
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration((event) => {
            if (event.affectsConfiguration(CONFIG_SECTION)) {
                applyExternalToolConfig();
                updateExpiryStatusBar(statusBarItem);
            }
        })
    );

    const certificateCommand = vscode.commands.registerCommand('certificateUtil.openCertificateTools', () => {
        CertificatePanel.render(context.extensionUri);
    });

    const inspectToolCommand = vscode.commands.registerCommand('certificateUtil.openInspectTool', () => {
        CertificatePanel.render(context.extensionUri, { type: 'open-tab', initialTab: 'inspect' });
    });

    const validateToolCommand = vscode.commands.registerCommand('certificateUtil.openValidateTool', () => {
        CertificatePanel.render(context.extensionUri, { type: 'open-tab', initialTab: 'validate' });
    });

    const chainToolCommand = vscode.commands.registerCommand('certificateUtil.openChainTool', () => {
        CertificatePanel.render(context.extensionUri, { type: 'open-tab', initialTab: 'chain' });
    });

    const operationsCommand = vscode.commands.registerCommand('certificateUtil.openCertificateOperations', () => {
        CertificateOperationsPanel.render(context.extensionUri);
    });

    const convertToolCommand = vscode.commands.registerCommand('certificateUtil.openConvertTool', () => {
        CertificateOperationsPanel.render(context.extensionUri, { initialTab: 'convert' });
    });

    const keystoreToolCommand = vscode.commands.registerCommand('certificateUtil.openKeystoreTool', () => {
        CertificateOperationsPanel.render(context.extensionUri, { initialTab: 'keystore' });
    });

    const remoteToolCommand = vscode.commands.registerCommand('certificateUtil.openRemoteTool', () => {
        CertificatePanel.render(context.extensionUri, { type: 'open-tab', initialTab: 'remote' });
    });

    const inspectActiveCertificateCommand = vscode.commands.registerCommand('certificateUtil.inspectActiveCertificate', () => {
        CertificatePanel.render(context.extensionUri, { type: 'inspect-active', initialTab: 'inspect' });
    });

    const inspectCertificateFileCommand = vscode.commands.registerCommand(
        'certificateUtil.inspectCertificateFile',
        async (resource?: vscode.Uri) => {
            // When invoked from the Explorer context menu, VS Code passes the clicked resource URI;
            // otherwise fall back to an open dialog.
            let filePath = resource?.fsPath;
            if (!filePath) {
                const selection = await vscode.window.showOpenDialog({
                    canSelectMany: false,
                    canSelectFiles: true,
                    canSelectFolders: false,
                    openLabel: 'Inspect Certificate File',
                });

                if (!selection?.[0]) {
                    return;
                }
                filePath = selection[0].fsPath;
            }

            CertificatePanel.render(context.extensionUri, {
                type: 'inspect-file',
                filePath,
                initialTab: 'inspect',
            });
        }
    );

    const inspectRemoteCertificateCommand = vscode.commands.registerCommand('certificateUtil.inspectRemoteCertificate', async () => {
        const target = await vscode.window.showInputBox({
            prompt: 'Enter a remote TLS endpoint',
            placeHolder: 'example.com:443',
            validateInput: (value) => {
                try {
                    parseRemoteTarget(value);
                    return undefined;
                } catch (error) {
                    return error instanceof Error ? error.message : 'Enter a valid host name or IP address.';
                }
            },
        });

        if (!target) {
            return;
        }

        CertificatePanel.render(context.extensionUri, {
            type: 'inspect-remote',
            remoteTarget: target.trim(),
            initialTab: 'remote',
        });
    });

    const certificateExpiryCommand = vscode.commands.registerCommand('certificateUtil.openExpiryChecker', () => {
        CertificateExpiryPanel.render(context.extensionUri);
    });

    const generateToolCommand = vscode.commands.registerCommand('certificateUtil.openGenerateTool', () => {
        GeneratePanel.render(context.extensionUri);
    });

    const verifyKeyMatchCommand = vscode.commands.registerCommand('certificateUtil.verifyKeyMatchesCertificate', () =>
        verifyKeyMatchesCertificate()
    );

    const diffProvider = CertificateDiffProvider.register(context);
    const compareCommand = vscode.commands.registerCommand('certificateUtil.compareCertificates', () => diffProvider.compare());

    const watchlistCommand = vscode.commands.registerCommand('certificateUtil.checkRemoteWatchlist', () => checkRemoteWatchlist());

    const documentationCommand = vscode.commands.registerCommand('certificateUtil.openDocumentation', () => {
        DocumentationPanel.render(context.extensionUri);
    });

    const sidebarViewProvider = vscode.window.registerWebviewViewProvider(
        'certificateUtilToolsView',
        new CertificateToolsProvider(context.extensionUri)
    );

    context.subscriptions.push(CertificateEditorProvider.register(context));

    // Status bar: show validity of the certificate file in the active editor.
    statusBarItem.command = 'certificateUtil.inspectActiveCertificate';
    updateExpiryStatusBar(statusBarItem);
    context.subscriptions.push(
        statusBarItem,
        vscode.window.onDidChangeActiveTextEditor(() => updateExpiryStatusBar(statusBarItem)),
        vscode.workspace.onDidSaveTextDocument((document) => {
            if (document === vscode.window.activeTextEditor?.document) {
                updateExpiryStatusBar(statusBarItem);
            }
        })
    );

    context.subscriptions.push(
        sidebarViewProvider,
        certificateCommand,
        inspectToolCommand,
        validateToolCommand,
        chainToolCommand,
        operationsCommand,
        convertToolCommand,
        keystoreToolCommand,
        remoteToolCommand,
        inspectActiveCertificateCommand,
        inspectCertificateFileCommand,
        inspectRemoteCertificateCommand,
        certificateExpiryCommand,
        generateToolCommand,
        verifyKeyMatchCommand,
        compareCommand,
        watchlistCommand,
        documentationCommand
    );
}

/**
 * Fetches every endpoint in the configured watchlist over TLS and opens a Markdown expiry report in a
 * new editor. No external tools are required.
 */
async function checkRemoteWatchlist(): Promise<void> {
    const { remoteWatchlist, expiryWarningDays } = getConfig();
    if (!remoteWatchlist.length) {
        void vscode.window.showInformationMessage(
            'No endpoints are configured. Add host:port entries to the "certificateUtil.remoteWatchlist" setting.'
        );
        return;
    }

    await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'Checking remote certificate watchlist…' },
        async () => {
            const results = await fetchWatchlist(remoteWatchlist, expiryWarningDays);
            const document = await vscode.workspace.openTextDocument({
                language: 'markdown',
                content: buildWatchlistReport(results),
            });
            await vscode.window.showTextDocument(document);
        }
    );
}

/**
 * Prompts for a private-key file and a certificate file, then reports whether the key corresponds to
 * the certificate (by signing a nonce and verifying it with the certificate's public key).
 */
async function verifyKeyMatchesCertificate(): Promise<void> {
    const keySelection = await vscode.window.showOpenDialog({
        canSelectMany: false,
        openLabel: 'Select Private Key',
        title: 'Select the private key (PEM)',
    });
    if (!keySelection?.[0]) {
        return;
    }

    const certSelection = await vscode.window.showOpenDialog({
        canSelectMany: false,
        openLabel: 'Select Certificate',
        title: 'Select the certificate (PEM)',
    });
    if (!certSelection?.[0]) {
        return;
    }

    try {
        const keyPem = Buffer.from(await vscode.workspace.fs.readFile(keySelection[0])).toString('utf8');
        const certPem = Buffer.from(await vscode.workspace.fs.readFile(certSelection[0])).toString('utf8');
        // Loaded on demand so @peculiar/x509 is not evaluated at activation.
        const { privateKeyMatchesCertificate } = await import('./certificates/generation.js');
        const matches = await privateKeyMatchesCertificate(keyPem, certPem);
        if (matches) {
            void vscode.window.showInformationMessage('The private key matches the certificate.');
        } else {
            void vscode.window.showWarningMessage('The private key does NOT match the certificate.');
        }
    } catch (error) {
        void vscode.window.showErrorMessage(`Key/certificate check failed: ${error instanceof Error ? error.message : String(error)}`);
    }
}

/** Pushes the current OpenSSL/keytool path settings into the external-tools module. */
function applyExternalToolConfig(): void {
    const config = getConfig();
    configureExternalTools({ opensslPath: config.opensslPath, keytoolPath: config.keytoolPath });
}

const CERTIFICATE_FILE_EXTENSIONS = new Set([...SUPPORTED_CERTIFICATE_EXTENSIONS, ...CLASSIFIED_ARTIFACT_EXTENSIONS]);

/**
 * Updates the status bar to reflect the validity of the certificate file in the active editor.
 * Hides the item when the active document is not a parseable certificate file.
 */
function updateExpiryStatusBar(item: vscode.StatusBarItem): void {
    const editor = vscode.window.activeTextEditor;
    const filePath = editor?.document.uri.fsPath;
    if (!filePath || editor?.document.uri.scheme !== 'file' || !CERTIFICATE_FILE_EXTENSIONS.has(path.extname(filePath).toLowerCase())) {
        item.hide();
        return;
    }

    try {
        const artifact = parseCertificateInputFromFile(filePath);
        const leaf = artifact.certificates[artifact.chain?.leafIndex ?? 0];
        if (!leaf) {
            item.hide();
            return;
        }

        const status = getCertificateStatus(leaf.validTo, new Date(), getConfig().expiryWarningDays);
        const expiry = new Date(leaf.validTo).toISOString().slice(0, 10);
        if (status === 'expired') {
            item.text = `$(error) Cert expired ${expiry}`;
            item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        } else if (status === 'expiring') {
            item.text = `$(warning) Cert expires ${expiry}`;
            item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        } else {
            item.text = `$(shield) Cert valid to ${expiry}`;
            item.backgroundColor = undefined;
        }
        item.tooltip = `${leaf.subjectCommonName || 'Certificate'} — click to inspect`;
        item.show();
    } catch {
        // Not a parseable certificate (e.g. an unrelated .key/.csr file); keep the status bar clean.
        item.hide();
    }
}

export function deactivate() {}
