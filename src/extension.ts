import * as vscode from 'vscode';
import { parseRemoteTarget } from './certificates/externalTools';
import { CertificateExpiryPanel, CertificateOperationsPanel, CertificatePanel } from './panels';
import { CertificateToolsProvider } from './providers';

export function activate(context: vscode.ExtensionContext) {
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

    const inspectCertificateFileCommand = vscode.commands.registerCommand('certificateUtil.inspectCertificateFile', async () => {
        const selection = await vscode.window.showOpenDialog({
            canSelectMany: false,
            canSelectFiles: true,
            canSelectFolders: false,
            openLabel: 'Inspect Certificate File',
        });

        if (!selection?.[0]) {
            return;
        }

        CertificatePanel.render(context.extensionUri, {
            type: 'inspect-file',
            filePath: selection[0].fsPath,
            initialTab: 'inspect',
        });
    });

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

    const sidebarViewProvider = vscode.window.registerWebviewViewProvider(
        'certificateUtilToolsView',
        new CertificateToolsProvider(context.extensionUri)
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
        certificateExpiryCommand
    );
}

export function deactivate() {}
