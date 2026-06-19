import * as vscode from 'vscode';
import { CertificateExpiryPanel, CertificatePanel } from './panels';
import { CertificateToolsProvider } from './providers';

export function activate(context: vscode.ExtensionContext) {
    const certificateToolsProvider = new CertificateToolsProvider(context.extensionUri);
    const sidebarViewProvider = vscode.window.registerWebviewViewProvider(
        'certificateUtilToolsView',
        certificateToolsProvider
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

    const convertToolCommand = vscode.commands.registerCommand('certificateUtil.openConvertTool', () => {
        CertificatePanel.render(context.extensionUri, { type: 'open-tab', initialTab: 'convert' });
    });

    const keystoreToolCommand = vscode.commands.registerCommand('certificateUtil.openKeystoreTool', () => {
        CertificatePanel.render(context.extensionUri, { type: 'open-tab', initialTab: 'keystore' });
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
            validateInput: (value) => (!value.trim() ? 'A host name is required.' : undefined),
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

    context.subscriptions.push(
        sidebarViewProvider,
        certificateCommand,
        inspectToolCommand,
        validateToolCommand,
        chainToolCommand,
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
