import * as crypto from 'crypto';
import * as vscode from 'vscode';

interface CertificateToolItem {
    label: string;
    description: string;
    command: string;
    icon: string;
}

const CERTIFICATE_TOOLS: CertificateToolItem[] = [
    {
        label: 'Certificate Tools',
        description: 'Inspect, validate, analyze, and fetch remote certificates',
        command: 'certificateUtil.openCertificateTools',
        icon: 'certificate.svg',
    },
    {
        label: 'Conversion & Keystore',
        description: 'Convert certificate formats and build JKS, PFX, and PKCS#12 export commands',
        command: 'certificateUtil.openCertificateOperations',
        icon: 'conversion-keystore.svg',
    },
    {
        label: 'Expiry Checker',
        description: 'Scan folders for PEM and DER certificates by expiration date',
        command: 'certificateUtil.openExpiryChecker',
        icon: 'cert-expiry.svg',
    },
    {
        label: 'Generate Certificate',
        description: 'Create key pairs, CSRs, and self-signed certificates locally',
        command: 'certificateUtil.openGenerateTool',
        icon: 'certificate.svg',
    },
];

export class CertificateToolsProvider implements vscode.WebviewViewProvider {
    constructor(private readonly extensionUri: vscode.Uri) {}

    public resolveWebviewView(webviewView: vscode.WebviewView): void {
        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this.extensionUri],
        };

        webviewView.webview.html = this.getHtml(webviewView.webview);
        webviewView.webview.onDidReceiveMessage(async (message) => {
            if (message.command === 'runTool' && typeof message.toolCommand === 'string') {
                await vscode.commands.executeCommand(message.toolCommand);
            }
        });
    }

    private iconUri(webview: vscode.Webview, file: string): string {
        return webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'resources', 'icons', file)).toString();
    }

    private escapeHtml(value: string): string {
        return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    private renderTool(webview: vscode.Webview, tool: CertificateToolItem): string {
        const icon = this.iconUri(webview, tool.icon);
        const label = this.escapeHtml(tool.label);
        const description = this.escapeHtml(tool.description);
        const command = this.escapeHtml(tool.command);

        return `<button type="button" class="tool-button" data-command="${command}">
            <img class="tool-icon" src="${icon}" alt="" />
            <span class="tool-copy">
                <span class="tool-label">${label}</span>
                <span class="tool-description">${description}</span>
            </span>
        </button>`;
    }

    private getHtml(webview: vscode.Webview): string {
        const nonce = crypto.randomBytes(16).toString('base64url');
        const csp = `default-src 'none'; img-src ${webview.cspSource}; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';`;
        const tools = CERTIFICATE_TOOLS.map((tool) => this.renderTool(webview, tool)).join('');

        return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<style nonce="${nonce}">
    html,
    body {
        height: 100%;
        margin: 0;
        padding: 8px;
        box-sizing: border-box;
        color: var(--vscode-sideBar-foreground);
        background: var(--vscode-sideBar-background);
        font-family: var(--vscode-font-family);
    }

    .tool-list {
        display: flex;
        flex-direction: column;
        gap: 8px;
    }

    .tool-button {
        width: 100%;
        border: 1px solid var(--vscode-sideBar-border, var(--vscode-input-border));
        border-radius: 8px;
        padding: 9px;
        background: var(--vscode-editorWidget-background);
        color: inherit;
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 10px;
        text-align: left;
        font: inherit;
    }

    .tool-button:hover {
        background: var(--vscode-list-hoverBackground);
    }

    .tool-button:focus-visible {
        outline: 1px solid var(--vscode-focusBorder);
        outline-offset: 1px;
    }

    .tool-icon {
        width: 24px;
        height: 24px;
        flex: 0 0 auto;
    }

    .tool-copy {
        min-width: 0;
        display: flex;
        flex-direction: column;
        gap: 3px;
    }

    .tool-label {
        color: var(--vscode-sideBar-foreground);
        font-size: 12px;
        font-weight: 600;
        line-height: 1.25;
    }

    .tool-description {
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
        line-height: 1.35;
    }
</style>
</head>
<body>
    <main class="tool-list">
        ${tools}
    </main>
    <script nonce="${nonce}">
        const vscode = acquireVsCodeApi();
        document.querySelectorAll('.tool-button').forEach((button) => {
            button.addEventListener('click', () => {
                vscode.postMessage({
                    command: 'runTool',
                    toolCommand: button.dataset.command
                });
            });
        });
    </script>
</body>
</html>`;
    }
}
