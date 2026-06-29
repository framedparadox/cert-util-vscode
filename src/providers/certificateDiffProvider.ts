import * as path from 'path';
import * as vscode from 'vscode';
import { ParsedCertificateDetails, parseCertificateInputFromFile } from '../certificates/certificateUtils';

/**
 * Backs the certificate comparison feature: it stores normalized, human-readable certificate
 * summaries behind a virtual `cert-diff:` scheme so they can be opened in VS Code's native diff
 * editor (which highlights field-level differences for free).
 */
export class CertificateDiffProvider implements vscode.TextDocumentContentProvider {
    public static readonly scheme = 'cert-diff';
    private readonly contents = new Map<string, string>();

    public static register(context: vscode.ExtensionContext): CertificateDiffProvider {
        const provider = new CertificateDiffProvider();
        context.subscriptions.push(vscode.workspace.registerTextDocumentContentProvider(CertificateDiffProvider.scheme, provider));
        return provider;
    }

    public provideTextDocumentContent(uri: vscode.Uri): string {
        return this.contents.get(uri.path) ?? '';
    }

    /** Prompts for two certificate files and opens a diff of their normalized summaries. */
    public async compare(): Promise<void> {
        const selection = await vscode.window.showOpenDialog({
            canSelectMany: true,
            openLabel: 'Select two certificates to compare',
            title: 'Select exactly two certificate files',
        });
        if (!selection || selection.length !== 2) {
            if (selection && selection.length !== 2) {
                void vscode.window.showWarningMessage('Select exactly two certificate files to compare.');
            }
            return;
        }

        try {
            const [left, right] = selection;
            const leftUri = this.store(left.fsPath);
            const rightUri = this.store(right.fsPath);
            await vscode.commands.executeCommand(
                'vscode.diff',
                leftUri,
                rightUri,
                `${path.basename(left.fsPath)} ↔ ${path.basename(right.fsPath)}`
            );
        } catch (error) {
            void vscode.window.showErrorMessage(`Certificate comparison failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    private store(filePath: string): vscode.Uri {
        const artifact = parseCertificateInputFromFile(filePath);
        const details = artifact.certificates[0];
        if (!details) {
            throw new Error(`No X.509 certificate could be parsed from ${path.basename(filePath)}.`);
        }
        // A stable, unique virtual path per source file keeps repeat comparisons from colliding.
        const virtualPath = `/${Buffer.from(filePath).toString('base64url')}.txt`;
        this.contents.set(virtualPath, certificateToComparableText(details));
        return vscode.Uri.from({ scheme: CertificateDiffProvider.scheme, path: virtualPath });
    }
}

/** Renders a certificate as a stable, line-oriented summary suitable for a text diff. */
function certificateToComparableText(details: ParsedCertificateDetails): string {
    const lines = [
        `Subject:        ${details.subject}`,
        `Issuer:         ${details.issuer}`,
        `Valid From:     ${details.validFrom}`,
        `Valid To:       ${details.validTo}`,
        `Serial Number:  ${details.serialNumber}`,
        `Type:           ${details.type}`,
        `Public Key:     ${details.algorithm}`,
        `Signature:      ${details.signatureAlgorithm}`,
        `Self-Signed:    ${details.isSelfSigned}`,
        `CA:             ${details.isCertificateAuthority}`,
        `Key Usage:      ${details.keyUsage.join(', ') || 'None'}`,
        `Extended Usage: ${details.extendedKeyUsage.join(', ') || 'None'}`,
        'Subject Alternative Names:',
        ...(details.subjectAltNames.length ? details.subjectAltNames.map((name) => `  ${name}`) : ['  None']),
        `SHA-1:          ${details.fingerprint}`,
        `SHA-256:        ${details.fingerprint256}`,
    ];
    return lines.join('\n');
}
