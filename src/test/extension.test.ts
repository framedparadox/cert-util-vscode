import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

suite('extension manifest', () => {
    test('extension should be present', () => {
        const extension = vscode.extensions.all.find((candidate) => candidate.packageJSON?.name === 'certi');
        assert.ok(extension);
    });

    test('manifest contributes the expanded certificate commands', () => {
        const packageJsonPath = path.resolve(__dirname, '../../package.json');
        const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8')) as {
            contributes?: {
                commands?: Array<{ command: string; title?: string; category?: string }>;
                views?: unknown;
                viewsContainers?: unknown;
            };
            capabilities?: {
                untrustedWorkspaces?: { supported?: boolean };
                virtualWorkspaces?: { supported?: boolean };
            };
        };
        const commandEntries = packageJson.contributes?.commands ?? [];
        const commands = new Set(commandEntries.map((entry) => entry.command));

        assert.ok(commands.has('certificateUtil.openCertificateTools'));
        assert.ok(commands.has('certificateUtil.openCertificateOperations'));
        assert.ok(commands.has('certificateUtil.inspectActiveCertificate'));
        assert.ok(commands.has('certificateUtil.inspectCertificateFile'));
        assert.ok(commands.has('certificateUtil.inspectRemoteCertificate'));
        assert.ok(commands.has('certificateUtil.openInspectTool'));
        assert.ok(commands.has('certificateUtil.openValidateTool'));
        assert.ok(commands.has('certificateUtil.openChainTool'));
        assert.ok(commands.has('certificateUtil.openConvertTool'));
        assert.ok(commands.has('certificateUtil.openKeystoreTool'));
        assert.ok(commands.has('certificateUtil.openRemoteTool'));
        assert.ok(commands.has('certificateUtil.openExpiryChecker'));
        assert.ok(commandEntries.every((entry) => entry.category === 'Certificate Utility'));
        assert.ok(commandEntries.every((entry) => /^(Inspect|Open) /.test(entry.title ?? '')));
        assert.strictEqual(packageJson.contributes?.views, undefined);
        assert.strictEqual(packageJson.contributes?.viewsContainers, undefined);
        assert.strictEqual(packageJson.capabilities?.untrustedWorkspaces?.supported, true);
        assert.strictEqual(packageJson.capabilities?.virtualWorkspaces?.supported, false);
    });
});
