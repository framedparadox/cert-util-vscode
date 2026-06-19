import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

suite('extension manifest', () => {
    test('extension should be present', () => {
        const extension = vscode.extensions.all.find((candidate) => candidate.packageJSON?.name === 'certificate-util');
        assert.ok(extension);
    });

    test('manifest contributes the expanded certificate commands', () => {
        const packageJsonPath = path.resolve(__dirname, '../../package.json');
        const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8')) as {
            contributes?: { commands?: Array<{ command: string }> };
        };
        const commands = new Set((packageJson.contributes?.commands ?? []).map((entry) => entry.command));

        assert.ok(commands.has('certificateUtil.openCertificateTools'));
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
    });
});
