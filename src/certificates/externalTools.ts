import * as childProcess from 'child_process';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import {
    ExternalToolAvailability,
    ParsedCertificateArtifact,
    ParsedCertificateDetails,
    ValidationIssue,
    parseCertificateInputFromFile,
    parseCertificateInputFromText,
} from './certificateUtils';

interface CommandResult {
    ok: boolean;
    stdout: string;
    stderr: string;
    command: string;
    error?: string;
}

export interface PkcsInspectionResult {
    summary: string;
    command: string;
    certificates?: ParsedCertificateDetails[];
    warnings: string[];
    rawOutput: string;
}

export interface RemoteInspectionResult {
    artifact: ParsedCertificateArtifact;
    command: string;
    warnings: string[];
    rawOutput: string;
}

/**
 * Name of the password file referenced in generated command recipes.
 * Using a file reference keeps the secret out of the displayed command string and shell history.
 */
const RECIPE_PASS_FILE = 'passfile.txt';

/** How long (ms) the external-tool availability result is cached before re-probing. */
const TOOL_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const COMMAND_MAX_OUTPUT_BYTES = 5 * 1024 * 1024;

let toolAvailabilityCache: ExternalToolAvailability | undefined;
let toolAvailabilityCacheTime = 0;
let toolAvailabilityProbe: Promise<ExternalToolAvailability> | undefined;

export async function detectExternalToolAvailability(forceRefresh = false): Promise<ExternalToolAvailability> {
    const now = Date.now();
    if (!forceRefresh && toolAvailabilityCache && now - toolAvailabilityCacheTime < TOOL_CACHE_TTL_MS) {
        return toolAvailabilityCache;
    }

    if (!forceRefresh && toolAvailabilityProbe) {
        return toolAvailabilityProbe;
    }

    const probe = Promise.all([detectCommandVersion('openssl', ['version']), detectCommandVersion('keytool', ['-J-version'])]).then(
        ([openssl, keytool]) => {
            toolAvailabilityCache = { openssl, keytool };
            toolAvailabilityCacheTime = Date.now();
            return toolAvailabilityCache;
        }
    );
    toolAvailabilityProbe = probe;

    try {
        return await probe;
    } finally {
        if (toolAvailabilityProbe === probe) {
            toolAvailabilityProbe = undefined;
        }
    }
}

export async function inspectPkcs12File(filePath: string, password?: string): Promise<PkcsInspectionResult> {
    const availability = await detectExternalToolAvailability();
    const displayArgs = ['pkcs12', '-info', '-in', filePath];
    if (!availability.openssl.available) {
        return {
            summary: 'OpenSSL is not available. PKCS#12 inspection is limited to command recipes.',
            command: buildOpenSslCommand(displayArgs),
            warnings: ['OpenSSL is not available on this machine.'],
            rawOutput: '',
        };
    }

    // Pass the password through stdin so it does not appear in the process listing visible
    // to other users on the machine (e.g. via `ps aux` or /proc/<pid>/cmdline).
    const commandArgs = ['pkcs12', '-in', filePath, '-nodes', '-nokeys', '-passin', 'stdin'];
    const result = await runCommand('openssl', commandArgs, password ?? '');
    const artifact = result.ok
        ? parseCertificateInputFromText(result.stdout, {
              kind: 'file',
              label: path.basename(filePath),
              filePath,
          })
        : undefined;

    return {
        summary: result.ok
            ? `OpenSSL extracted ${artifact?.certificates.length ?? 0} certificate(s) from the PKCS#12 bundle.`
            : 'OpenSSL could not inspect the PKCS#12 file.',
        command: result.command,
        certificates: artifact?.certificates,
        warnings: result.ok ? (artifact?.warnings ?? []) : [result.stderr || 'OpenSSL command failed.'],
        rawOutput: result.ok ? result.stdout : result.stderr,
    };
}

export async function inspectPkcs7File(filePath: string): Promise<PkcsInspectionResult> {
    const availability = await detectExternalToolAvailability();
    if (!availability.openssl.available) {
        return {
            summary: 'OpenSSL is not available. PKCS#7 inspection is limited to command recipes.',
            command: buildOpenSslCommand(['pkcs7', '-in', filePath, '-print_certs']),
            warnings: ['OpenSSL is not available on this machine.'],
            rawOutput: '',
        };
    }

    const result = await runCommand('openssl', ['pkcs7', '-in', filePath, '-print_certs']);
    const artifact = result.ok
        ? parseCertificateInputFromText(result.stdout, {
              kind: 'file',
              label: path.basename(filePath),
              filePath,
          })
        : undefined;

    return {
        summary: result.ok
            ? `OpenSSL extracted ${artifact?.certificates.length ?? 0} certificate(s) from the PKCS#7 bundle.`
            : 'OpenSSL could not inspect the PKCS#7 file.',
        command: result.command,
        certificates: artifact?.certificates,
        warnings: result.ok ? (artifact?.warnings ?? []) : [result.stderr || 'OpenSSL command failed.'],
        rawOutput: result.ok ? result.stdout : result.stderr,
    };
}

export async function inspectRemoteCertificate(target: string): Promise<RemoteInspectionResult> {
    const availability = await detectExternalToolAvailability();
    if (!availability.openssl.available) {
        throw new Error('OpenSSL is required for remote certificate inspection.');
    }

    const { host, port } = parseRemoteTarget(target);
    const endpoint = net.isIP(host) === 6 ? `[${host}]:${port}` : `${host}:${port}`;
    const args = ['s_client', '-showcerts'];
    if (net.isIP(host) === 0) {
        args.push('-servername', host);
    }
    args.push('-connect', endpoint);

    const result = await runCommand('openssl', args, '', 15000);
    if (!result.ok) {
        throw new Error(result.stderr || 'OpenSSL s_client failed.');
    }

    // parseCertificateInputFromText always runs analyzeCertificateChain when certificates are
    // found, so artifact.chain is already populated — no need to recompute it here.
    const artifact = parseCertificateInputFromText(result.stdout, {
        kind: 'remote',
        label: endpoint,
        host: endpoint,
    });

    return {
        artifact,
        command: result.command,
        warnings: artifact.warnings,
        rawOutput: result.stdout,
    };
}

export async function verifyWithOpenSsl(
    certificatePem: string,
    chainPem?: string,
    caFile?: string,
    caPath?: string
): Promise<{ issues: ValidationIssue[]; command: string; rawOutput: string }> {
    const availability = await detectExternalToolAvailability();
    if (!availability.openssl.available) {
        return {
            issues: [
                {
                    severity: 'warning',
                    code: 'openssl-unavailable',
                    message: 'OpenSSL is not available, so trust verification could not be performed.',
                },
            ],
            command: buildOpenSslCommand(['verify', '-CAfile', '<ca-file>', '<leaf.pem>']),
            rawOutput: '',
        };
    }

    const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-util-verify-'));
    const leafFile = path.join(tempDirectory, 'leaf.pem');
    const chainFile = path.join(tempDirectory, 'chain.pem');
    fs.writeFileSync(leafFile, certificatePem, { mode: 0o600 });
    if (chainPem) {
        fs.writeFileSync(chainFile, chainPem, { mode: 0o600 });
    }

    const args = ['verify'];
    if (caFile) {
        args.push('-CAfile', caFile);
    }
    if (caPath) {
        args.push('-CApath', caPath);
    }
    if (chainPem) {
        args.push('-untrusted', chainFile);
    }
    args.push(leafFile);

    let result: CommandResult;
    try {
        result = await runCommand('openssl', args);
    } finally {
        // Always remove temp files — even if runCommand somehow throws.
        fs.rmSync(tempDirectory, { recursive: true, force: true });
    }

    if (result.ok) {
        return {
            issues: [
                {
                    severity: 'info',
                    code: 'openssl-verify-ok',
                    message: 'OpenSSL trust verification succeeded.',
                },
            ],
            command: result.command,
            rawOutput: result.stdout,
        };
    }

    return {
        issues: [
            {
                severity: 'error',
                code: 'openssl-verify-failed',
                message: 'OpenSSL trust verification failed.',
                details: result.stderr || result.stdout,
            },
        ],
        command: result.command,
        rawOutput: result.stderr || result.stdout,
    };
}

export function buildPemToDerCommand(filePath: string, outputPath: string): string {
    return buildOpenSslCommand(['x509', '-in', filePath, '-outform', 'DER', '-out', outputPath]);
}

export function buildDerToPemCommand(filePath: string, outputPath: string): string {
    return buildOpenSslCommand(['x509', '-inform', 'DER', '-in', filePath, '-out', outputPath]);
}

export function buildPkcs12ExportCommand(certPath: string, keyPath: string, outputPath: string, password?: string): string {
    const args = ['pkcs12', '-export', '-in', certPath, '-inkey', keyPath, '-out', outputPath];
    if (password) {
        // Reference a passfile instead of embedding the secret directly so it does not appear
        // in shell history when the user pastes and runs this command.
        args.push('-password', `file:${RECIPE_PASS_FILE}`);
    }
    return buildOpenSslCommand(args);
}

export function buildPkcs12PemExportCommands(
    filePath: string,
    certificateOutputPath: string,
    keyOutputPath: string,
    password?: string
): string {
    // Reference a passfile instead of embedding the secret so it does not appear in shell history.
    const passwordArgs = password ? ['-passin', `file:${RECIPE_PASS_FILE}`] : [];
    return [
        buildOpenSslCommand(['pkcs12', '-in', filePath, ...passwordArgs, '-clcerts', '-nokeys', '-out', certificateOutputPath]),
        buildOpenSslCommand(['pkcs12', '-in', filePath, ...passwordArgs, '-nocerts', '-nodes', '-out', keyOutputPath]),
    ].join('\n');
}

export async function listJksAliases(
    filePath: string,
    password?: string
): Promise<{ summary: string; command: string; rawOutput: string }> {
    const availability = await detectExternalToolAvailability();

    // Build the display args using a passfile reference so the password does not appear in the UI.
    const displayArgs = ['-list', '-keystore', filePath];
    if (password) {
        displayArgs.push('-storepass:file', RECIPE_PASS_FILE);
    }

    if (!availability.keytool.available) {
        return {
            summary: 'keytool is not available. The extension can only show the command recipe.',
            command: buildKeytoolCommand(displayArgs),
            rawOutput: '',
        };
    }

    // For live execution, write the password to a restricted-permission temp file so it does
    // not appear in the process listing (e.g. `ps aux`) visible to other users on the machine.
    let tempDir: string | undefined;
    const execArgs = ['-list', '-keystore', filePath];
    try {
        if (password) {
            tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-util-pass-'));
            const passFile = path.join(tempDir, 'pass.txt');
            fs.writeFileSync(passFile, password, { mode: 0o600 });
            execArgs.push('-storepass:file', passFile);
        }

        const result = await runCommand('keytool', execArgs);
        return {
            summary: result.ok ? 'JKS aliases listed successfully.' : 'keytool could not list JKS aliases.',
            command: buildKeytoolCommand(displayArgs),
            rawOutput: result.ok ? result.stdout : result.stderr,
        };
    } finally {
        if (tempDir) {
            fs.rmSync(tempDir, { recursive: true, force: true });
        }
    }
}

export function buildJksExportCommand(filePath: string, alias: string): string {
    return buildKeytoolCommand(['-exportcert', '-alias', alias, '-keystore', filePath, '-rfc', '-file', 'certificate.pem']);
}

export function buildJksToPkcs12Command(filePath: string): string {
    return buildKeytoolCommand(['-importkeystore', '-srckeystore', filePath, '-destkeystore', 'keystore.p12', '-deststoretype', 'PKCS12']);
}

export function buildJksPemExportCommands(
    filePath: string,
    alias: string,
    pkcs12OutputPath: string,
    certificateOutputPath: string,
    keyOutputPath: string,
    password?: string
): string {
    const args = [
        '-importkeystore',
        '-srckeystore',
        filePath,
        '-srcalias',
        alias,
        '-destkeystore',
        pkcs12OutputPath,
        '-deststoretype',
        'PKCS12',
        '-destalias',
        alias,
    ];
    // Read the store password from a file rather than embedding it on the command line, so the
    // generated (and copyable) recipe does not leak the secret into shell history or the DOM. The
    // same file is reused for the OpenSSL extraction because the intermediate PKCS#12 is written
    // with the store password.
    const passwordFile = 'storepass.txt';
    if (password) {
        args.push('-srcstorepass:file', passwordFile, '-deststorepass:file', passwordFile);
    }

    const passinArgs = password ? ['-passin', `file:${passwordFile}`] : [];
    return [
        buildKeytoolCommand(args),
        buildOpenSslCommand(['pkcs12', '-in', pkcs12OutputPath, ...passinArgs, '-clcerts', '-nokeys', '-out', certificateOutputPath]),
        buildOpenSslCommand(['pkcs12', '-in', pkcs12OutputPath, ...passinArgs, '-nocerts', '-nodes', '-out', keyOutputPath]),
    ].join('\n');
}

async function detectCommandVersion(command: string, args: string[]): Promise<{ available: boolean; version?: string; error?: string }> {
    const result = await runCommand(command, args, undefined, 5000);
    const output = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();
    if ((result.ok || output) && !result.error) {
        return {
            available: true,
            version: output.split('\n')[0]?.trim(),
        };
    }

    return {
        available: false,
        error: result.error || output || `Failed to execute ${command}.`,
    };
}

function runCommand(command: string, args: string[], input?: string, timeout = 10000): Promise<CommandResult> {
    const commandString = [command, ...args.map(shellQuote)].join(' ');

    return new Promise((resolve) => {
        let child: childProcess.ChildProcessWithoutNullStreams;
        try {
            child = childProcess.spawn(command, args, {
                stdio: ['pipe', 'pipe', 'pipe'],
            });
        } catch (error) {
            const detail = error instanceof Error ? error.message : String(error);
            resolve({
                ok: false,
                stdout: '',
                stderr: detail,
                command: commandString,
                error: detail,
            });
            return;
        }

        let stdout = '';
        let stderr = '';
        let outputBytes = 0;
        let settled = false;
        let timeoutHandle: NodeJS.Timeout | undefined;

        const finish = (ok: boolean, error?: string) => {
            if (settled) {
                return;
            }
            settled = true;
            if (timeoutHandle) {
                clearTimeout(timeoutHandle);
            }
            resolve({
                ok,
                stdout,
                stderr,
                command: commandString,
                error,
            });
        };

        const appendOutput = (target: 'stdout' | 'stderr', chunk: string) => {
            if (settled) {
                return;
            }

            outputBytes += Buffer.byteLength(chunk);
            if (outputBytes > COMMAND_MAX_OUTPUT_BYTES) {
                const detail = `Command output exceeded the ${COMMAND_MAX_OUTPUT_BYTES / (1024 * 1024)} MB limit.`;
                stderr = stderr ? `${stderr}\n${detail}` : detail;
                child.kill();
                finish(false, detail);
                return;
            }

            if (target === 'stdout') {
                stdout += chunk;
            } else {
                stderr += chunk;
            }
        };

        child.stdout.setEncoding('utf8');
        child.stderr.setEncoding('utf8');
        child.stdout.on('data', (chunk: string) => appendOutput('stdout', chunk));
        child.stderr.on('data', (chunk: string) => appendOutput('stderr', chunk));

        child.once('error', (error) => {
            const detail = error.message;
            stderr = stderr ? `${stderr}\n${detail}` : detail;
            finish(false, detail);
        });

        child.once('close', (code) => {
            finish(code === 0);
        });

        child.stdin.on('error', () => {
            // The child may close stdin early after reporting its own actionable error.
        });
        child.stdin.end(input);

        timeoutHandle = setTimeout(() => {
            const detail = `Command timed out after ${timeout} ms.`;
            stderr = stderr ? `${stderr}\n${detail}` : detail;
            child.kill();
            finish(false, detail);
        }, timeout);
    });
}

function buildOpenSslCommand(args: string[]): string {
    return ['openssl', ...args.map(shellQuote)].join(' ');
}

function buildKeytoolCommand(args: string[]): string {
    return ['keytool', ...args.map(shellQuote)].join(' ');
}

function shellQuote(value: string): string {
    if (/^[A-Za-z0-9_./:-]+$/.test(value)) {
        return value;
    }
    return `'${value.replace(/'/g, `'\\''`)}'`;
}

export function parseRemoteTarget(target: string): { host: string; port: number } {
    const trimmed = target.trim();
    if (!trimmed) {
        throw new Error('Remote target is required.');
    }
    if (trimmed.includes('://') || /[/?#\s]/.test(trimmed)) {
        throw new Error('Enter a host name or IP address, optionally followed by a port.');
    }

    let host: string;
    let port = 443;

    if (trimmed.startsWith('[')) {
        const closingBracket = trimmed.indexOf(']');
        if (closingBracket === -1) {
            throw new Error('IPv6 addresses must use matching brackets.');
        }

        host = trimmed.slice(1, closingBracket);
        if (net.isIP(host) !== 6) {
            throw new Error('Bracketed remote targets must contain a valid IPv6 address.');
        }

        const suffix = trimmed.slice(closingBracket + 1);
        if (suffix) {
            if (!suffix.startsWith(':')) {
                throw new Error('Unexpected text after the IPv6 address.');
            }
            port = parseRemotePort(suffix.slice(1));
        }
    } else if (net.isIP(trimmed) === 6) {
        host = trimmed;
    } else {
        const firstColon = trimmed.indexOf(':');
        const lastColon = trimmed.lastIndexOf(':');
        if (firstColon !== lastColon) {
            throw new Error('IPv6 addresses with a port must be enclosed in brackets.');
        }

        if (lastColon === -1) {
            host = trimmed;
        } else {
            host = trimmed.slice(0, lastColon);
            port = parseRemotePort(trimmed.slice(lastColon + 1));
        }

        if (!isValidRemoteHost(host)) {
            throw new Error('Enter a valid host name or IP address.');
        }
    }

    return { host, port };
}

function parseRemotePort(value: string): number {
    if (!/^\d+$/.test(value)) {
        throw new Error('The remote port must be a number between 1 and 65535.');
    }

    const port = Number(value);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error('The remote port must be a number between 1 and 65535.');
    }
    return port;
}

function isValidRemoteHost(host: string): boolean {
    if (net.isIP(host)) {
        return true;
    }
    if (!host || host.length > 253) {
        return false;
    }

    const normalized = host.endsWith('.') ? host.slice(0, -1) : host;
    return normalized.split('.').every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label));
}

export function parseRemoteInspectionOutput(rawOutput: string): number {
    return parseCertificateInputFromText(rawOutput, {
        kind: 'remote',
        label: 'remote',
    }).certificates.length;
}

export function parsePkcsCertificateOutput(rawOutput: string): number {
    return parseCertificateInputFromText(rawOutput, {
        kind: 'pasted',
        label: 'output',
    }).certificates.length;
}

export function parseArtifactFromExternalFile(filePath: string): ParsedCertificateArtifact {
    return parseCertificateInputFromFile(filePath);
}
