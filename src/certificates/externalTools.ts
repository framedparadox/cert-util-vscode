import * as childProcess from 'child_process';
import * as fs from 'fs';
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

let toolAvailabilityCache: ExternalToolAvailability | undefined;
let toolAvailabilityCacheTime = 0;

export function detectExternalToolAvailability(forceRefresh = false): ExternalToolAvailability {
    const now = Date.now();
    if (!forceRefresh && toolAvailabilityCache && now - toolAvailabilityCacheTime < TOOL_CACHE_TTL_MS) {
        return toolAvailabilityCache;
    }

    toolAvailabilityCache = {
        openssl: detectCommandVersion('openssl', ['version']),
        keytool: detectCommandVersion('keytool', ['-J-version']),
    };
    toolAvailabilityCacheTime = now;
    return toolAvailabilityCache;
}

export function inspectPkcs12File(filePath: string, password?: string): PkcsInspectionResult {
    const availability = detectExternalToolAvailability();
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
    const result = runCommand('openssl', commandArgs, password ?? '');
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
        warnings: result.ok ? artifact?.warnings ?? [] : [result.stderr || 'OpenSSL command failed.'],
        rawOutput: result.ok ? result.stdout : result.stderr,
    };
}

export function inspectPkcs7File(filePath: string): PkcsInspectionResult {
    const availability = detectExternalToolAvailability();
    if (!availability.openssl.available) {
        return {
            summary: 'OpenSSL is not available. PKCS#7 inspection is limited to command recipes.',
            command: buildOpenSslCommand(['pkcs7', '-in', filePath, '-print_certs']),
            warnings: ['OpenSSL is not available on this machine.'],
            rawOutput: '',
        };
    }

    const result = runCommand('openssl', ['pkcs7', '-in', filePath, '-print_certs']);
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
        warnings: result.ok ? artifact?.warnings ?? [] : [result.stderr || 'OpenSSL command failed.'],
        rawOutput: result.ok ? result.stdout : result.stderr,
    };
}

export function inspectRemoteCertificate(target: string): RemoteInspectionResult {
    const availability = detectExternalToolAvailability();
    if (!availability.openssl.available) {
        throw new Error('OpenSSL is required for remote certificate inspection.');
    }

    const { host, port } = normalizeRemoteTarget(target);
    const result = runCommand('openssl', ['s_client', '-showcerts', '-servername', host, '-connect', `${host}:${port}`], '', 15000);
    if (!result.ok) {
        throw new Error(result.stderr || 'OpenSSL s_client failed.');
    }

    // parseCertificateInputFromText always runs analyzeCertificateChain when certificates are
    // found, so artifact.chain is already populated — no need to recompute it here.
    const artifact = parseCertificateInputFromText(result.stdout, {
        kind: 'remote',
        label: `${host}:${port}`,
        host: `${host}:${port}`,
    });

    return {
        artifact,
        command: result.command,
        warnings: artifact.warnings,
        rawOutput: result.stdout,
    };
}

export function verifyWithOpenSsl(
    certificatePem: string,
    chainPem?: string,
    caFile?: string,
    caPath?: string
): { issues: ValidationIssue[]; command: string; rawOutput: string } {
    const availability = detectExternalToolAvailability();
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
    fs.writeFileSync(leafFile, certificatePem);
    if (chainPem) {
        fs.writeFileSync(chainFile, chainPem);
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
        result = runCommand('openssl', args);
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
        buildOpenSslCommand([
            'pkcs12',
            '-in',
            filePath,
            ...passwordArgs,
            '-clcerts',
            '-nokeys',
            '-out',
            certificateOutputPath,
        ]),
        buildOpenSslCommand(['pkcs12', '-in', filePath, ...passwordArgs, '-nocerts', '-nodes', '-out', keyOutputPath]),
    ].join('\n');
}

export function listJksAliases(filePath: string, password?: string): { summary: string; command: string; rawOutput: string } {
    const availability = detectExternalToolAvailability();

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

        const result = runCommand('keytool', execArgs);
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

function detectCommandVersion(command: string, args: string[]): { available: boolean; version?: string; error?: string } {
    try {
        const result = childProcess.spawnSync(command, args, {
            encoding: 'utf8',
            timeout: 5000,
        });
        const output = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();
        // result.error is set when spawnSync itself fails (e.g. ENOENT or SIGTERM timeout).
        // Treat that as unavailable even if there happened to be partial output.
        if ((result.status === 0 || output) && !result.error) {
            const version = output.split('\n')[0]?.trim();
            return {
                available: true,
                version,
            };
        }

        return {
            available: false,
            error: output || `Failed to execute ${command}.`,
        };
    } catch (error) {
        return {
            available: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

function runCommand(command: string, args: string[], input?: string, timeout = 10000): CommandResult {
    const result = childProcess.spawnSync(command, args, {
        input,
        encoding: 'utf8',
        timeout,
    });

    const commandString = [command, ...args.map(shellQuote)].join(' ');
    return {
        ok: result.status === 0,
        stdout: result.stdout ?? '',
        stderr: result.stderr ?? '',
        command: commandString,
    };
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

function normalizeRemoteTarget(target: string): { host: string; port: number } {
    const trimmed = target.trim();
    if (!trimmed) {
        throw new Error('Remote target is required.');
    }

    const lastColonIndex = trimmed.lastIndexOf(':');
    if (lastColonIndex > -1 && trimmed.indexOf(']') === -1) {
        const host = trimmed.slice(0, lastColonIndex);
        const port = Number.parseInt(trimmed.slice(lastColonIndex + 1), 10);
        if (Number.isInteger(port) && port > 0 && port <= 65535) {
            return { host, port };
        }
    }

    return {
        host: trimmed,
        port: 443,
    };
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
