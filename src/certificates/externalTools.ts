import * as childProcess from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
    ExternalToolAvailability,
    ParsedCertificateArtifact,
    ParsedCertificateDetails,
    ValidationIssue,
    analyzeCertificateChain,
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

let toolAvailabilityCache: ExternalToolAvailability | undefined;

export function detectExternalToolAvailability(forceRefresh = false): ExternalToolAvailability {
    if (!forceRefresh && toolAvailabilityCache) {
        return toolAvailabilityCache;
    }

    toolAvailabilityCache = {
        openssl: detectCommandVersion('openssl', ['version']),
        keytool: detectCommandVersion('keytool', ['-J-version']),
    };
    return toolAvailabilityCache;
}

export function inspectPkcs12File(filePath: string, password?: string): PkcsInspectionResult {
    const availability = detectExternalToolAvailability();
    if (!availability.openssl.available) {
        return {
            summary: 'OpenSSL is not available. PKCS#12 inspection is limited to command recipes.',
            command: buildOpenSslCommand(['pkcs12', '-info', '-in', filePath]),
            warnings: ['OpenSSL is not available on this machine.'],
            rawOutput: '',
        };
    }

    const passArg = password ? `pass:${password}` : 'pass:';
    const commandArgs = ['pkcs12', '-in', filePath, '-nodes', '-nokeys', '-passin', passArg];
    const result = runCommand('openssl', commandArgs);
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

    const artifact = parseCertificateInputFromText(result.stdout, {
        kind: 'remote',
        label: `${host}:${port}`,
        host: `${host}:${port}`,
    });

    return {
        artifact: {
            ...artifact,
            chain: artifact.chain ?? analyzeCertificateChain(artifact.certificates),
        },
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

    const result = runCommand('openssl', args);
    fs.rmSync(tempDirectory, { recursive: true, force: true });

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
        args.push('-password', `pass:${password}`);
    }
    return buildOpenSslCommand(args);
}

export function listJksAliases(filePath: string, password?: string): { summary: string; command: string; rawOutput: string } {
    const availability = detectExternalToolAvailability();
    const args = ['-list', '-keystore', filePath];
    if (password) {
        args.push('-storepass', password);
    }

    if (!availability.keytool.available) {
        return {
            summary: 'keytool is not available. The extension can only show the command recipe.',
            command: buildKeytoolCommand(args),
            rawOutput: '',
        };
    }

    const result = runCommand('keytool', args);
    return {
        summary: result.ok ? 'JKS aliases listed successfully.' : 'keytool could not list JKS aliases.',
        command: result.command,
        rawOutput: result.ok ? result.stdout : result.stderr,
    };
}

export function buildJksExportCommand(filePath: string, alias: string): string {
    return buildKeytoolCommand(['-exportcert', '-alias', alias, '-keystore', filePath, '-rfc', '-file', 'certificate.pem']);
}

export function buildJksToPkcs12Command(filePath: string): string {
    return buildKeytoolCommand(['-importkeystore', '-srckeystore', filePath, '-destkeystore', 'keystore.p12', '-deststoretype', 'PKCS12']);
}

function detectCommandVersion(command: string, args: string[]): { available: boolean; version?: string; error?: string } {
    try {
        const result = childProcess.spawnSync(command, args, {
            encoding: 'utf8',
            timeout: 5000,
        });
        const output = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();
        if (result.status === 0 || output) {
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
        if (Number.isInteger(port) && port > 0) {
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
