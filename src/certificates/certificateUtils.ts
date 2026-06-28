import * as crypto from 'crypto';
import * as fs from 'fs';
import * as net from 'net';
import * as path from 'path';

export const SUPPORTED_CERTIFICATE_EXTENSIONS = ['.crt', '.cer', '.cert', '.pem', '.der', '.ca-bundle', '.ca', '.bundle'];
export const CLASSIFIED_ARTIFACT_EXTENSIONS = ['.jks', '.p12', '.pfx', '.p7b', '.p7c', '.p7s', '.csr', '.key'];

export type CertificateStatus = 'valid' | 'expiring' | 'expired';
export type CertificateArtifactKind =
    | 'x509-cert'
    | 'cert-chain'
    | 'csr'
    | 'pkcs12'
    | 'pkcs7'
    | 'private-key'
    | 'jks'
    | 'unknown';
export type CertificateInputEncoding = 'PEM' | 'DER' | 'P12' | 'P7B' | 'JKS' | 'TEXT' | 'UNKNOWN';
export type CertificateInputSourceKind = 'pasted' | 'file' | 'active-editor' | 'remote';
export type ValidationSeverity = 'error' | 'warning' | 'info';
export type ValidationPurpose = 'serverAuth' | 'clientAuth' | 'codeSigning' | 'emailProtection';
export type CertificateChainRole = 'leaf' | 'intermediate' | 'root' | 'unknown';

export interface CertificateInputSource {
    kind: CertificateInputSourceKind;
    label: string;
    filePath?: string;
    host?: string;
}

export interface ExternalToolStatus {
    available: boolean;
    version?: string;
    error?: string;
}

export interface ExternalToolAvailability {
    openssl: ExternalToolStatus;
    keytool: ExternalToolStatus;
}

export interface ValidationIssue {
    severity: ValidationSeverity;
    code: string;
    message: string;
    details?: string;
}

export interface ParsedCertificateDetails {
    pem: string;
    subject: string;
    subjectCommonName: string;
    issuer: string;
    issuerCommonName: string;
    validFrom: string;
    validTo: string;
    serialNumber: string;
    fingerprint: string;
    fingerprint256: string;
    fingerprint512: string;
    keyUsage: string[];
    extendedKeyUsage: string[];
    subjectAltName: string;
    subjectAltNames: string[];
    infoAccess: string;
    infoAccessEntries: string[];
    ocspUrls: string[];
    caIssuersUrls: string[];
    crlDistributionPoints: string[];
    type: string;
    algorithm: string;
    format: string;
    signatureAlgorithm: string;
    publicKeyAlgorithm: string;
    bits?: number;
    isCertificateAuthority: boolean;
    isSelfSigned: boolean;
    purposeHints: ValidationPurpose[];
}

export interface CertificateChainEntry {
    index: number;
    role: CertificateChainRole;
    subjectCommonName: string;
    issuerCommonName: string;
    serialNumber: string;
    isSelfSigned: boolean;
}

export interface CertificateChainDetails {
    entries: CertificateChainEntry[];
    warnings: string[];
    duplicateSerialNumbers: string[];
    leafIndex?: number;
    rootIndex?: number;
}

export interface ParsedCertificateArtifact {
    kind: CertificateArtifactKind;
    encoding: CertificateInputEncoding;
    source: CertificateInputSource;
    warnings: string[];
    blockTypes: string[];
    certificates: ParsedCertificateDetails[];
    chain?: CertificateChainDetails;
    rawText?: string;
    filePath?: string;
}

export interface CertificateValidationResult {
    status: CertificateStatus;
    valid: boolean;
    issues: ValidationIssue[];
    summary: string;
}

export interface ValidationOptions {
    hostname?: string;
    purpose?: ValidationPurpose;
    referenceDate?: Date;
}

export interface CertificateDetails {
    subject: string;
    subjectCommonName: string;
    issuer: string;
    issuerCommonName: string;
    validFrom: string;
    validTo: string;
    serialNumber: string;
    fingerprint: string;
    fingerprint256: string;
    keyUsage: string[];
    subjectAltName: string;
    infoAccess: string;
    type: string;
    algorithm: string;
    format: string;
}

export interface ScannedCertificate {
    id: string;
    name: string;
    owner: string;
    type: string;
    expiryDate: string;
    filePath: string;
    issuer: string;
    validFrom: string;
    serialNumber: string;
    fingerprint: string;
    algorithm: string;
    format: string;
}

interface PemBlock {
    type: string;
    pem: string;
}

interface ArtifactParseOptions {
    source: CertificateInputSource;
    content?: string | Buffer;
    filePath?: string;
}

export function normalizePem(input: string, type = 'CERTIFICATE'): string {
    const trimmed = input.trim();
    if (!trimmed) {
        throw new Error('Certificate content is empty.');
    }

    if (trimmed.includes(`-----BEGIN ${type}-----`)) {
        return trimmed;
    }

    const body = trimmed.replace(/\s+/g, '');
    return `-----BEGIN ${type}-----\n${body.match(/.{1,64}/g)?.join('\n') ?? ''}\n-----END ${type}-----`;
}

export function extractPemBlocks(content: string): string[] {
    return matchPemBlocks(content).map((block) => block.pem);
}

export function parseCertificateContent(content: string | Buffer, format = 'PEM'): CertificateDetails {
    return toCertificateDetails(createParsedCertificateDetails(createX509Certificate(content), asPemString(content), format));
}

export function parseCertificateFile(filePath: string): CertificateDetails {
    const artifact = parseArtifact({
        source: {
            kind: 'file',
            label: path.basename(filePath),
            filePath,
        },
        filePath,
    });

    if (!artifact.certificates.length) {
        throw new Error(`No X.509 certificate could be parsed from ${filePath}.`);
    }

    return toCertificateDetails(artifact.certificates[0]);
}

export function scanCertificateFile(filePath: string): ScannedCertificate {
    const details = parseCertificateFile(filePath);
    const fileFormat = formatFromFilePath(filePath);

    return {
        id: generateCertificateId(filePath, details.serialNumber),
        name: path.basename(filePath),
        owner: details.subjectCommonName,
        type: details.type,
        expiryDate: details.validTo,
        filePath,
        issuer: details.issuerCommonName,
        validFrom: details.validFrom,
        serialNumber: details.serialNumber,
        fingerprint: details.fingerprint,
        algorithm: details.algorithm,
        format: fileFormat,
    };
}

export function parseCertificateInputFromText(content: string, source: CertificateInputSource): ParsedCertificateArtifact {
    return parseArtifact({ source, content });
}

export function parseCertificateInputFromFile(filePath: string, sourceKind: CertificateInputSourceKind = 'file'): ParsedCertificateArtifact {
    return parseArtifact({
        source: {
            kind: sourceKind,
            label: sourceKind === 'active-editor' ? `Active editor: ${path.basename(filePath)}` : path.basename(filePath),
            filePath,
        },
        filePath,
    });
}

export function validateArtifact(artifact: ParsedCertificateArtifact, options: ValidationOptions = {}): CertificateValidationResult {
    if (!artifact.certificates.length) {
        return {
            status: 'valid',
            valid: false,
            summary: 'No X.509 certificates available to validate.',
            issues: [
                {
                    severity: 'error',
                    code: 'no-certificates',
                    message: 'The selected artifact does not contain a parseable X.509 certificate.',
                },
            ],
        };
    }

    const issues: ValidationIssue[] = [];
    const leaf = artifact.chain?.leafIndex !== undefined ? artifact.certificates[artifact.chain.leafIndex] : artifact.certificates[0];
    const referenceDate = options.referenceDate ?? new Date();
    const validFrom = new Date(leaf.validFrom);
    const validTo = new Date(leaf.validTo);

    if (referenceDate < validFrom) {
        issues.push({
            severity: 'error',
            code: 'not-yet-valid',
            message: `Certificate is not valid before ${validFrom.toISOString()}.`,
        });
    }

    const status = getCertificateStatus(validTo, referenceDate);
    if (status === 'expired') {
        issues.push({
            severity: 'error',
            code: 'expired',
            message: `Certificate expired on ${validTo.toISOString()}.`,
        });
    } else if (status === 'expiring') {
        issues.push({
            severity: 'warning',
            code: 'expiring-soon',
            message: `Certificate expires soon on ${validTo.toISOString()}.`,
        });
    } else {
        issues.push({
            severity: 'info',
            code: 'valid-window',
            message: `Certificate is within its validity window until ${validTo.toISOString()}.`,
        });
    }

    if (leaf.isSelfSigned) {
        issues.push({
            severity: leaf.isCertificateAuthority ? 'info' : 'warning',
            code: 'self-signed',
            message: leaf.isCertificateAuthority
                ? 'Certificate is self-signed and acts as a certificate authority.'
                : 'Certificate is self-signed.',
        });
    }

    issues.push({
        severity: 'info',
        code: leaf.isCertificateAuthority ? 'certificate-authority' : 'leaf-certificate',
        message: leaf.isCertificateAuthority ? 'Certificate is marked as a CA certificate.' : 'Certificate is marked as a leaf certificate.',
    });

    if (options.hostname) {
        const match = validateHostname(leaf, options.hostname);
        if (match) {
            issues.push({
                severity: 'info',
                code: 'hostname-match',
                message: `Hostname ${options.hostname} matches the certificate.`,
            });
        } else {
            issues.push({
                severity: 'error',
                code: 'hostname-mismatch',
                message: `Hostname ${options.hostname} does not match the certificate subject or SAN entries.`,
            });
        }
    }

    if (options.purpose) {
        if (!leaf.extendedKeyUsage.length) {
            issues.push({
                severity: 'warning',
                code: 'eku-missing',
                message: `Extended Key Usage is not present, so ${options.purpose} could not be confirmed.`,
            });
        } else if (leaf.purposeHints.includes(options.purpose)) {
            issues.push({
                severity: 'info',
                code: 'eku-match',
                message: `Certificate Extended Key Usage supports ${options.purpose}.`,
            });
        } else {
            issues.push({
                severity: 'error',
                code: 'eku-mismatch',
                message: `Certificate Extended Key Usage does not support ${options.purpose}.`,
            });
        }
    }

    if (artifact.chain) {
        for (const warning of artifact.chain.warnings) {
            issues.push({
                severity: 'warning',
                code: 'chain-warning',
                message: warning,
            });
        }
    }

    const valid = !issues.some((issue) => issue.severity === 'error');
    return {
        status,
        valid,
        issues,
        summary: valid ? 'Certificate validation passed with no errors.' : 'Certificate validation detected one or more errors.',
    };
}

export function analyzeCertificateChain(certificates: ParsedCertificateDetails[]): CertificateChainDetails | undefined {
    if (!certificates.length) {
        return undefined;
    }

    const duplicateSerialNumbers = findDuplicates(certificates.map((certificate) => certificate.serialNumber));
    const warnings: string[] = [];
    const issuerSubjects = new Set(certificates.map((certificate) => certificate.subject));
    const entries: CertificateChainEntry[] = certificates.map((certificate, index) => {
        const issuesOthers = certificates.some((candidate, candidateIndex) => {
            if (candidateIndex === index) {
                return false;
            }
            return candidate.issuer === certificate.subject;
        });

        let role: CertificateChainRole = 'unknown';
        if (certificate.isSelfSigned) {
            role = 'root';
        } else if (!issuesOthers) {
            role = 'leaf';
        } else {
            role = 'intermediate';
        }

        return {
            index,
            role,
            subjectCommonName: certificate.subjectCommonName,
            issuerCommonName: certificate.issuerCommonName,
            serialNumber: certificate.serialNumber,
            isSelfSigned: certificate.isSelfSigned,
        };
    });

    const leafIndex = entries.find((entry) => entry.role === 'leaf')?.index;
    const rootIndex = entries.find((entry) => entry.role === 'root')?.index;

    for (let index = 0; index < certificates.length - 1; index += 1) {
        if (certificates[index].issuer !== certificates[index + 1].subject) {
            warnings.push(
                `Certificate ${index + 1} issuer does not match certificate ${index + 2} subject. The bundle may be out of order or incomplete.`
            );
        }
    }

    if (certificates.length > 1 && rootIndex === undefined) {
        warnings.push('No self-signed root certificate was detected in the chain.');
    }

    if (duplicateSerialNumbers.length) {
        warnings.push(`Duplicate certificate serial numbers detected: ${duplicateSerialNumbers.join(', ')}`);
    }

    for (const certificate of certificates) {
        if (!certificate.isSelfSigned && !issuerSubjects.has(certificate.issuer)) {
            warnings.push(`Missing issuer certificate for ${certificate.subjectCommonName || certificate.subject}.`);
        }
    }

    return {
        entries,
        warnings,
        duplicateSerialNumbers,
        leafIndex,
        rootIndex,
    };
}

export function validateHostname(certificate: ParsedCertificateDetails, hostname: string): boolean {
    const normalizedHost = hostname.trim();
    if (!normalizedHost) {
        return false;
    }

    const cert = createX509Certificate(certificate.pem);
    if (net.isIP(normalizedHost)) {
        return cert.checkIP(normalizedHost) !== undefined;
    }
    return cert.checkHost(normalizedHost) !== undefined;
}

export function extractFirstPemCertificate(content: string): string {
    const first = matchPemBlocks(content).find((block) => block.type === 'CERTIFICATE');
    if (!first) {
        throw new Error('No PEM certificate block found.');
    }
    return first.pem;
}

export function getCertificateStatus(validTo: string | Date, referenceDate = new Date()): CertificateStatus {
    const expiryDate = validTo instanceof Date ? validTo : new Date(validTo);
    if (Number.isNaN(expiryDate.getTime())) {
        throw new Error('Certificate expiry date is invalid.');
    }

    const expiringThreshold = new Date(referenceDate);
    expiringThreshold.setMonth(expiringThreshold.getMonth() + 1);

    if (expiryDate < referenceDate) {
        return 'expired';
    }

    if (expiryDate < expiringThreshold) {
        return 'expiring';
    }

    return 'valid';
}

export function extractCommonName(subject: string): string {
    const cnMatch = subject.match(/(?:^|\n|,)\s*CN\s*=\s*([^,\n]+)/);
    return cnMatch ? cnMatch[1].trim() : subject.split('\n')[0]?.trim() || 'Unknown';
}

export function formatFromFilePath(filePath: string): string {
    const ext = path.extname(filePath).toLowerCase();
    return ext.startsWith('.') ? ext.slice(1).toUpperCase() : 'UNKNOWN';
}

function parseArtifact(options: ArtifactParseOptions): ParsedCertificateArtifact {
    const filePath = options.filePath;
    const extension = filePath ? path.extname(filePath).toLowerCase() : '';
    const encoding = detectEncoding(filePath);
    const rawContent = options.content ?? (filePath ? fs.readFileSync(filePath) : '');
    const rawText = typeof rawContent === 'string' ? rawContent : rawContent.toString('utf8');
    const pemBlocks = typeof rawContent === 'string' ? matchPemBlocks(rawContent) : matchPemBlocks(rawText);
    const blockTypes = [...new Set(pemBlocks.map((block) => block.type))];
    const warnings: string[] = [];
    const certificates = parseCertificatesFromInput(rawContent, extension, pemBlocks, warnings);

    let kind: CertificateArtifactKind = 'unknown';
    if (certificates.length > 1) {
        kind = 'cert-chain';
    } else if (certificates.length === 1) {
        kind = 'x509-cert';
    } else if (blockTypes.some((type) => type.includes('CERTIFICATE REQUEST'))) {
        kind = 'csr';
    } else if (blockTypes.some((type) => type.includes('PRIVATE KEY'))) {
        kind = 'private-key';
    } else if (['.p12', '.pfx'].includes(extension)) {
        kind = 'pkcs12';
    } else if (['.p7b', '.p7c', '.p7s'].includes(extension)) {
        kind = 'pkcs7';
    } else if (extension === '.jks') {
        kind = 'jks';
    }

    const chain = certificates.length ? analyzeCertificateChain(certificates) : undefined;
    return {
        kind,
        encoding,
        source: options.source,
        warnings: [...warnings, ...(chain?.warnings ?? [])],
        blockTypes,
        certificates,
        chain,
        rawText: typeof rawContent === 'string' ? rawContent : undefined,
        filePath,
    };
}

function parseCertificatesFromInput(
    rawContent: string | Buffer,
    extension: string,
    pemBlocks: PemBlock[],
    warnings: string[]
): ParsedCertificateDetails[] {
    const certificates: ParsedCertificateDetails[] = [];
    const certificateBlocks = pemBlocks.filter((block) => block.type === 'CERTIFICATE');

    for (const block of certificateBlocks) {
        try {
            certificates.push(createParsedCertificateDetails(createX509Certificate(block.pem), block.pem, 'PEM'));
        } catch (error) {
            warnings.push(`Failed to parse PEM certificate block: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    if (certificates.length) {
        return certificates;
    }

    if (typeof rawContent !== 'string' && shouldAttemptDerParsing(extension)) {
        try {
            return [createParsedCertificateDetails(createX509Certificate(rawContent), rawContent.toString('base64'), 'DER')];
        } catch {
            // Fall through to classification-only behavior.
        }
    }

    return [];
}

function createParsedCertificateDetails(cert: crypto.X509Certificate, pem: string, format: string): ParsedCertificateDetails {
    const certWithExtendedProperties = cert as crypto.X509Certificate & {
        signatureAlgorithm?: string;
    };
    const legacy = cert.toLegacyObject() as {
        ca?: boolean;
        bits?: number;
        asn1Curve?: string;
        nistCurve?: string;
        ext_key_usage?: string[];
        subjectaltname?: string;
        infoAccess?: string;
    };
    const subjectAltName = cert.subjectAltName ?? legacy.subjectaltname ?? 'N/A';
    const infoAccess = cert.infoAccess ?? legacy.infoAccess ?? 'N/A';
    const keyUsage = cert.keyUsage ?? [];
    const extendedKeyUsage = legacy.ext_key_usage ?? [];
    const purposeHints = derivePurposeHints(keyUsage, extendedKeyUsage);
    const publicKeyDetails = cert.publicKey.asymmetricKeyType
        ? cert.publicKey.asymmetricKeyType.toUpperCase()
        : legacy.asn1Curve || legacy.nistCurve || 'Unknown';

    return {
        pem: pem.includes('-----BEGIN') ? pem : cert.toString(),
        subject: cert.subject,
        subjectCommonName: extractCommonName(cert.subject),
        issuer: cert.issuer,
        issuerCommonName: extractCommonName(cert.issuer),
        validFrom: cert.validFrom,
        validTo: cert.validTo,
        serialNumber: cert.serialNumber,
        fingerprint: cert.fingerprint,
        fingerprint256: cert.fingerprint256,
        fingerprint512: cert.fingerprint512,
        keyUsage,
        extendedKeyUsage,
        subjectAltName,
        subjectAltNames: splitMultilineField(subjectAltName),
        infoAccess,
        infoAccessEntries: splitMultilineField(infoAccess),
        ocspUrls: extractInfoAccessValues(infoAccess, 'OCSP'),
        caIssuersUrls: extractInfoAccessValues(infoAccess, 'CA Issuers'),
        crlDistributionPoints: [],
        type: determineCertificateType(cert, keyUsage, extendedKeyUsage),
        algorithm: extractAlgorithm(cert),
        format,
        signatureAlgorithm: certWithExtendedProperties.signatureAlgorithm || 'Unknown',
        publicKeyAlgorithm: publicKeyDetails,
        bits: typeof legacy.bits === 'number' ? legacy.bits : undefined,
        isCertificateAuthority: cert.ca,
        isSelfSigned: cert.subject === cert.issuer,
        purposeHints,
    };
}

function determineCertificateType(
    cert: crypto.X509Certificate,
    keyUsage: string[],
    extendedKeyUsage: string[]
): string {
    const subject = cert.subject.toLowerCase();
    const usages = new Set([...keyUsage, ...extendedKeyUsage.map((usage) => usage.toLowerCase())]);

    if (cert.ca) {
        return 'Certificate Authority';
    }

    if (usages.has('1.3.6.1.5.5.7.3.3') || subject.includes('code')) {
        return 'Code Signing';
    }

    if (usages.has('1.3.6.1.5.5.7.3.2') || subject.includes('client')) {
        return 'Client Authentication';
    }

    return 'TLS/SSL';
}

function extractAlgorithm(cert: crypto.X509Certificate): string {
    return cert.fingerprint256 ? 'SHA256' : 'Unknown';
}

function generateCertificateId(filePath: string, serialNumber: string): string {
    return crypto.createHash('sha256').update(`${filePath}:${serialNumber}`).digest('hex').slice(0, 16);
}

function createX509Certificate(content: string | Buffer): crypto.X509Certificate {
    return new crypto.X509Certificate(content);
}

function matchPemBlocks(content: string): PemBlock[] {
    const blocks: PemBlock[] = [];
    const pattern = /-----BEGIN ([^-]+)-----[\s\S]*?-----END \1-----/g;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
        blocks.push({
            type: match[1].trim(),
            pem: match[0],
        });
    }
    return blocks;
}

function detectEncoding(filePath?: string): CertificateInputEncoding {
    const extension = filePath ? path.extname(filePath).toLowerCase() : '';
    switch (extension) {
        case '.der':
            return 'DER';
        case '.p12':
        case '.pfx':
            return 'P12';
        case '.p7b':
        case '.p7c':
        case '.p7s':
            return 'P7B';
        case '.jks':
            return 'JKS';
        case '.pem':
        case '.crt':
        case '.cer':
        case '.cert':
        case '.ca':
        case '.bundle':
        case '.ca-bundle':
            return 'PEM';
        case '.txt':
            return 'TEXT';
        default:
            return extension ? 'UNKNOWN' : 'TEXT';
    }
}

function shouldAttemptDerParsing(extension: string): boolean {
    return extension === '.der' || SUPPORTED_CERTIFICATE_EXTENSIONS.includes(extension);
}

function asPemString(content: string | Buffer): string {
    if (typeof content === 'string') {
        return content;
    }
    return normalizePem(content.toString('base64'));
}

function derivePurposeHints(keyUsage: string[], extendedKeyUsage: string[]): ValidationPurpose[] {
    const usages = new Set(extendedKeyUsage);
    const hints: ValidationPurpose[] = [];

    if (usages.has('1.3.6.1.5.5.7.3.1') || keyUsage.includes('digitalSignature') || keyUsage.includes('keyEncipherment')) {
        hints.push('serverAuth');
    }
    if (usages.has('1.3.6.1.5.5.7.3.2') || keyUsage.includes('digitalSignature')) {
        hints.push('clientAuth');
    }
    if (usages.has('1.3.6.1.5.5.7.3.3')) {
        hints.push('codeSigning');
    }
    if (usages.has('1.3.6.1.5.5.7.3.4')) {
        hints.push('emailProtection');
    }

    return [...new Set(hints)];
}

function splitMultilineField(value: string): string[] {
    if (!value || value === 'N/A') {
        return [];
    }

    return value
        .split(/\n|,\s(?=[A-Z0-9.-]+:)/)
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0);
}

function extractInfoAccessValues(value: string, prefix: string): string[] {
    const separator = ' - ';
    const lowerPrefix = prefix.toLowerCase();
    return splitMultilineField(value)
        .filter((entry) => entry.toLowerCase().startsWith(lowerPrefix))
        .map((entry) => {
            const sepIndex = entry.indexOf(separator);
            return sepIndex !== -1 ? entry.slice(sepIndex + separator.length).trim() : '';
        })
        .filter((entry) => entry.length > 0);
}

function findDuplicates(values: string[]): string[] {
    const counts = new Map<string, number>();
    for (const value of values) {
        counts.set(value, (counts.get(value) ?? 0) + 1);
    }

    return [...counts.entries()].filter(([, count]) => count > 1).map(([value]) => value);
}

function toCertificateDetails(details: ParsedCertificateDetails): CertificateDetails {
    return {
        subject: details.subject,
        subjectCommonName: details.subjectCommonName,
        issuer: details.issuer,
        issuerCommonName: details.issuerCommonName,
        validFrom: details.validFrom,
        validTo: details.validTo,
        serialNumber: details.serialNumber,
        fingerprint: details.fingerprint,
        fingerprint256: details.fingerprint256,
        keyUsage: details.keyUsage,
        subjectAltName: details.subjectAltName,
        infoAccess: details.infoAccess,
        type: details.type,
        algorithm: details.algorithm,
        format: details.format,
    };
}
