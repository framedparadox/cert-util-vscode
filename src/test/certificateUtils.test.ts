import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
    MAX_CERTIFICATE_FILE_BYTES,
    analyzeCertificateChain,
    assessAlgorithmStrength,
    extractPemBlocks,
    getCertificateStatus,
    normalizePem,
    parseCertificateContent,
    parseCertificateFile,
    parseCertificateInputFromFile,
    parseCertificateInputFromText,
    scanCertificateFile,
    validateArtifact,
} from '../certificates/certificateUtils';
import {
    buildDerToPemCommand,
    buildJksExportCommand,
    buildJksPemExportCommands,
    buildJksToPkcs12Command,
    buildPemToDerCommand,
    buildPkcs12ExportCommand,
    buildPkcs12PemExportCommands,
    detectExternalToolAvailability,
    parsePkcsCertificateOutput,
    parseRemoteInspectionOutput,
    parseRemoteTarget,
} from '../certificates/externalTools';

const TEST_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDXjCCAkagAwIBAgIUbKwyVr4ExYLNKN3TRmJi57jnSaowDQYJKoZIhvcNAQEL
BQAwKjEUMBIGA1UEAwwLZXhhbXBsZS5jb20xEjAQBgNVBAoMCUNlcnQgVXRpbDAe
Fw0yNjA2MTgwMzAwMDhaFw0yNzA2MTgwMzAwMDhaMCoxFDASBgNVBAMMC2V4YW1w
bGUuY29tMRIwEAYDVQQKDAlDZXJ0IFV0aWwwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCvxcE/gD6wz+0bEnSn1qQBParH2flcFcUZ8aNDaqrGvRWrRYe6
oJcZ0Lo8jtBW4kS0k/DTW/JYFWMGvbyMOnk8YyUKkfc/fvOasPvMvwC6nAVFytii
nNtGkjQseoecJY8woeiVbmqV/cyGdE/IXLhFk6IzXZoUhHiMVOA+tbgfHb1kf4AY
aMnpuzfXKgqNc3eohIkr5dR97nhkKU3GlXgrk3aDyrX3mqMAaqOCd6SKDfUgqgxF
oXZLWvpXPChaQ0zX4aAa7F69uvJJYUGj+MT3+qftPnVb6ZVw4/RVrSYj2PhC8gj2
N0WPl+o1tmAlN1YUDriaj8b4BAVR/Bj2Lxn1AgMBAAGjfDB6MB0GA1UdDgQWBBTM
EwdNmLzK4HUz/wd3HeyGxD4teDAfBgNVHSMEGDAWgBTMEwdNmLzK4HUz/wd3HeyG
xD4teDAPBgNVHRMBAf8EBTADAQH/MCcGA1UdEQQgMB6CC2V4YW1wbGUuY29tggls
b2NhbGhvc3SHBH8AAAEwDQYJKoZIhvcNAQELBQADggEBAJq98i2MHHPU6g7n6QP1
S1d7+qHWOe6Sv/Zy0L1/BgyMNtoJZtYWjA6woAOjNWcNwk+Fp22dsVmWHyDO7Xmj
aAwnlD8JJAlnI5XzIxUnsTLSRS1TQqOQ9MjHjormwu877zqUdcpqAX/mA2LPN/Bm
SDGF5l6c5jRnfdEk3eV4reBVsOj4pwzDuQP6kcGU2Z6ar99+UhC7LbnTWjfXCXg0
SeNoYZaR09FOn4PKkvkhrrKlcJPUdDzfR1ws6wsboRTUtY4lQAqNxrm5L4bpALMX
QOFDPhUMv4AdoXykNwESDe/tmomE6MOaQjLPJwSixjiTYl7XxM8i6Nzj3dIa+eHe
I7Y=
-----END CERTIFICATE-----`;

const TEST_CSR_PEM = `-----BEGIN CERTIFICATE REQUEST-----
MIIBVTCBvwIBADAcMRowGAYDVQQDDBFjc3IuZXhhbXBsZS50ZXN0MIGfMA0GCSqG
SIb3DQEBAQUAA4GNADCBiQKBgQC2X2MS98m18m5GsLzJ7I0r8n07akQyycGldAZR
2g9BIKmj6r6SJ4Prmb6vKJ40PAA7Fo/U1m8vnB7kdLqUs0RrXmKh6rPFY1Q1yDX2
11O79z8aJmxdOQ2Y+zbofbLTgN0mFM7P+IYIcJtJQ3A5SlQ0j3QanPEYzXw2Thfx
5V76LwIDAQABoAAwDQYJKoZIhvcNAQELBQADgYEAKe6E8r5vB8ZBeuZ54r/5iUw7
uLwSJDRPQ4V8FAxE8/6yeeqv14IyqXhS3CxKQ0QjxQjeUn1l1eBv9M3gVsER+v7l
8Q9FF7q7Z+vA2qv1QnCHMw46FnmKYrtkM6d4qsTM+qE11wX8f0a2J3HcN0EuL4O3
9QjRk+W8s2nLFBvTO0U=
-----END CERTIFICATE REQUEST-----`;

const TEST_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDq
-----END PRIVATE KEY-----`;

suite('certificateUtils', () => {
    test('normalizes bare certificate base64 into PEM', () => {
        const body = TEST_CERT_PEM.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
        const normalized = normalizePem(body);

        assert.ok(normalized.startsWith('-----BEGIN CERTIFICATE-----'));
        assert.ok(normalized.endsWith('-----END CERTIFICATE-----'));
        assert.ok(normalized.includes(body.slice(0, 64)));
    });

    test('extracts PEM blocks from bundle text', () => {
        const bundle = `${TEST_CERT_PEM}\n${TEST_CSR_PEM}`;
        const blocks = extractPemBlocks(bundle);
        assert.strictEqual(blocks.length, 2);
    });

    test('decodes PEM and captures structured certificate fields', () => {
        const details = parseCertificateContent(TEST_CERT_PEM, 'PEM');
        assert.strictEqual(details.subjectCommonName, 'example.com');
        assert.strictEqual(details.issuerCommonName, 'example.com');
        assert.strictEqual(details.format, 'PEM');
        assert.ok(details.fingerprint.includes(':'));
        assert.ok(details.subjectAltName.includes('DNS:example.com'));
    });

    test('parses DER certificate content', () => {
        const der = new crypto.X509Certificate(TEST_CERT_PEM).raw;
        const details = parseCertificateContent(der, 'DER');

        assert.strictEqual(details.subjectCommonName, 'example.com');
        assert.strictEqual(details.format, 'DER');
    });

    test('classifies PEM bundles, CSR, and private keys', () => {
        const chainArtifact = parseCertificateInputFromText(`${TEST_CERT_PEM}\n${TEST_CERT_PEM}`, {
            kind: 'pasted',
            label: 'bundle',
        });
        const csrArtifact = parseCertificateInputFromText(TEST_CSR_PEM, {
            kind: 'pasted',
            label: 'csr',
        });
        const keyArtifact = parseCertificateInputFromText(TEST_PRIVATE_KEY_PEM, {
            kind: 'pasted',
            label: 'key',
        });

        assert.strictEqual(chainArtifact.kind, 'cert-chain');
        assert.strictEqual(chainArtifact.certificates.length, 2);
        assert.strictEqual(csrArtifact.kind, 'csr');
        assert.strictEqual(keyArtifact.kind, 'private-key');
    });

    test('parses and scans a PEM certificate file', () => {
        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-util-test-'));
        const certPath = path.join(tempDir, 'server.crt');
        fs.writeFileSync(certPath, TEST_CERT_PEM);

        const details = parseCertificateFile(certPath);
        const scanned = scanCertificateFile(certPath);

        assert.strictEqual(details.subjectCommonName, 'example.com');
        assert.strictEqual(scanned.owner, 'example.com');
        assert.strictEqual(scanned.format, 'CRT');
    });

    test('classifies PKCS#12, PKCS#7, and JKS files without parsing them as X.509 directly', () => {
        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-util-classify-'));
        const p12Path = path.join(tempDir, 'bundle.p12');
        const p7bPath = path.join(tempDir, 'bundle.p7b');
        const jksPath = path.join(tempDir, 'keystore.jks');
        fs.writeFileSync(p12Path, 'placeholder');
        fs.writeFileSync(p7bPath, 'placeholder');
        fs.writeFileSync(jksPath, 'placeholder');

        assert.strictEqual(parseCertificateInputFromFile(p12Path).kind, 'pkcs12');
        assert.strictEqual(parseCertificateInputFromFile(p7bPath).kind, 'pkcs7');
        assert.strictEqual(parseCertificateInputFromFile(jksPath).kind, 'jks');
    });

    test('rejects oversized certificate files before reading them', () => {
        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-util-size-'));
        const oversizedPath = path.join(tempDir, 'oversized.pem');
        fs.writeFileSync(oversizedPath, '');
        fs.truncateSync(oversizedPath, MAX_CERTIFICATE_FILE_BYTES + 1);

        assert.throws(() => parseCertificateInputFromFile(oversizedPath), /10 MB file limit/);
    });

    test('validates hostname and purpose against a parsed artifact', () => {
        const artifact = parseCertificateInputFromText(TEST_CERT_PEM, {
            kind: 'pasted',
            label: 'cert',
        });

        const matching = validateArtifact(artifact, {
            hostname: 'example.com',
            purpose: 'serverAuth',
        });
        const mismatch = validateArtifact(artifact, {
            hostname: 'api.example.com',
        });

        assert.ok(matching.issues.some((issue) => issue.code === 'hostname-match'));
        assert.ok(mismatch.issues.some((issue) => issue.code === 'hostname-mismatch'));
    });

    test('analyzes duplicate and incomplete chains', () => {
        const artifact = parseCertificateInputFromText(`${TEST_CERT_PEM}\n${TEST_CERT_PEM}`, {
            kind: 'pasted',
            label: 'bundle',
        });
        const chain = analyzeCertificateChain(artifact.certificates);

        assert.ok(chain);
        assert.ok(chain?.duplicateSerialNumbers.length);
        assert.ok(chain?.warnings.some((warning) => warning.includes('Duplicate')));
    });

    test('classifies expiry status relative to a reference date', () => {
        const reference = new Date('2026-06-17T00:00:00Z');

        assert.strictEqual(getCertificateStatus('2026-06-16T00:00:00Z', reference), 'expired');
        assert.strictEqual(getCertificateStatus('2026-07-01T00:00:00Z', reference), 'expiring');
        assert.strictEqual(getCertificateStatus('2026-08-01T00:00:00Z', reference), 'valid');
    });

    test('honors a custom expiry warning threshold', () => {
        const reference = new Date('2026-06-17T00:00:00Z');

        // 2026-07-01 is 14 days out: "expiring" under the default 30-day window, "valid" under 7 days.
        assert.strictEqual(getCertificateStatus('2026-07-01T00:00:00Z', reference, 30), 'expiring');
        assert.strictEqual(getCertificateStatus('2026-07-01T00:00:00Z', reference, 7), 'valid');
        // 2026-09-01 is ~76 days out: still flagged when the window is widened to 90 days.
        assert.strictEqual(getCertificateStatus('2026-09-01T00:00:00Z', reference, 90), 'expiring');
    });

    test('flags weak signature algorithms and short keys', () => {
        const [cert] = parseCertificateInputFromText(TEST_CERT_PEM, {
            kind: 'pasted',
            label: 'cert',
        }).certificates;

        // A healthy SHA-256 / 2048-bit RSA certificate raises no strength concerns.
        assert.strictEqual(assessAlgorithmStrength(cert).length, 0);

        const sha1 = assessAlgorithmStrength({ ...cert, signatureAlgorithm: 'sha1WithRSAEncryption' });
        assert.ok(sha1.some((issue) => issue.code === 'weak-signature-algorithm' && issue.severity === 'warning'));

        const md5 = assessAlgorithmStrength({ ...cert, signatureAlgorithm: 'md5WithRSAEncryption' });
        assert.ok(md5.some((issue) => issue.code === 'weak-signature-algorithm' && issue.severity === 'error'));

        const shortKey = assessAlgorithmStrength({ ...cert, publicKeyAlgorithm: 'RSA', bits: 1024 });
        assert.ok(shortKey.some((issue) => issue.code === 'weak-key-size'));
    });

    test('cryptographically verifies chain links', () => {
        const chain = analyzeCertificateChain(
            parseCertificateInputFromText(TEST_CERT_PEM, { kind: 'pasted', label: 'self-signed' }).certificates
        );

        // The self-signed root verifies against its own key.
        assert.strictEqual(chain?.entries[0].signatureVerified, true);
        assert.ok(!chain?.warnings.some((warning) => warning.includes('could not be cryptographically verified')));
    });

    test('detects a self-signed CA certificate via cryptographic verification', () => {
        const [cert] = parseCertificateInputFromText(TEST_CERT_PEM, {
            kind: 'pasted',
            label: 'self-signed',
        }).certificates;

        assert.strictEqual(cert.isSelfSigned, true);
        assert.strictEqual(cert.isCertificateAuthority, true);
    });

    test('parses the signature algorithm from the certificate DER', () => {
        const [cert] = parseCertificateInputFromText(TEST_CERT_PEM, {
            kind: 'pasted',
            label: 'cert',
        }).certificates;

        assert.strictEqual(cert.signatureAlgorithm, 'sha256WithRSAEncryption');
    });

    test('summarizes the key algorithm and strength separately from the signature', () => {
        const [cert] = parseCertificateInputFromText(TEST_CERT_PEM, {
            kind: 'pasted',
            label: 'cert',
        }).certificates;

        assert.strictEqual(cert.algorithm, 'RSA (2048-bit)');
        assert.strictEqual(cert.publicKeyAlgorithm, 'RSA');
        assert.strictEqual(cert.bits, 2048);
        // `algorithm` is the key summary and must stay distinct from the signature algorithm.
        assert.notStrictEqual(cert.algorithm, cert.signatureAlgorithm);
    });
});

suite('externalTools helpers', () => {
    test('builds command recipes consistently', () => {
        assert.ok(buildPemToDerCommand('cert.pem', 'cert.der').includes('openssl x509'));
        assert.ok(buildDerToPemCommand('cert.der', 'cert.pem').includes('openssl x509'));
        assert.ok(buildPkcs12ExportCommand('cert.pem', 'key.pem', 'cert.p12', 'secret').includes('openssl pkcs12'));
        assert.ok(buildPkcs12PemExportCommands('bundle.p12', 'cert.pem', 'key.pem', 'secret').includes('-nocerts'));
        assert.ok(buildJksExportCommand('keystore.jks', 'server').includes('keytool'));
        assert.ok(buildJksPemExportCommands('keystore.jks', 'server', 'keystore.p12', 'cert.pem', 'key.pem').includes('keytool'));
        assert.ok(buildJksToPkcs12Command('keystore.jks').includes('PKCS12'));
    });

    test('keeps store passwords out of generated JKS recipes', () => {
        const command = buildJksPemExportCommands('keystore.jks', 'server', 'keystore.p12', 'cert.pem', 'key.pem', 's3cr3t-pass');
        assert.ok(!command.includes('s3cr3t-pass'), 'password must not be embedded in the command');
        assert.ok(command.includes('-srcstorepass:file'), 'keytool should read the password from a file');
        assert.ok(command.includes('file:storepass.txt'), 'OpenSSL should read the password from a file');
    });

    test('parses OpenSSL-like outputs that contain PEM certificates', () => {
        assert.strictEqual(parsePkcsCertificateOutput(TEST_CERT_PEM), 1);
        assert.strictEqual(parseRemoteInspectionOutput(`${TEST_CERT_PEM}\n${TEST_CERT_PEM}`), 2);
    });

    test('parses host, port, and IPv6 remote targets', () => {
        assert.deepStrictEqual(parseRemoteTarget('example.com'), { host: 'example.com', port: 443 });
        assert.deepStrictEqual(parseRemoteTarget('example.com:8443'), { host: 'example.com', port: 8443 });
        assert.deepStrictEqual(parseRemoteTarget('2001:db8::1'), { host: '2001:db8::1', port: 443 });
        assert.deepStrictEqual(parseRemoteTarget('[2001:db8::1]:9443'), { host: '2001:db8::1', port: 9443 });
    });

    test('rejects malformed remote targets', () => {
        assert.throws(() => parseRemoteTarget('https://example.com'), /host name or IP address/);
        assert.throws(() => parseRemoteTarget('example.com:not-a-port'), /port must be a number/);
        assert.throws(() => parseRemoteTarget('example.com:70000'), /port must be a number/);
        assert.throws(() => parseRemoteTarget('[example.com]:443'), /valid IPv6 address/);
    });

    test('detects external tools asynchronously', async function () {
        this.timeout(12000);
        const availability = await detectExternalToolAvailability(true);
        assert.strictEqual(typeof availability.openssl.available, 'boolean');
        assert.strictEqual(typeof availability.keytool.available, 'boolean');
    });
});
