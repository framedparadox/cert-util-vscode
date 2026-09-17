import * as assert from 'assert';
import { parseCertificateInputFromText } from '../certificates/certificateUtils';
import { buildPkcs12, parsePkcs12 } from '../certificates/keystoreParser';
import { generateCsr, generateKeyPair, generateSelfSignedCertificate, privateKeyMatchesCertificate } from '../certificates/generation';

suite('certificate generation', () => {
    test('generates an EC key pair as PEM', async () => {
        const pair = await generateKeyPair('EC-P256');
        assert.ok(pair.privateKeyPem.includes('-----BEGIN PRIVATE KEY-----'));
        assert.ok(pair.publicKeyPem.includes('-----BEGIN PUBLIC KEY-----'));
    });

    test('generates a self-signed certificate that parses and matches its key', async () => {
        const result = await generateSelfSignedCertificate({
            keyAlgorithm: 'EC-P256',
            subject: { commonName: 'generated.example.com', organization: 'Cert Util' },
            subjectAltNames: ['DNS:generated.example.com', 'DNS:www.generated.example.com'],
            validityDays: 90,
        });

        const [certificate] = parseCertificateInputFromText(result.certificatePem, {
            kind: 'pasted',
            label: 'generated',
        }).certificates;

        assert.strictEqual(certificate.subjectCommonName, 'generated.example.com');
        assert.ok(certificate.subjectAltNames.some((name) => name.includes('www.generated.example.com')));
        assert.ok(new Date(certificate.validTo).getTime() > Date.now());
        assert.strictEqual(await privateKeyMatchesCertificate(result.privateKeyPem, result.certificatePem), true);
    });

    test('generates an Ed25519 self-signed certificate', async () => {
        const result = await generateSelfSignedCertificate({
            keyAlgorithm: 'Ed25519',
            subject: { commonName: 'ed25519.example.com' },
            validityDays: 30,
        });
        const [certificate] = parseCertificateInputFromText(result.certificatePem, { kind: 'pasted', label: 'ed' }).certificates;
        assert.strictEqual(certificate.subjectCommonName, 'ed25519.example.com');
    });

    test('generates a CSR in PEM form', async () => {
        const result = await generateCsr({
            keyAlgorithm: 'EC-P256',
            subject: { commonName: 'csr.example.com', country: 'US' },
            subjectAltNames: ['DNS:csr.example.com'],
        });
        assert.ok(result.csrPem.includes('-----BEGIN CERTIFICATE REQUEST-----'));
        assert.ok(result.privateKeyPem.includes('-----BEGIN PRIVATE KEY-----'));
    });

    test('rejects a private key that does not match a certificate', async () => {
        const a = await generateSelfSignedCertificate({
            keyAlgorithm: 'EC-P256',
            subject: { commonName: 'a.example.com' },
            validityDays: 30,
        });
        const b = await generateSelfSignedCertificate({
            keyAlgorithm: 'EC-P256',
            subject: { commonName: 'b.example.com' },
            validityDays: 30,
        });
        assert.strictEqual(await privateKeyMatchesCertificate(a.privateKeyPem, b.certificatePem), false);
    });

    test('builds a PKCS#12 container that round-trips', async function () {
        // RSA-2048 key generation plus a node-forge PKCS#12 build can exceed Mocha's 2s default.
        this.timeout(15000);
        const result = await generateSelfSignedCertificate({
            keyAlgorithm: 'RSA-2048',
            subject: { commonName: 'pfx.example.com' },
            validityDays: 30,
        });
        const base64 = buildPkcs12(result.certificatePem, result.privateKeyPem, 'secret');
        const parsed = parsePkcs12(Buffer.from(base64, 'base64'), 'secret');

        assert.strictEqual(parsed.certificatePems.length, 1);
        assert.strictEqual(parsed.privateKey?.algorithm, 'RSA');
    });
});
