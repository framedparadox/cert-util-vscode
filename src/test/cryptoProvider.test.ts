import * as assert from 'assert';
import * as forge from 'node-forge';
import { decodeRichExtensions, parsePkcs12, parsePkcs7 } from '../certificates/cryptoProvider';

interface ForgeKeypairCert {
    privateKey: forge.pki.rsa.PrivateKey;
    certificate: forge.pki.Certificate;
}

/** Builds a small self-signed RSA certificate (1024-bit for test speed) with the given extensions. */
// node-forge types certificate extensions as `any[]`, so the fixtures use the same shape.
function createSelfSignedCertificate(extensions: unknown[] = []): ForgeKeypairCert {
    const keys = forge.pki.rsa.generateKeyPair({ bits: 1024 });
    const certificate = forge.pki.createCertificate();
    certificate.publicKey = keys.publicKey;
    certificate.serialNumber = '01';
    certificate.validity.notBefore = new Date('2026-01-01T00:00:00Z');
    certificate.validity.notAfter = new Date('2030-01-01T00:00:00Z');
    const attrs = [
        { name: 'commonName', value: 'keystore.example.com' },
        { name: 'organizationName', value: 'Cert Util' },
    ];
    certificate.setSubject(attrs);
    certificate.setIssuer(attrs);
    if (extensions.length) {
        certificate.setExtensions(extensions);
    }
    certificate.sign(keys.privateKey, forge.md.sha256.create());
    return { privateKey: keys.privateKey, certificate };
}

function toDerBuffer(certificate: forge.pki.Certificate): Buffer {
    const der = forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes();
    return Buffer.from(der, 'binary');
}

suite('cryptoProvider native parsing', () => {
    test('parses a PKCS#12 container and recovers the certificate and key', () => {
        const { privateKey, certificate } = createSelfSignedCertificate();
        const password = 'p@ssw0rd';
        const p12Asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, certificate, password, { algorithm: '3des' });
        const der = Buffer.from(forge.asn1.toDer(p12Asn1).getBytes(), 'binary');

        const parsed = parsePkcs12(der, password);

        assert.strictEqual(parsed.certificatePems.length, 1);
        assert.ok(parsed.certificatePems[0].includes('-----BEGIN CERTIFICATE-----'));
        assert.strictEqual(parsed.privateKey?.algorithm, 'RSA');
        assert.strictEqual(parsed.privateKey?.bits, 1024);
    });

    test('reports a clear error for the wrong PKCS#12 password', () => {
        const { privateKey, certificate } = createSelfSignedCertificate();
        const p12Asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, certificate, 'correct-horse', { algorithm: '3des' });
        const der = Buffer.from(forge.asn1.toDer(p12Asn1).getBytes(), 'binary');

        assert.throws(() => parsePkcs12(der, 'wrong-password'), /password is incorrect/i);
    });

    test('extracts certificates from a PKCS#7 bundle', () => {
        const { certificate } = createSelfSignedCertificate();
        const p7 = forge.pkcs7.createSignedData();
        p7.addCertificate(certificate);
        const pem = forge.pkcs7.messageToPem(p7);

        const parsed = parsePkcs7(Buffer.from(pem, 'utf8'));

        assert.strictEqual(parsed.certificatePems.length, 1);
        assert.ok(parsed.certificatePems[0].includes('-----BEGIN CERTIFICATE-----'));
    });

    test('decodes subject key identifier and basic-constraints path length', () => {
        const { certificate } = createSelfSignedCertificate([
            { name: 'basicConstraints', cA: true, pathLenConstraint: 1 },
            { name: 'subjectKeyIdentifier' },
            {
                name: 'cRLDistributionPoints',
                altNames: [{ type: 6, value: 'http://crl.example.com/root.crl' }],
            },
        ]);

        const extensions = decodeRichExtensions(toDerBuffer(certificate));

        assert.strictEqual(extensions.basicConstraintsPathLength, 1);
        assert.ok(extensions.subjectKeyIdentifier, 'subject key identifier should be decoded');
        assert.strictEqual(extensions.hasEmbeddedScts, false);
    });
});
