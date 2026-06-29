// Must load before any @peculiar/x509 import (tsyringe DI requires the polyfill).
import 'reflect-metadata';
import * as assert from 'assert';
import { X509CertificateGenerator, X509CrlGenerator } from '@peculiar/x509';
// Importing generation sets the @peculiar/x509 WebCrypto engine as a side effect.
import { generateKeyPair } from '../certificates/generation';
import { checkAgainstCrl, getCrlDistributionUrls, getOcspUrls } from '../certificates/revocation';

async function createCaCertificate(serialNumber: string) {
    const { keys } = await generateKeyPair('EC-P256');
    const certificate = await X509CertificateGenerator.createSelfSigned({
        serialNumber,
        name: 'CN=Test CA, O=Cert Util',
        notBefore: new Date('2026-01-01T00:00:00Z'),
        notAfter: new Date('2030-01-01T00:00:00Z'),
        signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        keys,
    });
    return { keys, certificate };
}

suite('certificate revocation (CRL)', () => {
    test('reports a certificate listed in the CRL as revoked', async () => {
        const serialNumber = '0a0b0c0d';
        const { keys, certificate } = await createCaCertificate(serialNumber);

        const crl = await X509CrlGenerator.create({
            issuer: 'CN=Test CA, O=Cert Util',
            thisUpdate: new Date('2026-06-01T00:00:00Z'),
            nextUpdate: new Date('2026-12-01T00:00:00Z'),
            signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
            signingKey: keys.privateKey,
            entries: [{ serialNumber, revocationDate: new Date('2026-05-01T00:00:00Z') }],
        });

        const result = checkAgainstCrl(crl.rawData, certificate.toString('pem'));
        assert.strictEqual(result.status, 'revoked');
        assert.ok(result.revocationDate);
    });

    test('reports a certificate absent from the CRL as good', async () => {
        const { keys } = await createCaCertificate('aaaa');
        // A second certificate with a different serial number that is not in the CRL.
        const other = await X509CertificateGenerator.createSelfSigned({
            serialNumber: 'bbbb',
            name: 'CN=Test CA, O=Cert Util',
            notBefore: new Date('2026-01-01T00:00:00Z'),
            notAfter: new Date('2030-01-01T00:00:00Z'),
            signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
            keys,
        });

        const crl = await X509CrlGenerator.create({
            issuer: 'CN=Test CA, O=Cert Util',
            signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
            signingKey: keys.privateKey,
            entries: [{ serialNumber: 'aaaa', revocationDate: new Date('2026-05-01T00:00:00Z') }],
        });

        const result = checkAgainstCrl(crl.rawData, other.toString('pem'));
        assert.strictEqual(result.status, 'good');
    });

    test('returns no distribution or OCSP URLs for a certificate without those extensions', async () => {
        const { certificate } = await createCaCertificate('cccc');
        const pem = certificate.toString('pem');
        assert.deepStrictEqual(getCrlDistributionUrls(pem), []);
        assert.deepStrictEqual(getOcspUrls(pem), []);
    });
});
