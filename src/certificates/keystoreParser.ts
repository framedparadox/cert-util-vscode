import * as forge from 'node-forge';

// This module is the sole consumer of node-forge and is loaded lazily (via dynamic import) so the
// ~800 KB library is not evaluated at extension activation — only when a keystore is actually parsed
// or built.

/** Private-key metadata recovered from a keystore (the key material itself is never surfaced). */
export interface KeystoreKeyInfo {
    algorithm: string;
    bits?: number;
}

/** Result of parsing a PKCS#12/PFX or PKCS#7 container into PEM certificates. */
export interface ParsedKeystore {
    certificatePems: string[];
    privateKey?: KeystoreKeyInfo;
    warnings: string[];
}

/**
 * Parses a PKCS#12 / PFX container with node-forge (which supports the legacy ciphers — 3DES, RC2 —
 * that Node's WebCrypto cannot), returning the contained certificates as PEM plus private-key
 * metadata. Throws a friendly error when the password is wrong or the container is malformed.
 */
export function parsePkcs12(data: Buffer, password: string): ParsedKeystore {
    let p12: forge.pkcs12.Pkcs12Pfx;
    try {
        const asn1 = forge.asn1.fromDer(forge.util.createBuffer(data.toString('binary')));
        // strict = false tolerates real-world PFX files that bend the DER rules slightly.
        p12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, password);
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (/mac could not be verified|invalid password/i.test(message)) {
            throw new Error('Could not open the PKCS#12 file. The password is incorrect.');
        }
        throw new Error(`Could not parse the PKCS#12 file: ${message}`);
    }

    const warnings: string[] = [];
    const certificatePems: string[] = [];
    const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] ?? [];
    for (const bag of certBags) {
        if (bag.cert) {
            certificatePems.push(forge.pki.certificateToPem(bag.cert));
        }
    }

    const keyInfo = extractKeystoreKeyInfo(p12);
    if (!certificatePems.length) {
        warnings.push('No certificates were found in the PKCS#12 container.');
    }

    return { certificatePems, privateKey: keyInfo, warnings };
}

/**
 * Parses a PKCS#7 / CMS container (PEM or DER) with node-forge and returns the embedded
 * certificates as PEM. Commonly used for `.p7b`/`.p7c` certificate bundles.
 */
export function parsePkcs7(data: Buffer): ParsedKeystore {
    let message: forge.pkcs7.PkcsSignedData;
    const text = data.toString('binary');
    try {
        if (text.includes('-----BEGIN PKCS7-----')) {
            message = forge.pkcs7.messageFromPem(text) as forge.pkcs7.PkcsSignedData;
        } else {
            const asn1 = forge.asn1.fromDer(forge.util.createBuffer(text));
            message = forge.pkcs7.messageFromAsn1(asn1) as forge.pkcs7.PkcsSignedData;
        }
    } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        throw new Error(`Could not parse the PKCS#7 file: ${detail}`);
    }

    const certificates = message.certificates ?? [];
    const certificatePems = certificates.map((cert) => forge.pki.certificateToPem(cert));
    const warnings = certificatePems.length ? [] : ['No certificates were found in the PKCS#7 container.'];
    return { certificatePems, warnings };
}

/**
 * Builds a password-protected PKCS#12 / PFX container (3DES) from a certificate and its private key.
 * Optional extra certificates are included as chain entries. Returns base64 DER.
 */
export function buildPkcs12(certificatePem: string, privateKeyPem: string, password: string, chainPems: string[] = []): string {
    const certificate = forge.pki.certificateFromPem(certificatePem);
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    const chain = [certificate, ...chainPems.map((pem) => forge.pki.certificateFromPem(pem))];
    const asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, chain, password, { algorithm: '3des' });
    return forge.util.encode64(forge.asn1.toDer(asn1).getBytes());
}

function extractKeystoreKeyInfo(p12: forge.pkcs12.Pkcs12Pfx): KeystoreKeyInfo | undefined {
    const shrouded = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] ?? [];
    const plain = p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] ?? [];
    const keyBag = [...shrouded, ...plain].find((bag) => bag.key);
    const key = keyBag?.key as forge.pki.rsa.PrivateKey | undefined;
    if (!key) {
        return undefined;
    }
    // node-forge surfaces RSA keys with an `n` modulus; other key types lack it.
    if (typeof key.n?.bitLength === 'function') {
        return { algorithm: 'RSA', bits: key.n.bitLength() };
    }
    return { algorithm: 'Unknown' };
}
