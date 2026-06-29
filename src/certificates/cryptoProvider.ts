// Must be imported before @peculiar/x509 (which uses tsyringe dependency injection).
import 'reflect-metadata';
import * as forge from 'node-forge';
import {
    AuthorityKeyIdentifierExtension,
    BasicConstraintsExtension,
    CRLDistributionPointsExtension,
    CertificatePolicyExtension,
    SubjectKeyIdentifierExtension,
    X509Certificate as PeculiarCertificate,
} from '@peculiar/x509';
import { AsnConvert } from '@peculiar/asn1-schema';
import { GeneralName, NameConstraints } from '@peculiar/asn1-x509';

/** OID of the Name Constraints extension (no typed wrapper in @peculiar/x509). */
const OID_NAME_CONSTRAINTS = '2.5.29.30';
/** OID of the Signed Certificate Timestamp (Certificate Transparency) extension. */
const OID_SCT_LIST = '1.3.6.1.4.1.11129.2.4.2';

/**
 * Higher-fidelity X.509 extension data decoded with @peculiar/x509, beyond what Node's
 * `crypto.X509Certificate` exposes. Every field is best-effort: decoding failures leave the
 * corresponding field empty rather than throwing.
 */
export interface RichCertificateExtensions {
    authorityKeyIdentifier?: string;
    subjectKeyIdentifier?: string;
    basicConstraintsPathLength?: number;
    crlDistributionPoints: string[];
    certificatePolicies: string[];
    nameConstraintsPermitted: string[];
    nameConstraintsExcluded: string[];
    hasEmbeddedScts: boolean;
}

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
 * Decodes the richer certificate extensions from a DER buffer. Returns empty/false fields when an
 * extension is absent or cannot be parsed, so callers can render whatever decoded successfully.
 */
export function decodeRichExtensions(der: Buffer): RichCertificateExtensions {
    const result: RichCertificateExtensions = {
        crlDistributionPoints: [],
        certificatePolicies: [],
        nameConstraintsPermitted: [],
        nameConstraintsExcluded: [],
        hasEmbeddedScts: false,
    };

    let certificate: PeculiarCertificate;
    try {
        certificate = new PeculiarCertificate(new Uint8Array(der));
    } catch {
        return result;
    }

    safely(() => {
        const aki = certificate.getExtension(AuthorityKeyIdentifierExtension);
        if (aki?.keyId) {
            result.authorityKeyIdentifier = formatKeyId(aki.keyId);
        }
    });

    safely(() => {
        const ski = certificate.getExtension(SubjectKeyIdentifierExtension);
        if (ski?.keyId) {
            result.subjectKeyIdentifier = formatKeyId(ski.keyId);
        }
    });

    safely(() => {
        const basic = certificate.getExtension(BasicConstraintsExtension);
        if (basic && typeof basic.pathLength === 'number') {
            result.basicConstraintsPathLength = basic.pathLength;
        }
    });

    safely(() => {
        const crl = certificate.getExtension(CRLDistributionPointsExtension);
        for (const point of crl?.distributionPoints ?? []) {
            for (const name of point.distributionPoint?.fullName ?? []) {
                const value = formatGeneralName(name);
                if (value) {
                    result.crlDistributionPoints.push(value);
                }
            }
        }
    });

    safely(() => {
        const policies = certificate.getExtension(CertificatePolicyExtension);
        if (policies?.policies?.length) {
            result.certificatePolicies = policies.policies.map((oid) => oid);
        }
    });

    safely(() => {
        const extension = certificate.getExtension(OID_NAME_CONSTRAINTS);
        if (extension) {
            const constraints = AsnConvert.parse(extension.value, NameConstraints);
            result.nameConstraintsPermitted = (constraints.permittedSubtrees ?? [])
                .map((subtree) => formatGeneralName(subtree.base))
                .filter((value): value is string => Boolean(value));
            result.nameConstraintsExcluded = (constraints.excludedSubtrees ?? [])
                .map((subtree) => formatGeneralName(subtree.base))
                .filter((value): value is string => Boolean(value));
        }
    });

    safely(() => {
        result.hasEmbeddedScts = certificate.getExtension(OID_SCT_LIST) !== null;
    });

    return result;
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

/** Formats a hex key identifier into colon-separated upper-case byte pairs (e.g. `AB:CD:EF`). */
function formatKeyId(keyId: string): string {
    const normalized = keyId.replace(/[^0-9a-fA-F]/g, '').toUpperCase();
    return normalized.match(/.{1,2}/g)?.join(':') ?? normalized;
}

/** Renders an ASN.1 GeneralName as a prefixed string (e.g. `DNS:example.com`, `URI:http://...`). */
function formatGeneralName(name: GeneralName): string | undefined {
    if (name.dNSName) {
        return `DNS:${name.dNSName}`;
    }
    if (name.uniformResourceIdentifier) {
        return `URI:${name.uniformResourceIdentifier}`;
    }
    if (name.rfc822Name) {
        return `email:${name.rfc822Name}`;
    }
    if (name.iPAddress) {
        return `IP:${name.iPAddress}`;
    }
    return undefined;
}

function safely(action: () => void): void {
    try {
        action();
    } catch {
        // Best-effort extension decoding — ignore a single extension that fails to parse.
    }
}
