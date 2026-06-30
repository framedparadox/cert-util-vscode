// Must be imported before @peculiar/x509 (which uses tsyringe dependency injection).
import 'reflect-metadata';
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
