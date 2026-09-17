// Lightweight, dependency-free types and constants shared by the generation module and its UI. Kept
// separate from generation.ts so importing them does not pull in @peculiar/x509 at activation.

export type KeyAlgorithm = 'RSA-2048' | 'RSA-3072' | 'RSA-4096' | 'EC-P256' | 'EC-P384' | 'Ed25519';

export const KEY_ALGORITHMS: KeyAlgorithm[] = ['RSA-2048', 'RSA-3072', 'RSA-4096', 'EC-P256', 'EC-P384', 'Ed25519'];

export interface CertificateSubject {
    commonName: string;
    organization?: string;
    organizationalUnit?: string;
    country?: string;
    state?: string;
    locality?: string;
    email?: string;
}
