// reflect-metadata must load before @peculiar/x509 (tsyringe-based DI).
import 'reflect-metadata';
import { webcrypto } from 'crypto';
import * as forge from 'node-forge';
import {
    BasicConstraintsExtension,
    ExtendedKeyUsageExtension,
    Extension,
    KeyUsageFlags,
    KeyUsagesExtension,
    Pkcs10CertificateRequestGenerator,
    PemConverter,
    SubjectAlternativeNameExtension,
    SubjectKeyIdentifierExtension,
    X509Certificate,
    X509CertificateGenerator,
    cryptoProvider,
} from '@peculiar/x509';

// @peculiar/x509 needs a WebCrypto engine for key generation, signing, and verification. The Node
// extension host exposes one via `crypto.webcrypto`.
const crypto = webcrypto as unknown as Crypto;
cryptoProvider.set(crypto);

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

export interface GeneratedKeyPair {
    keys: CryptoKeyPair;
    privateKeyPem: string;
    publicKeyPem: string;
}

export interface CsrResult {
    csrPem: string;
    privateKeyPem: string;
    publicKeyPem: string;
}

export interface CertificateResult {
    certificatePem: string;
    privateKeyPem: string;
    publicKeyPem: string;
}

export interface GenerationOptions {
    keyAlgorithm: KeyAlgorithm;
    subject: CertificateSubject;
    subjectAltNames?: string[];
    /** Mark the certificate/request as a CA (adds basicConstraints CA:true and keyCertSign). */
    isCertificateAuthority?: boolean;
}

export interface SelfSignedOptions extends GenerationOptions {
    validityDays: number;
}

/** Generates a key pair for the requested algorithm and returns PKCS#8 / SPKI PEM encodings. */
export async function generateKeyPair(algorithm: KeyAlgorithm): Promise<GeneratedKeyPair> {
    const keys = (await crypto.subtle.generateKey(generateParams(algorithm), true, ['sign', 'verify'])) as CryptoKeyPair;
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', keys.privateKey);
    const spki = await crypto.subtle.exportKey('spki', keys.publicKey);
    return {
        keys,
        privateKeyPem: PemConverter.encode(pkcs8, 'PRIVATE KEY'),
        publicKeyPem: PemConverter.encode(spki, 'PUBLIC KEY'),
    };
}

/** Generates a PKCS#10 certificate signing request (and the matching private key) as PEM. */
export async function generateCsr(options: GenerationOptions): Promise<CsrResult> {
    const keyPair = await generateKeyPair(options.keyAlgorithm);
    const extensions = await buildExtensions(options, keyPair.keys.publicKey);
    const csr = await Pkcs10CertificateRequestGenerator.create(
        {
            name: buildDistinguishedName(options.subject),
            keys: keyPair.keys,
            signingAlgorithm: signingParams(options.keyAlgorithm),
            extensions,
        },
        crypto
    );

    return { csrPem: csr.toString('pem'), privateKeyPem: keyPair.privateKeyPem, publicKeyPem: keyPair.publicKeyPem };
}

/** Generates a self-signed X.509 certificate (and the matching private key) as PEM. */
export async function generateSelfSignedCertificate(options: SelfSignedOptions): Promise<CertificateResult> {
    const keyPair = await generateKeyPair(options.keyAlgorithm);
    const now = new Date();
    const notAfter = new Date(now.getTime() + options.validityDays * 24 * 60 * 60 * 1000);
    const certificate = await X509CertificateGenerator.createSelfSigned(
        {
            serialNumber: randomSerialNumber(),
            name: buildDistinguishedName(options.subject),
            notBefore: now,
            notAfter,
            signingAlgorithm: signingParams(options.keyAlgorithm),
            keys: keyPair.keys,
            extensions: await buildExtensions(options, keyPair.keys.publicKey),
        },
        crypto
    );

    return { certificatePem: certificate.toString('pem'), privateKeyPem: keyPair.privateKeyPem, publicKeyPem: keyPair.publicKeyPem };
}

/**
 * Verifies whether a PEM-encoded PKCS#8 private key corresponds to a PEM-encoded certificate by
 * signing a random nonce with the key and verifying it with the certificate's public key. Returns
 * false (never throws) when the key/cert do not match or cannot be parsed.
 */
export async function privateKeyMatchesCertificate(privateKeyPem: string, certificatePem: string): Promise<boolean> {
    try {
        const certificate = new X509Certificate(certificatePem);
        const keyAlgorithm = certificate.publicKey.algorithm;
        const importParams = importParamsFor(keyAlgorithm);
        const signAlgorithm = signAlgorithmFor(keyAlgorithm);

        const publicKey = await certificate.publicKey.export(importParams, ['verify'], crypto);
        const privateKey = await crypto.subtle.importKey('pkcs8', pemToDer(privateKeyPem), importParams, false, ['sign']);

        const data = crypto.getRandomValues(new Uint8Array(32));
        const signature = await crypto.subtle.sign(signAlgorithm, privateKey, data);
        return await crypto.subtle.verify(signAlgorithm, publicKey, signature, data);
    } catch {
        return false;
    }
}

/**
 * Builds a password-protected PKCS#12 / PFX container (3DES) from a certificate and its private key
 * using node-forge. Optional extra certificates are included as chain entries. Returns base64 DER.
 */
export function buildPkcs12(certificatePem: string, privateKeyPem: string, password: string, chainPems: string[] = []): string {
    const certificate = forge.pki.certificateFromPem(certificatePem);
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    const chain = [certificate, ...chainPems.map((pem) => forge.pki.certificateFromPem(pem))];
    const asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, chain, password, { algorithm: '3des' });
    return forge.util.encode64(forge.asn1.toDer(asn1).getBytes());
}

function generateParams(algorithm: KeyAlgorithm): RsaHashedKeyGenParams | EcKeyGenParams | { name: string } {
    switch (algorithm) {
        case 'RSA-2048':
        case 'RSA-3072':
        case 'RSA-4096':
            return {
                name: 'RSASSA-PKCS1-v1_5',
                hash: 'SHA-256',
                publicExponent: new Uint8Array([1, 0, 1]),
                modulusLength: Number(algorithm.split('-')[1]),
            };
        case 'EC-P256':
            return { name: 'ECDSA', namedCurve: 'P-256' };
        case 'EC-P384':
            return { name: 'ECDSA', namedCurve: 'P-384' };
        case 'Ed25519':
            return { name: 'Ed25519' };
    }
}

function signingParams(algorithm: KeyAlgorithm): Algorithm | EcdsaParams {
    if (algorithm.startsWith('EC-')) {
        return { name: 'ECDSA', hash: 'SHA-256' };
    }
    if (algorithm === 'Ed25519') {
        return { name: 'Ed25519' };
    }
    return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
}

function importParamsFor(algorithm: Algorithm): Algorithm | EcKeyImportParams | RsaHashedImportParams {
    const name = algorithm.name;
    if (name === 'ECDSA' || name === 'ECDH') {
        return { name: 'ECDSA', namedCurve: (algorithm as EcKeyImportParams).namedCurve };
    }
    if (name === 'Ed25519') {
        return { name: 'Ed25519' };
    }
    return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
}

function signAlgorithmFor(algorithm: Algorithm): Algorithm | EcdsaParams {
    if (algorithm.name === 'ECDSA' || algorithm.name === 'ECDH') {
        return { name: 'ECDSA', hash: 'SHA-256' };
    }
    if (algorithm.name === 'Ed25519') {
        return { name: 'Ed25519' };
    }
    return { name: 'RSASSA-PKCS1-v1_5' };
}

async function buildExtensions(options: GenerationOptions, publicKey: CryptoKey): Promise<Extension[]> {
    const extensions: Extension[] = [];

    if (options.isCertificateAuthority) {
        extensions.push(new BasicConstraintsExtension(true, undefined, true));
        extensions.push(new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true));
    } else {
        extensions.push(new BasicConstraintsExtension(false, undefined, true));
        extensions.push(new KeyUsagesExtension(KeyUsageFlags.digitalSignature | KeyUsageFlags.keyEncipherment, true));
        // serverAuth + clientAuth — the common default for a leaf TLS certificate.
        extensions.push(new ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2']));
    }

    const sans = (options.subjectAltNames ?? []).map(parseGeneralName).filter((value) => value !== undefined);
    if (sans.length) {
        extensions.push(new SubjectAlternativeNameExtension(sans));
    }

    extensions.push(await SubjectKeyIdentifierExtension.create(publicKey, false, crypto));
    return extensions;
}

function parseGeneralName(value: string): { type: 'dns' | 'ip' | 'email' | 'url'; value: string } | undefined {
    const trimmed = value.trim();
    if (!trimmed) {
        return undefined;
    }
    const match = /^(DNS|IP|EMAIL|URI|URL):(.+)$/i.exec(trimmed);
    if (match) {
        const prefix = match[1].toUpperCase();
        const inner = match[2].trim();
        if (prefix === 'IP') {
            return { type: 'ip', value: inner };
        }
        if (prefix === 'EMAIL') {
            return { type: 'email', value: inner };
        }
        if (prefix === 'URI' || prefix === 'URL') {
            return { type: 'url', value: inner };
        }
        return { type: 'dns', value: inner };
    }
    // Bare values are treated as DNS names, the most common SAN type.
    return { type: 'dns', value: trimmed };
}

function buildDistinguishedName(subject: CertificateSubject): string {
    const parts: string[] = [];
    const push = (key: string, value?: string) => {
        const trimmed = value?.trim();
        if (trimmed) {
            parts.push(`${key}=${escapeDnValue(trimmed)}`);
        }
    };
    push('CN', subject.commonName);
    push('OU', subject.organizationalUnit);
    push('O', subject.organization);
    push('L', subject.locality);
    push('ST', subject.state);
    push('C', subject.country);
    push('E', subject.email);
    if (!parts.length) {
        throw new Error('A subject common name is required.');
    }
    return parts.join(', ');
}

function escapeDnValue(value: string): string {
    return value.replace(/([,+"\\<>;])/g, '\\$1');
}

function randomSerialNumber(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    // Clear the top bit so the integer is unambiguously positive.
    bytes[0] &= 0x7f;
    return Array.from(bytes)
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');
}

function pemToDer(pem: string): ArrayBuffer {
    const body = pem
        .replace(/-----BEGIN [^-]+-----/g, '')
        .replace(/-----END [^-]+-----/g, '')
        .replace(/\s+/g, '');
    return Uint8Array.from(Buffer.from(body, 'base64')).buffer;
}
