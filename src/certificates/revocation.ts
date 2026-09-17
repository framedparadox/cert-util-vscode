// reflect-metadata must load before @peculiar/x509 (tsyringe-based DI).
import 'reflect-metadata';
import { webcrypto } from 'crypto';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { AuthorityInfoAccessExtension, CRLDistributionPointsExtension, GeneralName, X509Certificate, X509Crl } from '@peculiar/x509';
import { GeneralName as Asn1GeneralName } from '@peculiar/asn1-x509';

const cryptoEngine = new pkijs.CryptoEngine({ name: 'cert-util', crypto: webcrypto as unknown as Crypto });
pkijs.setEngine('cert-util', cryptoEngine);

export type RevocationStatus = 'good' | 'revoked' | 'unknown';

export interface RevocationResult {
    status: RevocationStatus;
    method: 'OCSP' | 'CRL' | 'none';
    detail: string;
    source?: string;
    revocationDate?: string;
}

/** How long a fetched CRL is cached before it is re-downloaded. */
const CRL_CACHE_TTL_MS = 10 * 60 * 1000;
/** Maximum number of distinct CRL URLs retained in the in-memory cache. */
const CRL_CACHE_MAX_ENTRIES = 64;
/** Upper bound on a downloaded CRL/OCSP response to avoid unbounded memory use. */
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const NETWORK_TIMEOUT_MS = 10_000;

interface CachedCrl {
    fetchedAt: number;
    data: ArrayBuffer;
}
const crlCache = new Map<string, CachedCrl>();

/** Returns the HTTP(S) CRL distribution point URLs declared in the certificate. */
export function getCrlDistributionUrls(certificatePem: string): string[] {
    try {
        const certificate = new X509Certificate(certificatePem);
        const extension = certificate.getExtension(CRLDistributionPointsExtension);
        const urls: string[] = [];
        for (const point of extension?.distributionPoints ?? []) {
            for (const name of point.distributionPoint?.fullName ?? []) {
                const url = httpUrlFromAsn1GeneralName(name);
                if (url) {
                    urls.push(url);
                }
            }
        }
        return urls;
    } catch {
        return [];
    }
}

/** Returns the HTTP(S) OCSP responder URLs declared in the certificate's Authority Information Access. */
export function getOcspUrls(certificatePem: string): string[] {
    try {
        const certificate = new X509Certificate(certificatePem);
        const extension = certificate.getExtension(AuthorityInfoAccessExtension);
        return (extension?.ocsp ?? []).map(httpUrlFromX509GeneralName).filter((url): url is string => Boolean(url));
    } catch {
        return [];
    }
}

/**
 * Checks a certificate's revocation status against a CRL that has already been downloaded. Pure and
 * offline, so it is fully unit-testable. Returns `revoked` (with the date) when the serial appears in
 * the CRL, otherwise `good`.
 */
export function checkAgainstCrl(
    crlData: ArrayBuffer | Buffer,
    certificatePem: string
): { status: RevocationStatus; revocationDate?: string } {
    const crl = new X509Crl(toArrayBuffer(crlData));
    const certificate = new X509Certificate(certificatePem);
    const revoked = crl.findRevoked(certificate.serialNumber);
    if (revoked) {
        return { status: 'revoked', revocationDate: revoked.revocationDate.toISOString() };
    }
    return { status: 'good' };
}

/**
 * Downloads the certificate's CRL(s) and checks revocation. Results are cached per URL for a few
 * minutes. Network or parse failures yield an `unknown` status rather than throwing.
 */
export async function checkRevocationViaCrl(certificatePem: string): Promise<RevocationResult> {
    const urls = getCrlDistributionUrls(certificatePem);
    if (!urls.length) {
        return { status: 'unknown', method: 'CRL', detail: 'No CRL distribution points are present in the certificate.' };
    }

    for (const url of urls) {
        try {
            const data = await fetchCrl(url);
            const { status, revocationDate } = checkAgainstCrl(data, certificatePem);
            return {
                status,
                method: 'CRL',
                source: url,
                detail:
                    status === 'revoked'
                        ? `Certificate is listed as revoked in the CRL${revocationDate ? ` (revoked ${revocationDate})` : ''}.`
                        : 'Certificate is not listed in the CRL.',
                revocationDate,
            };
        } catch {
            // Try the next distribution point.
        }
    }

    return { status: 'unknown', method: 'CRL', detail: 'None of the CRL distribution points could be retrieved or parsed.' };
}

/**
 * Performs an online OCSP check. Requires the issuer certificate to build the request. Network or
 * parse failures yield an `unknown` status rather than throwing.
 */
export async function checkRevocationViaOcsp(certificatePem: string, issuerPem: string): Promise<RevocationResult> {
    const urls = getOcspUrls(certificatePem);
    if (!urls.length) {
        return { status: 'unknown', method: 'OCSP', detail: 'No OCSP responder URL is present in the certificate.' };
    }

    const certificate = pkijsCertificate(certificatePem);
    const issuer = pkijsCertificate(issuerPem);

    const request = new pkijs.OCSPRequest();
    await request.createForCertificate(certificate, { hashAlgorithm: 'SHA-256', issuerCertificate: issuer }, cryptoEngine);
    const requestBytes = request.toSchema(true).toBER();

    for (const url of urls) {
        try {
            const responseBytes = await postOcsp(url, requestBytes);
            const asn1 = asn1js.fromBER(responseBytes);
            const ocspResponse = new pkijs.OCSPResponse({ schema: asn1.result });
            if (ocspResponse.responseStatus.valueBlock.valueDec !== 0 || !ocspResponse.responseBytes) {
                return { status: 'unknown', method: 'OCSP', source: url, detail: 'OCSP responder returned a non-successful status.' };
            }

            const basic = new pkijs.BasicOCSPResponse({
                schema: asn1js.fromBER(ocspResponse.responseBytes.response.valueBlock.valueHexView).result,
            });
            const status = await basic.getCertificateStatus(certificate, issuer, cryptoEngine);
            // pkijs status values: 0 = good, 1 = revoked, 2 = unknown.
            if (status.status === 0) {
                return { status: 'good', method: 'OCSP', source: url, detail: 'OCSP responder reports the certificate as good.' };
            }
            if (status.status === 1) {
                return { status: 'revoked', method: 'OCSP', source: url, detail: 'OCSP responder reports the certificate as revoked.' };
            }
            return { status: 'unknown', method: 'OCSP', source: url, detail: 'OCSP responder reports an unknown status.' };
        } catch {
            // Try the next responder.
        }
    }

    return { status: 'unknown', method: 'OCSP', detail: 'The OCSP responder(s) could not be reached or returned an unparseable response.' };
}

/**
 * Checks revocation using OCSP first (when an issuer is available) and falling back to CRL. Returns
 * the first definitive (`good`/`revoked`) answer, otherwise an `unknown` result.
 */
export async function checkRevocation(certificatePem: string, issuerPem?: string): Promise<RevocationResult> {
    if (issuerPem) {
        const ocsp = await checkRevocationViaOcsp(certificatePem, issuerPem);
        if (ocsp.status !== 'unknown') {
            return ocsp;
        }
    }

    const crl = await checkRevocationViaCrl(certificatePem);
    if (crl.status !== 'unknown') {
        return crl;
    }

    if (!issuerPem) {
        return {
            status: 'unknown',
            method: 'none',
            detail: 'OCSP requires the issuer certificate, and no usable CRL was available.',
        };
    }
    return crl;
}

function pkijsCertificate(pem: string): pkijs.Certificate {
    const der = pemToArrayBuffer(pem);
    const asn1 = asn1js.fromBER(der);
    return new pkijs.Certificate({ schema: asn1.result });
}

async function fetchCrl(url: string): Promise<ArrayBuffer> {
    const cached = crlCache.get(url);
    if (cached && Date.now() - cached.fetchedAt < CRL_CACHE_TTL_MS) {
        return cached.data;
    }
    const data = await fetchArrayBuffer(url, { method: 'GET' });
    // Bound the cache so a long session that touches many distinct CRL URLs cannot grow without
    // limit. Map preserves insertion order, so the first key is the oldest.
    if (crlCache.size >= CRL_CACHE_MAX_ENTRIES) {
        const oldest = crlCache.keys().next().value;
        if (oldest !== undefined) {
            crlCache.delete(oldest);
        }
    }
    crlCache.set(url, { fetchedAt: Date.now(), data });
    return data;
}

async function postOcsp(url: string, body: ArrayBuffer): Promise<ArrayBuffer> {
    return fetchArrayBuffer(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/ocsp-request' },
        body,
    });
}

async function fetchArrayBuffer(url: string, init: RequestInit): Promise<ArrayBuffer> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), NETWORK_TIMEOUT_MS);
    try {
        const response = await fetch(url, { ...init, signal: controller.signal });
        if (!response.ok) {
            throw new Error(`Request to ${url} failed with status ${response.status}.`);
        }
        // Reject early if the server declares an oversized body...
        const declaredLength = Number(response.headers.get('content-length'));
        if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) {
            throw new Error('Revocation response exceeds the size limit.');
        }
        // ...and stream the body with a running cap so a server that omits or lies about
        // content-length (or uses chunked encoding) still cannot exhaust memory.
        return await readBoundedBody(response, MAX_RESPONSE_BYTES);
    } finally {
        clearTimeout(timer);
    }
}

async function readBoundedBody(response: Response, limit: number): Promise<ArrayBuffer> {
    const body = response.body;
    if (!body) {
        const data = await response.arrayBuffer();
        if (data.byteLength > limit) {
            throw new Error('Revocation response exceeds the size limit.');
        }
        return data;
    }

    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) {
            break;
        }
        total += value.byteLength;
        if (total > limit) {
            await reader.cancel();
            throw new Error('Revocation response exceeds the size limit.');
        }
        chunks.push(value);
    }

    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return out.buffer;
}

function httpUrlFromAsn1GeneralName(name: Asn1GeneralName): string | undefined {
    const url = name.uniformResourceIdentifier;
    return url && /^https?:\/\//i.test(url) ? url : undefined;
}

function httpUrlFromX509GeneralName(name: GeneralName): string | undefined {
    return name.type === 'url' && /^https?:\/\//i.test(name.value) ? name.value : undefined;
}

/** Copies any buffer-like value into a fresh, non-shared ArrayBuffer accepted by the ASN.1 parsers. */
function toArrayBuffer(data: ArrayBuffer | Buffer): ArrayBuffer {
    if (data instanceof ArrayBuffer) {
        return data;
    }
    const copy = new ArrayBuffer(data.byteLength);
    new Uint8Array(copy).set(data);
    return copy;
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
    const body = pem
        .replace(/-----BEGIN [^-]+-----/g, '')
        .replace(/-----END [^-]+-----/g, '')
        .replace(/\s+/g, '');
    return toArrayBuffer(Buffer.from(body, 'base64'));
}
