import * as tls from 'tls';
import { parseRemoteTarget } from './externalTools';

export interface RemoteCertificateSummary {
    endpoint: string;
    host: string;
    port: number;
    subject?: string;
    issuer?: string;
    validTo?: string;
    daysRemaining?: number;
    status: 'valid' | 'expiring' | 'expired' | 'error';
    error?: string;
}

const DEFAULT_TIMEOUT_MS = 8000;

/**
 * Fetches the leaf certificate presented by a TLS endpoint using Node's `tls` module (no OpenSSL
 * required). Connection errors are captured in the result rather than thrown.
 */
export function fetchRemoteCertificateSummary(
    endpoint: string,
    warningThresholdDays: number,
    timeoutMs = DEFAULT_TIMEOUT_MS
): Promise<RemoteCertificateSummary> {
    let host: string;
    let port: number;
    try {
        ({ host, port } = parseRemoteTarget(endpoint));
    } catch (error) {
        return Promise.resolve({
            endpoint,
            host: endpoint,
            port: 0,
            status: 'error',
            error: error instanceof Error ? error.message : String(error),
        });
    }

    return new Promise((resolve) => {
        const finish = (summary: RemoteCertificateSummary) => {
            socket.destroy();
            resolve(summary);
        };

        const socket = tls.connect(
            {
                host,
                port,
                servername: host,
                // We only want to read the presented certificate, not enforce trust.
                rejectUnauthorized: false,
                timeout: timeoutMs,
            },
            () => {
                const peer = socket.getPeerCertificate();
                if (!peer || !peer.valid_to) {
                    finish({ endpoint, host, port, status: 'error', error: 'No certificate was presented.' });
                    return;
                }

                const validTo = new Date(peer.valid_to);
                const daysRemaining = Math.floor((validTo.getTime() - Date.now()) / (24 * 60 * 60 * 1000));
                finish({
                    endpoint,
                    host,
                    port,
                    subject: peer.subject?.CN ?? formatName(peer.subject),
                    issuer: peer.issuer?.CN ?? formatName(peer.issuer),
                    validTo: validTo.toISOString(),
                    daysRemaining,
                    status: daysRemaining < 0 ? 'expired' : daysRemaining <= warningThresholdDays ? 'expiring' : 'valid',
                });
            }
        );

        socket.on('timeout', () => finish({ endpoint, host, port, status: 'error', error: 'Connection timed out.' }));
        socket.on('error', (error) => finish({ endpoint, host, port, status: 'error', error: error.message }));
    });
}

/** Fetches every endpoint in the watchlist concurrently. */
export function fetchWatchlist(endpoints: string[], warningThresholdDays: number): Promise<RemoteCertificateSummary[]> {
    return Promise.all(endpoints.map((endpoint) => fetchRemoteCertificateSummary(endpoint, warningThresholdDays)));
}

/** Renders watchlist results as a Markdown report. */
export function buildWatchlistReport(results: RemoteCertificateSummary[]): string {
    const lines = [
        '# Remote Certificate Watchlist',
        '',
        `Generated: ${new Date().toISOString()}`,
        `Endpoints: ${results.length}`,
        '',
        '| Status | Endpoint | Subject | Issuer | Expires | Days Left |',
        '| --- | --- | --- | --- | --- | --- |',
    ];
    for (const result of results) {
        const expires = result.validTo ?? '';
        const days = typeof result.daysRemaining === 'number' ? String(result.daysRemaining) : '';
        const detail = result.status === 'error' ? `error: ${result.error ?? 'unknown'}` : result.status;
        lines.push(
            `| ${detail} | ${cell(result.endpoint)} | ${cell(result.subject ?? '')} | ${cell(result.issuer ?? '')} | ${cell(expires)} | ${days} |`
        );
    }
    return lines.join('\n') + '\n';
}

function formatName(name: tls.PeerCertificate['subject'] | undefined): string | undefined {
    if (!name) {
        return undefined;
    }
    return (
        Object.entries(name)
            .map(([key, value]) => `${key}=${value}`)
            .join(', ') || undefined
    );
}

function cell(value: string): string {
    return value.replace(/\|/g, '\\|').replace(/\n/g, ' ');
}
