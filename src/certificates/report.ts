import { ScannedCertificate, getCertificateStatus } from './certificateUtils';

export type ReportFormat = 'json' | 'markdown' | 'csv';

interface ReportRow extends ScannedCertificate {
    status: string;
}

/**
 * Builds an exportable expiry report from scanned certificates in the requested format. The status of
 * each certificate is computed against `warningThresholdDays` so the report matches the scanner view.
 */
export function buildExpiryReport(certificates: ScannedCertificate[], format: ReportFormat, warningThresholdDays: number): string {
    const reference = new Date();
    const rows: ReportRow[] = certificates.map((certificate) => ({
        ...certificate,
        status: safeStatus(certificate.expiryDate, reference, warningThresholdDays),
    }));

    switch (format) {
        case 'json':
            return JSON.stringify({ generatedAt: reference.toISOString(), count: rows.length, certificates: rows }, null, 2);
        case 'csv':
            return buildCsv(rows);
        case 'markdown':
        default:
            return buildMarkdown(rows, reference);
    }
}

/** Default filename for a report of the given format. */
export function reportFileName(format: ReportFormat): string {
    const extension = format === 'markdown' ? 'md' : format;
    return `certificate-expiry-report.${extension}`;
}

function safeStatus(expiryDate: string, reference: Date, warningThresholdDays: number): string {
    try {
        return getCertificateStatus(expiryDate, reference, warningThresholdDays);
    } catch {
        return 'unknown';
    }
}

function buildMarkdown(rows: ReportRow[], reference: Date): string {
    const header = ['# Certificate Expiry Report', '', `Generated: ${reference.toISOString()}`, `Certificates: ${rows.length}`, ''];
    const counts = countByStatus(rows);
    header.push(`- Expired: ${counts.expired}`, `- Expiring soon: ${counts.expiring}`, `- Valid: ${counts.valid}`, '');
    const table = [
        '| Status | Common Name | Issuer | Expires | Algorithm | File |',
        '| --- | --- | --- | --- | --- | --- |',
        ...rows.map(
            (row) =>
                `| ${row.status} | ${escapeCell(row.owner)} | ${escapeCell(row.issuer)} | ${escapeCell(row.expiryDate)} | ${escapeCell(row.algorithm)} | ${escapeCell(row.filePath)} |`
        ),
    ];
    return [...header, ...table, ''].join('\n');
}

function buildCsv(rows: ReportRow[]): string {
    const header = ['Status', 'CommonName', 'Issuer', 'ValidFrom', 'Expires', 'SerialNumber', 'Algorithm', 'Format', 'FilePath'];
    const lines = rows.map((row) =>
        [row.status, row.owner, row.issuer, row.validFrom, row.expiryDate, row.serialNumber, row.algorithm, row.format, row.filePath]
            .map(csvField)
            .join(',')
    );
    return [header.join(','), ...lines].join('\n');
}

function countByStatus(rows: ReportRow[]): { expired: number; expiring: number; valid: number } {
    return {
        expired: rows.filter((row) => row.status === 'expired').length,
        expiring: rows.filter((row) => row.status === 'expiring').length,
        valid: rows.filter((row) => row.status === 'valid').length,
    };
}

function escapeCell(value: string): string {
    return (value ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function csvField(value: string): string {
    const text = value ?? '';
    return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}
