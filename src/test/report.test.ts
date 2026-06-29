import * as assert from 'assert';
import { ScannedCertificate } from '../certificates/certificateUtils';
import { buildExpiryReport, reportFileName } from '../certificates/report';

function scanned(overrides: Partial<ScannedCertificate>): ScannedCertificate {
    return {
        id: 'id',
        name: 'cert.pem',
        owner: 'example.com',
        type: 'TLS/SSL',
        expiryDate: '2999-01-01T00:00:00Z',
        filePath: '/certs/cert.pem',
        issuer: 'Example CA',
        validFrom: '2020-01-01T00:00:00Z',
        serialNumber: '01',
        fingerprint: 'AA:BB',
        algorithm: 'RSA (2048-bit)',
        format: 'PEM',
        ...overrides,
    };
}

suite('expiry report export', () => {
    const certificates = [
        scanned({ owner: 'valid.example.com', expiryDate: '2999-01-01T00:00:00Z' }),
        scanned({ owner: 'expired.example.com', expiryDate: '2000-01-01T00:00:00Z' }),
    ];

    test('builds valid JSON with computed statuses', () => {
        const json = JSON.parse(buildExpiryReport(certificates, 'json', 30)) as {
            count: number;
            certificates: Array<{ owner: string; status: string }>;
        };
        assert.strictEqual(json.count, 2);
        assert.strictEqual(json.certificates.find((c) => c.owner === 'expired.example.com')?.status, 'expired');
        assert.strictEqual(json.certificates.find((c) => c.owner === 'valid.example.com')?.status, 'valid');
    });

    test('builds CSV with a header row and one line per certificate', () => {
        const csv = buildExpiryReport(certificates, 'csv', 30).split('\n');
        assert.ok(csv[0].startsWith('Status,CommonName,Issuer'));
        assert.strictEqual(csv.length, 3);
    });

    test('builds a Markdown table', () => {
        const markdown = buildExpiryReport(certificates, 'markdown', 30);
        assert.ok(markdown.includes('# Certificate Expiry Report'));
        assert.ok(markdown.includes('| Status | Common Name |'));
        assert.ok(markdown.includes('expired.example.com'));
    });

    test('derives sensible file names per format', () => {
        assert.strictEqual(reportFileName('json'), 'certificate-expiry-report.json');
        assert.strictEqual(reportFileName('csv'), 'certificate-expiry-report.csv');
        assert.strictEqual(reportFileName('markdown'), 'certificate-expiry-report.md');
    });
});
