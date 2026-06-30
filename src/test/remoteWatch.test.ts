import * as assert from 'assert';
import { buildWatchlistReport, fetchRemoteCertificateSummary } from '../certificates/remoteWatch';

suite('remote watchlist', () => {
    test('returns an error result for an unparseable endpoint without throwing', async () => {
        const result = await fetchRemoteCertificateSummary('https://not a valid endpoint', 30);
        assert.strictEqual(result.status, 'error');
        assert.ok(result.error);
    });

    test('builds a Markdown report with one row per endpoint', () => {
        const report = buildWatchlistReport([
            {
                endpoint: 'a.example.com:443',
                host: 'a.example.com',
                port: 443,
                status: 'valid',
                validTo: '2030-01-01T00:00:00Z',
                daysRemaining: 1000,
            },
            { endpoint: 'b.example.com:443', host: 'b.example.com', port: 443, status: 'error', error: 'Connection timed out.' },
        ]);

        assert.ok(report.includes('# Remote Certificate Watchlist'));
        assert.ok(report.includes('a.example.com:443'));
        assert.ok(report.includes('error: Connection timed out.'));
    });
});
