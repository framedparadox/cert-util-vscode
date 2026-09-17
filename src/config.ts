import * as vscode from 'vscode';
import { DEFAULT_EXPIRY_WARNING_DAYS } from './certificates/certificateUtils';

/** Configuration section used by all `certificateUtil.*` settings. */
export const CONFIG_SECTION = 'certificateUtil';

export interface CertificateUtilConfig {
    /** Number of days before expiry at which a certificate is reported as "expiring". */
    expiryWarningDays: number;
    /** Default port assumed when a remote endpoint is entered without one. */
    defaultRemotePort: number;
    /** Absolute path or command name for the OpenSSL binary; empty means rely on PATH. */
    opensslPath: string;
    /** Absolute path or command name for the Java keytool binary; empty means rely on PATH. */
    keytoolPath: string;
    /** Remote TLS endpoints (host:port) monitored by the watchlist report. */
    remoteWatchlist: string[];
}

/** Reads the current `certificateUtil` settings, applying defaults and basic validation. */
export function getConfig(): CertificateUtilConfig {
    const config = vscode.workspace.getConfiguration(CONFIG_SECTION);

    const expiryWarningDays = config.get<number>('expiryWarningDays', DEFAULT_EXPIRY_WARNING_DAYS);
    const defaultRemotePort = config.get<number>('defaultRemotePort', 443);

    return {
        expiryWarningDays:
            Number.isFinite(expiryWarningDays) && expiryWarningDays > 0 ? Math.floor(expiryWarningDays) : DEFAULT_EXPIRY_WARNING_DAYS,
        defaultRemotePort:
            Number.isInteger(defaultRemotePort) && defaultRemotePort > 0 && defaultRemotePort <= 65535 ? defaultRemotePort : 443,
        opensslPath: (config.get<string>('opensslPath', '') ?? '').trim(),
        keytoolPath: (config.get<string>('keytoolPath', '') ?? '').trim(),
        remoteWatchlist: (config.get<string[]>('remoteWatchlist', []) ?? [])
            .map((entry) => (typeof entry === 'string' ? entry.trim() : ''))
            .filter((entry) => entry.length > 0),
    };
}
