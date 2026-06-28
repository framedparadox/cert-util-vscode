import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import {
    SUPPORTED_CERTIFICATE_EXTENSIONS,
    ScannedCertificate,
    scanCertificateFile,
} from '../certificates/certificateUtils';

/** Maximum directory recursion depth for the certificate scanner. */
const MAX_SCAN_DEPTH = 10;

export class CertificateExpiryPanel {
    // Private so external code cannot null-out or swap the singleton reference.
    private static currentPanel: CertificateExpiryPanel | undefined;

    private readonly panel: vscode.WebviewPanel;
    private readonly disposables: vscode.Disposable[] = [];

    private constructor(panel: vscode.WebviewPanel) {
        this.panel = panel;
        this.panel.webview.html = this.getWebviewContent();
        this.panel.onDidDispose(() => this.dispose(), null, this.disposables);

        this.panel.webview.onDidReceiveMessage(
            (message) => {
                switch (message.command) {
                    case 'openFolder':
                        void this.handleOpenFolder();
                        return;
                    case 'scanCertificates':
                        void this.handleScanCertificates(message.folderPath);
                        return;
                }
            },
            null,
            this.disposables
        );
    }

    public static render(extensionUri: vscode.Uri) {
        if (CertificateExpiryPanel.currentPanel) {
            CertificateExpiryPanel.currentPanel.panel.reveal(vscode.ViewColumn.One);
        } else {
            const panel = vscode.window.createWebviewPanel(
                'certificateExpiryPanel',
                'Certificate Expiry Checker',
                vscode.ViewColumn.One,
                {
                    enableScripts: true,
                    retainContextWhenHidden: true,
                    localResourceRoots: [extensionUri],
                }
            );

            panel.iconPath = vscode.Uri.joinPath(extensionUri, 'resources', 'icons', 'cert-expiry.svg');
            CertificateExpiryPanel.currentPanel = new CertificateExpiryPanel(panel);
        }
    }

    private async handleOpenFolder() {
        try {
            const folderUri = await vscode.window.showOpenDialog({
                canSelectMany: false,
                canSelectFiles: false,
                canSelectFolders: true,
                openLabel: 'Select Folder',
            });

            if (folderUri?.[0]) {
                this.panel.webview.postMessage({
                    command: 'folderSelected',
                    path: folderUri[0].fsPath,
                });
            }
        } catch (error) {
            this.postError(`Failed to open folder dialog: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    private async handleScanCertificates(folderPath: string) {
        try {
            if (!folderPath?.trim()) {
                this.postError('Please select a folder path using the "Select Folder" button.');
                return;
            }

            // Use async stat so we don't block the extension host thread.
            let stat: fs.Stats;
            try {
                stat = await fs.promises.stat(folderPath);
            } catch {
                this.postError(`Folder not found: ${folderPath}`);
                return;
            }

            if (!stat.isDirectory()) {
                this.postError('Path is not a directory.');
                return;
            }

            const files = await this.getAllFiles(folderPath);
            const certificates: ScannedCertificate[] = [];

            for (const file of files) {
                const ext = path.extname(file).toLowerCase();
                if (SUPPORTED_CERTIFICATE_EXTENSIONS.includes(ext)) {
                    try {
                        certificates.push(scanCertificateFile(file));
                    } catch {
                        // Skip files that can't be parsed as valid certificates.
                    }
                }
            }

            if (certificates.length === 0) {
                this.postError(
                    `No valid certificates found in ${folderPath}. Supported formats: ${SUPPORTED_CERTIFICATE_EXTENSIONS.join(', ')}`
                );
                return;
            }

            this.panel.webview.postMessage({
                command: 'scanResult',
                certificates,
            });
        } catch (error) {
            this.postError(`Failed to scan folder: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Recursively collects all file paths under `dirPath` up to `MAX_SCAN_DEPTH` levels deep.
     * Uses async FS APIs so the extension host event loop is not blocked on large trees.
     * Symlinked directories are skipped to prevent infinite loops.
     */
    private async getAllFiles(dirPath: string, depth = 0): Promise<string[]> {
        if (depth > MAX_SCAN_DEPTH) {
            return [];
        }

        let entries: fs.Dirent[];
        try {
            entries = await fs.promises.readdir(dirPath, { withFileTypes: true });
        } catch {
            return [];
        }

        const results: string[] = [];
        for (const entry of entries) {
            const fullPath = path.join(dirPath, entry.name);
            if (entry.isDirectory() && !entry.isSymbolicLink()) {
                const nested = await this.getAllFiles(fullPath, depth + 1);
                results.push(...nested);
            } else if (entry.isFile()) {
                results.push(fullPath);
            }
        }
        return results;
    }

    /** Post an inline error message to the webview (replaces alert() calls). */
    private postError(message: string) {
        this.panel.webview.postMessage({ command: 'error', message });
    }

    public dispose() {
        CertificateExpiryPanel.currentPanel = undefined;
        this.panel.dispose();
        while (this.disposables.length) {
            this.disposables.pop()?.dispose();
        }
    }

    private getWebviewContent(): string {
        const webview = this.panel.webview;
        const nonce = crypto.randomBytes(16).toString('base64url');
        // Remove 'unsafe-inline' from style-src — the <style> block carries the nonce instead.
        const csp = `default-src 'none'; img-src ${webview.cspSource} https: data:; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';`;
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="${csp}">
    <title>Certificate Expiry Checker</title>
    <style nonce="${nonce}">
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            padding: 20px;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            color: var(--vscode-foreground);
            background-color: var(--vscode-editor-background);
            line-height: 1.6;
        }

        h1 {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .lead {
            margin-bottom: 24px;
            color: var(--vscode-descriptionForeground);
        }

        .calendar-icon {
            width: 24px;
            height: 24px;
            color: var(--vscode-textLink-foreground);
        }

        .card {
            background-color: var(--vscode-sideBar-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 24px;
        }

        .card-title {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 16px;
        }

        .form-group {
            margin-bottom: 16px;
        }

        label {
            display: block;
            font-size: 13px;
            font-weight: 500;
            margin-bottom: 6px;
        }

        .input-with-button {
            display: flex;
            gap: 8px;
        }

        input[type="text"] {
            flex: 1;
            padding: 8px 12px;
            font-size: 13px;
            background-color: var(--vscode-input-background);
            color: var(--vscode-input-foreground);
            border: 1px solid var(--vscode-input-border);
            border-radius: 4px;
        }

        input[type="text"]:focus {
            outline: 1px solid var(--vscode-focusBorder);
            border-color: var(--vscode-focusBorder);
        }

        button {
            padding: 8px 16px;
            font-size: 13px;
            font-weight: 500;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: background-color 0.2s;
        }

        button.primary {
            background-color: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
        }

        button.primary:hover {
            background-color: var(--vscode-button-hoverBackground);
        }

        button.outline {
            background-color: transparent;
            color: var(--vscode-foreground);
            border: 1px solid var(--vscode-input-border);
        }

        button.outline:hover {
            background-color: var(--vscode-list-hoverBackground);
        }

        .tabs {
            display: flex;
            gap: 4px;
            border-bottom: 1px solid var(--vscode-panel-border);
            margin-bottom: 20px;
        }

        .tab {
            padding: 10px 16px;
            font-size: 13px;
            font-weight: 500;
            background: transparent;
            color: var(--vscode-foreground);
            border: none;
            border-bottom: 2px solid transparent;
            cursor: pointer;
            opacity: 0.7;
        }

        .tab:hover {
            opacity: 1;
            background-color: var(--vscode-list-hoverBackground);
        }

        .tab.active {
            opacity: 1;
            border-bottom-color: var(--vscode-textLink-foreground);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        thead {
            background-color: var(--vscode-list-hoverBackground);
        }

        th {
            text-align: left;
            padding: 12px;
            font-weight: 600;
            border-bottom: 1px solid var(--vscode-panel-border);
        }

        td {
            padding: 12px;
            border-bottom: 1px solid var(--vscode-panel-border);
        }

        tbody tr:hover {
            background-color: var(--vscode-list-hoverBackground);
        }

        .badge {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 4px 10px;
            font-size: 11px;
            font-weight: 600;
            border-radius: 12px;
            border: 1px solid;
        }

        .badge.valid {
            background-color: rgba(76, 175, 80, 0.1);
            color: #4caf50;
            border-color: #4caf50;
        }

        .badge.expiring {
            background-color: rgba(255, 152, 0, 0.1);
            color: #ff9800;
            border-color: #ff9800;
        }

        .badge.expired {
            background-color: rgba(244, 67, 54, 0.1);
            color: #f44336;
            border-color: #f44336;
        }

        .badge-icon {
            width: 12px;
            height: 12px;
        }

        .expiry-date.expiring {
            color: #ff9800;
            font-weight: 500;
        }

        .expiry-date.expired {
            color: #f44336;
            font-weight: 500;
        }

        .loading-spinner {
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid var(--vscode-input-border);
            border-radius: 50%;
            border-top-color: var(--vscode-button-background);
            animation: spin 0.6s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .no-results {
            text-align: center;
            padding: 40px 20px;
            color: var(--vscode-descriptionForeground);
        }

        /* Inline error banner — replaces blocking alert() calls */
        .error-banner {
            display: none;
            align-items: center;
            gap: 10px;
            padding: 12px 16px;
            margin-bottom: 16px;
            border-radius: 6px;
            border: 1px solid #f44336;
            background-color: rgba(244, 67, 54, 0.1);
            color: #f44336;
            font-size: 13px;
        }

        .error-banner.show {
            display: flex;
        }

        .error-banner-close {
            margin-left: auto;
            background: transparent;
            border: none;
            color: inherit;
            cursor: pointer;
            padding: 0 4px;
            font-size: 16px;
            line-height: 1;
        }

        #results {
            display: none;
        }

        #results.show {
            display: block;
        }

        /* Initially hidden elements (replaces inline style="display:none" which
           would be blocked by the strict style-src nonce CSP). */
        .initially-hidden {
            display: none;
        }

        /* Table cells that are hidden by default until a toggle button shows them */
        .col-type,
        .col-format,
        .col-validfrom,
        .cell-type,
        .cell-format,
        .cell-validfrom {
            display: none;
        }

        /* Column-toggle button bar above the results table */
        .col-toggles {
            margin-bottom: 16px;
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        /* Applied by JS when the user clicks a column-toggle button */
        .col-visible {
            display: table-cell;
        }

        /* Remove padding from the card that wraps the results table */
        .card.card-table {
            padding: 0;
        }

        /* CN column emphasis */
        .cn-cell {
            font-weight: 500;
        }
    </style>
</head>
<body>
    <h1>
        <svg class="calendar-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect>
            <line x1="16" y1="2" x2="16" y2="6"></line>
            <line x1="8" y1="2" x2="8" y2="6"></line>
            <line x1="3" y1="10" x2="21" y2="10"></line>
        </svg>
        Certificate Expiry Checker
    </h1>
    <p class="lead">Scan certificate folders to quickly find valid, expiring, and expired certificates before they disrupt dependent services.</p>

    <!-- Inline error banner (replaces alert() calls) -->
    <div class="error-banner" id="error-banner" role="alert">
        <span id="error-text"></span>
        <button class="error-banner-close" id="error-close" aria-label="Dismiss">&times;</button>
    </div>

    <div class="card">
        <div class="card-title">Scan Folder for Certificates</div>
        <div class="form-group">
            <label for="folder-path">Folder Path</label>
            <div class="input-with-button">
                <input type="text" id="folder-path" placeholder="/path/to/certificates" readonly>
                <button class="outline" id="browse-btn" title="Select Folder Path">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
                    </svg>
                </button>
                <button class="primary" id="scan-btn">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                        <polyline points="14 2 14 8 20 8"></polyline>
                        <line x1="16" y1="13" x2="8" y2="13"></line>
                        <line x1="16" y1="17" x2="8" y2="17"></line>
                        <polyline points="10 9 9 9 8 9"></polyline>
                    </svg>
                    <span id="scan-text">Scan Certificates</span>
                </button>
                <button class="outline initially-hidden" id="refresh-btn" title="Rescan Current Folder">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="23 4 23 10 17 10"></polyline>
                        <polyline points="1 20 1 14 7 14"></polyline>
                        <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
                    </svg>
                </button>
            </div>
        </div>
    </div>

    <div id="results">
        <div class="tabs">
            <button class="tab active" data-tab="all">All (<span id="count-all">0</span>)</button>
            <button class="tab" data-tab="expiring">Expiring Soon (<span id="count-expiring">0</span>)</button>
            <button class="tab" data-tab="expired">Expired (<span id="count-expired">0</span>)</button>
            <button class="tab" data-tab="valid">Valid (<span id="count-valid">0</span>)</button>
        </div>

        <div class="col-toggles">
            <button class="outline" id="toggle-type" data-column="type">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="9 11 12 14 22 4"></polyline>
                    <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path>
                </svg>
                Show Type
            </button>
            <button class="outline" id="toggle-format" data-column="format">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="9 11 12 14 22 4"></polyline>
                    <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path>
                </svg>
                Show Format
            </button>
            <button class="outline" id="toggle-validfrom" data-column="validfrom">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="9 11 12 14 22 4"></polyline>
                    <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path>
                </svg>
                Show Valid From
            </button>
        </div>

        <div class="card card-table">
            <table>
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Certificate Name (CN)</th>
                        <th>Issuer</th>
                        <th class="col-type">Type</th>
                        <th class="col-format">Format</th>
                        <th>Algorithm</th>
                        <th class="col-validfrom">Valid From</th>
                        <th>Expiry Date</th>
                    </tr>
                </thead>
                <tbody id="cert-table-body">
                </tbody>
            </table>
        </div>
    </div>

    <script nonce="${nonce}">
        (function() {
            const vscode = acquireVsCodeApi();
            let allCertificates = [];
            let currentTab = 'all';
            let isScanning = false;

            // Column visibility state
            let columnVisibility = {
                type: false,
                format: false,
                validfrom: false
            };

            // --- Error banner helpers (replaces blocking alert()) ---
            const errorBanner = document.getElementById('error-banner');
            const errorText = document.getElementById('error-text');

            function showError(message) {
                errorText.textContent = message;
                errorBanner.classList.add('show');
            }

            function hideError() {
                errorBanner.classList.remove('show');
            }

            document.getElementById('error-close').addEventListener('click', hideError);

            // Helper function to trigger scan
            function triggerScan() {
                const folderPath = document.getElementById('folder-path').value.trim();

                if (!folderPath) {
                    showError('Please select a folder path using the "Select Folder" button.');
                    return;
                }

                if (isScanning) { return; }

                hideError();
                isScanning = true;
                const scanText = document.getElementById('scan-text');
                const scanBtn = document.getElementById('scan-btn');
                scanText.innerHTML = '<span class="loading-spinner"></span> Scanning...';
                scanBtn.disabled = true;

                vscode.postMessage({
                    command: 'scanCertificates',
                    folderPath
                });
            }

            // Function to toggle column visibility
            function toggleColumn(columnName) {
                columnVisibility[columnName] = !columnVisibility[columnName];
                const isVisible = columnVisibility[columnName];

                // Toggle header and cell visibility via classList (not .style.display which
                // is blocked by strict style-src CSP). The CSS rule for .col-* / .cell-*
                // sets display:none by default; removing that rule via a .visible override.
                const elements = document.querySelectorAll('.col-' + columnName + ', .cell-' + columnName);
                elements.forEach(el => {
                    el.classList.toggle('col-visible', isVisible);
                });

                // Update button text
                const button = document.getElementById('toggle-' + columnName);
                if (button) {
                    const label = columnName === 'validfrom' ? 'Valid From'
                        : columnName.charAt(0).toUpperCase() + columnName.slice(1);
                    button.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
                        (isVisible ?
                            '<polyline points="20 6 9 17 4 12"></polyline>' :
                            '<polyline points="9 11 12 14 22 4"></polyline><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path>'
                        ) +
                        '</svg> ' + (isVisible ? 'Hide' : 'Show') + ' ' + label;
                }

                updateNoResultsColspan();
            }

            function updateNoResultsColspan() {
                let visibleColumns = 5; // Status, CN, Issuer, Algorithm, Expiry Date (always visible)
                if (columnVisibility.type) { visibleColumns++; }
                if (columnVisibility.format) { visibleColumns++; }
                if (columnVisibility.validfrom) { visibleColumns++; }

                const noResultsCell = document.querySelector('.no-results');
                if (noResultsCell) {
                    noResultsCell.setAttribute('colspan', visibleColumns.toString());
                }
            }

            // Event listeners
            document.getElementById('browse-btn').addEventListener('click', () => {
                vscode.postMessage({ command: 'openFolder' });
            });

            document.getElementById('folder-path').addEventListener('keypress', (e) => {
                if (e.key === 'Enter') { triggerScan(); }
            });

            document.getElementById('scan-btn').addEventListener('click', triggerScan);

            document.getElementById('refresh-btn').addEventListener('click', () => {
                const folderPath = document.getElementById('folder-path').value;
                if (folderPath) {
                    vscode.postMessage({ command: 'scanCertificates', folderPath });
                } else {
                    triggerScan();
                }
            });

            document.getElementById('toggle-type').addEventListener('click', () => toggleColumn('type'));
            document.getElementById('toggle-format').addEventListener('click', () => toggleColumn('format'));
            document.getElementById('toggle-validfrom').addEventListener('click', () => toggleColumn('validfrom'));

            // Tab switching
            document.querySelectorAll('.tab').forEach(tab => {
                tab.addEventListener('click', () => {
                    currentTab = tab.dataset.tab;
                    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                    tab.classList.add('active');
                    renderTable();
                });
            });

            // escapeHtml via a text node — no regex needed
            function escapeHtml(text) {
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }

            // Helper functions
            function getStatus(cert) {
                const expiryDate = new Date(cert.expiryDate);
                const today = new Date();
                const oneMonthFromNow = new Date();
                oneMonthFromNow.setMonth(oneMonthFromNow.getMonth() + 1);

                if (expiryDate < today) {
                    return 'expired';
                } else if (expiryDate < oneMonthFromNow) {
                    return 'expiring';
                } else {
                    return 'valid';
                }
            }

            function updateCounts() {
                const counts = {
                    all: allCertificates.length,
                    expiring: allCertificates.filter(c => getStatus(c) === 'expiring').length,
                    expired: allCertificates.filter(c => getStatus(c) === 'expired').length,
                    valid: allCertificates.filter(c => getStatus(c) === 'valid').length
                };

                Object.keys(counts).forEach(key => {
                    const el = document.getElementById('count-' + key);
                    if (el) { el.textContent = counts[key]; }
                });
            }

            function filterCertificates() {
                let filtered;
                switch (currentTab) {
                    case 'expiring':
                        filtered = allCertificates.filter(c => getStatus(c) === 'expiring');
                        break;
                    case 'expired':
                        filtered = allCertificates.filter(c => getStatus(c) === 'expired');
                        break;
                    case 'valid':
                        filtered = allCertificates.filter(c => getStatus(c) === 'valid');
                        break;
                    default:
                        filtered = allCertificates;
                }

                // Sort by expiry date ascending (soonest to expire first)
                return filtered.sort((a, b) => new Date(a.expiryDate) - new Date(b.expiryDate));
            }

            function formatDate(dateStr) {
                if (!dateStr) { return 'N/A'; }
                const date = new Date(dateStr);
                return date.toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric'
                });
            }

            function renderTable() {
                const tbody = document.getElementById('cert-table-body');
                const filtered = filterCertificates();

                if (filtered.length === 0) {
                    let visibleColumns = 5;
                    if (columnVisibility.type) { visibleColumns++; }
                    if (columnVisibility.format) { visibleColumns++; }
                    if (columnVisibility.validfrom) { visibleColumns++; }
                    tbody.innerHTML = '<tr><td colspan="' + visibleColumns + '" class="no-results">No certificates found</td></tr>';
                    return;
                }

                tbody.innerHTML = filtered.map(cert => {
                    const status = getStatus(cert);
                    const statusBadge = {
                        valid: '<span class="badge valid"><svg class="badge-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg> Valid</span>',
                        expiring: '<span class="badge expiring"><svg class="badge-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg> Expiring Soon</span>',
                        expired: '<span class="badge expired"><svg class="badge-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg> Expired</span>'
                    };

                    const dateClass = status === 'expired' ? 'expired' : (status === 'expiring' ? 'expiring' : '');

                    return \`
                        <tr>
                            <td>\${statusBadge[status]}</td>
                            <td class="cn-cell">\${escapeHtml(cert.owner)}</td>
                            <td>\${escapeHtml(cert.issuer || 'N/A')}</td>
                            <td class="cell-type">\${escapeHtml(cert.type)}</td>
                            <td class="cell-format">\${escapeHtml(cert.format || 'N/A')}</td>
                            <td>\${escapeHtml(cert.algorithm || 'N/A')}</td>
                            <td class="cell-validfrom">\${formatDate(cert.validFrom)}</td>
                            <td class="expiry-date \${dateClass}">\${formatDate(cert.expiryDate)}</td>
                        </tr>
                    \`;
                }).join('');
            }

            // Message handling
            window.addEventListener('message', event => {
                const message = event.data;

                switch (message.command) {
                    case 'folderSelected': {
                        document.getElementById('folder-path').value = message.path;
                        hideError();

                        // Automatically trigger scan when folder is selected
                        isScanning = true;
                        document.getElementById('scan-text').innerHTML = '<span class="loading-spinner"></span> Scanning...';
                        document.getElementById('scan-btn').disabled = true;

                        vscode.postMessage({
                            command: 'scanCertificates',
                            folderPath: message.path
                        });
                        break;
                    }

                    case 'scanResult': {
                        isScanning = false;
                        document.getElementById('scan-text').textContent = 'Scan Certificates';
                        document.getElementById('scan-btn').disabled = false;
                        document.getElementById('refresh-btn').classList.remove('initially-hidden');

                        allCertificates = message.certificates;
                        document.getElementById('results').classList.add('show');
                        updateCounts();
                        renderTable();
                        break;
                    }

                    case 'error': {
                        isScanning = false;
                        document.getElementById('scan-text').textContent = 'Scan Certificates';
                        document.getElementById('scan-btn').disabled = false;
                        showError(message.message);
                        break;
                    }
                }
            });
        })();
    </script>
</body>
</html>`;
    }
}
