import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import {
    SUPPORTED_CERTIFICATE_EXTENSIONS,
    ScannedCertificate,
    scanCertificateFile,
} from '../certificates/certificateUtils';

export class CertificateExpiryPanel {
    public static currentPanel: CertificateExpiryPanel | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private _disposables: vscode.Disposable[] = [];

    private constructor(panel: vscode.WebviewPanel) {
        this._panel = panel;
        this._panel.webview.html = this._getWebviewContent();
        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

        this._panel.webview.onDidReceiveMessage(
            (message) => {
                switch (message.command) {
                    case 'openFolder':
                        this.handleOpenFolder();
                        return;
                    case 'scanCertificates':
                        this.handleScanCertificates(message.folderPath);
                        return;
                }
            },
            null,
            this._disposables
        );
    }

    public static render(extensionUri: vscode.Uri) {
        if (CertificateExpiryPanel.currentPanel) {
            CertificateExpiryPanel.currentPanel._panel.reveal(vscode.ViewColumn.One);
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
            const options: vscode.OpenDialogOptions = {
                canSelectMany: false,
                canSelectFiles: false,
                canSelectFolders: true,
                openLabel: 'Select Folder',
            };

            const folderUri = await vscode.window.showOpenDialog(options);

            if (folderUri && folderUri[0]) {
                const selectedPath = folderUri[0].fsPath;
                if (this._panel && this._panel.webview) {
                    this._panel.webview.postMessage({
                        command: 'folderSelected',
                        path: selectedPath,
                    });
                }
            }
        } catch (error) {
            if (this._panel && this._panel.webview) {
                this._panel.webview.postMessage({
                    command: 'error',
                    message: `Failed to open folder dialog: ${error instanceof Error ? error.message : String(error)}`,
                });
            }
        }
    }

    private async handleScanCertificates(folderPath: string) {
        try {
            if (!folderPath || folderPath.trim() === '') {
                this._panel.webview.postMessage({
                    command: 'error',
                    message: 'Please enter a folder path',
                });
                return;
            }

            if (!fs.existsSync(folderPath)) {
                this._panel.webview.postMessage({
                    command: 'error',
                    message: `Folder not found: ${folderPath}`,
                });
                return;
            }

            const stat = fs.statSync(folderPath);
            if (!stat.isDirectory()) {
                this._panel.webview.postMessage({
                    command: 'error',
                    message: 'Path is not a directory',
                });
                return;
            }

            const certificates: ScannedCertificate[] = [];
            const files = this.getAllFiles(folderPath);

            for (const file of files) {
                const ext = path.extname(file).toLowerCase();
                if (SUPPORTED_CERTIFICATE_EXTENSIONS.includes(ext)) {
                    try {
                        certificates.push(scanCertificateFile(file));
                    } catch {
                        // Skip files that can't be parsed
                    }
                }
            }

            if (certificates.length === 0) {
                this._panel.webview.postMessage({
                    command: 'error',
                    message: `No valid certificates found in ${folderPath}. Supported formats: ${SUPPORTED_CERTIFICATE_EXTENSIONS.join(', ')}`,
                });
                return;
            }

            this._panel.webview.postMessage({
                command: 'scanResult',
                certificates: certificates,
            });
        } catch (error) {
            this._panel.webview.postMessage({
                command: 'error',
                message: `Failed to scan folder: ${error instanceof Error ? error.message : String(error)}`,
            });
        }
    }

    private getAllFiles(dirPath: string, arrayOfFiles: string[] = [], depth: number = 0): string[] {
        if (depth > 10) {
            return arrayOfFiles;
        }

        const files = fs.readdirSync(dirPath);

        files.forEach((file) => {
            const filePath = path.join(dirPath, file);
            const stat = fs.lstatSync(filePath);
            if (stat.isDirectory() && !stat.isSymbolicLink()) {
                arrayOfFiles = this.getAllFiles(filePath, arrayOfFiles, depth + 1);
            } else if (stat.isFile()) {
                arrayOfFiles.push(filePath);
            }
        });

        return arrayOfFiles;
    }

    public dispose() {
        CertificateExpiryPanel.currentPanel = undefined;
        this._panel.dispose();
        while (this._disposables.length) {
            const disposable = this._disposables.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }

    private _getWebviewContent(): string {
        const webview = this._panel.webview;
        const nonce = crypto.randomBytes(16).toString('base64url');
        const csp = `default-src 'none'; img-src ${webview.cspSource} https: data:; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';`;
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="${csp}">
    <title>Certificate Expiry Checker</title>
    <style>
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
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            gap: 12px;
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

        #results {
            display: none;
        }

        #results.show {
            display: block;
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
                <button class="outline" id="refresh-btn" title="Rescan Current Folder" style="display: none;">
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

        <div style="margin-bottom: 16px; display: flex; gap: 8px; flex-wrap: wrap;">
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

        <div class="card" style="padding: 0;">
            <table>
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Certificate Name (CN)</th>
                        <th>Issuer</th>
                        <th class="col-type" style="display: none;">Type</th>
                        <th class="col-format" style="display: none;">Format</th>
                        <th>Algorithm</th>
                        <th class="col-validfrom" style="display: none;">Valid From</th>
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

            // Helper function to trigger scan
            function triggerScan() {
                const folderPath = document.getElementById('folder-path').value.trim();

                if (!folderPath) {
                    alert('Please select a folder path using the "Select Folder" button');
                    return;
                }

                if (isScanning) return;

                // Use backend scanning
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

                // Toggle header
                const headers = document.querySelectorAll('.col-' + columnName);
                headers.forEach(header => {
                    header.style.display = isVisible ? '' : 'none';
                });

                // Toggle cells in body
                const cells = document.querySelectorAll('.cell-' + columnName);
                cells.forEach(cell => {
                    cell.style.display = isVisible ? '' : 'none';
                });

                // Update button text
                const button = document.getElementById('toggle-' + columnName);
                if (button) {
                    const label = columnName.charAt(0).toUpperCase() + columnName.slice(1).replace('validfrom', 'Valid From');
                    button.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
                        (isVisible ?
                            '<polyline points="20 6 9 17 4 12"></polyline>' :
                            '<polyline points="9 11 12 14 22 4"></polyline><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path>'
                        ) +
                        '</svg> ' + (isVisible ? 'Hide' : 'Show') + ' ' + label;
                }

                // Update colspan for no-results row
                updateNoResultsColspan();
            }

            function updateNoResultsColspan() {
                let visibleColumns = 5; // Status, CN, Issuer, Algorithm, Expiry Date (always visible)
                if (columnVisibility.type) visibleColumns++;
                if (columnVisibility.format) visibleColumns++;
                if (columnVisibility.validfrom) visibleColumns++;

                const noResultsCell = document.querySelector('.no-results');
                if (noResultsCell) {
                    noResultsCell.setAttribute('colspan', visibleColumns.toString());
                }
            }

            // Event listeners
            const browseBtn = document.getElementById('browse-btn');

            if (browseBtn) {
                browseBtn.addEventListener('click', () => {
                    vscode.postMessage({
                        command: 'openFolder'
                    });
                });
            }

            // Allow Enter key to trigger scan
            const folderPathInput = document.getElementById('folder-path');
            if (folderPathInput) {
                folderPathInput.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        triggerScan();
                    }
                });
            }

            const scanBtn = document.getElementById('scan-btn');
            if (scanBtn) {
                scanBtn.addEventListener('click', triggerScan);
            }

            // Refresh button to rescan the current folder
            const refreshBtn = document.getElementById('refresh-btn');
            if (refreshBtn) {
                refreshBtn.addEventListener('click', () => {
                    const folderPath = document.getElementById('folder-path').value;
                    if (folderPath) {
                        vscode.postMessage({
                            command: 'scanCertificates',
                            folderPath
                        });
                    } else {
                        triggerScan();
                    }
                });
            }

            // Column toggle buttons
            const toggleTypeBtn = document.getElementById('toggle-type');
            if (toggleTypeBtn) {
                toggleTypeBtn.addEventListener('click', () => toggleColumn('type'));
            }

            const toggleFormatBtn = document.getElementById('toggle-format');
            if (toggleFormatBtn) {
                toggleFormatBtn.addEventListener('click', () => toggleColumn('format'));
            }

            const toggleValidFromBtn = document.getElementById('toggle-validfrom');
            if (toggleValidFromBtn) {
                toggleValidFromBtn.addEventListener('click', () => toggleColumn('validfrom'));
            }

            // Tab switching
            document.querySelectorAll('.tab').forEach(tab => {
                tab.addEventListener('click', () => {
                    currentTab = tab.dataset.tab;
                    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                    tab.classList.add('active');
                    renderTable();
                });
            });

            // Make functions globally accessible
            window.escapeHtml = function(text) {
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            };

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
                    if (el) el.textContent = counts[key];
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
                return filtered.sort((a, b) => {
                    const dateA = new Date(a.expiryDate);
                    const dateB = new Date(b.expiryDate);
                    return dateA - dateB;
                });
            }

            function formatDate(dateStr) {
                if (!dateStr) return 'N/A';
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
                    // Calculate visible columns for colspan
                    let visibleColumns = 5; // Status, CN, Issuer, Algorithm, Expiry Date (always visible)
                    if (columnVisibility.type) visibleColumns++;
                    if (columnVisibility.format) visibleColumns++;
                    if (columnVisibility.validfrom) visibleColumns++;
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

                    // Display style based on columnVisibility
                    const typeDisplay = columnVisibility.type ? '' : ' style="display: none;"';
                    const formatDisplay = columnVisibility.format ? '' : ' style="display: none;"';
                    const validFromDisplay = columnVisibility.validfrom ? '' : ' style="display: none;"';

                    return \`
                        <tr>
                            <td>\${statusBadge[status]}</td>
                            <td style="font-weight: 500;">\${window.escapeHtml(cert.owner)}</td>
                            <td>\${window.escapeHtml(cert.issuer || 'N/A')}</td>
                            <td class="cell-type"\${typeDisplay}>\${window.escapeHtml(cert.type)}</td>
                            <td class="cell-format"\${formatDisplay}>\${window.escapeHtml(cert.format || 'N/A')}</td>
                            <td>\${window.escapeHtml(cert.algorithm || 'N/A')}</td>
                            <td class="cell-validfrom"\${validFromDisplay}>\${formatDate(cert.validFrom)}</td>
                            <td class="expiry-date \${dateClass}">\${formatDate(cert.expiryDate)}</td>
                        </tr>
                    \`;
                }).join('');
            }

            // Message handling
        window.addEventListener('message', event => {
            const message = event.data;

            switch (message.command) {
                case 'folderSelected':
                    const folderPathInput = document.getElementById('folder-path');
                    folderPathInput.value = message.path;

                    // Automatically trigger scan when folder is selected
                    isScanning = true;
                    const scanText = document.getElementById('scan-text');
                    const scanBtn = document.getElementById('scan-btn');
                    scanText.innerHTML = '<span class="loading-spinner"></span> Scanning...';
                    scanBtn.disabled = true;

                    vscode.postMessage({
                        command: 'scanCertificates',
                        folderPath: message.path
                    });
                    break;

                case 'scanResult':
                    isScanning = false;
                    const scanBtnResult = document.getElementById('scan-btn');
                    const scanTextResult = document.getElementById('scan-text');
                    const refreshBtnResult = document.getElementById('refresh-btn');
                    scanTextResult.textContent = 'Scan Certificates';
                    scanBtnResult.disabled = false;

                    // Show refresh button for backend scans too
                    if (refreshBtnResult) {
                        refreshBtnResult.style.display = 'inline-flex';
                    }

                    allCertificates = message.certificates;
                    document.getElementById('results').classList.add('show');
                    updateCounts();
                    renderTable();
                    break;

                case 'error':
                    isScanning = false;
                    const scanBtnError = document.getElementById('scan-btn');
                    const scanTextError = document.getElementById('scan-text');
                    if (scanTextError) scanTextError.textContent = 'Scan Certificates';
                    if (scanBtnError) scanBtnError.disabled = false;
                    alert(message.message);
                    break;
            }
        });
        })();
    </script>
</body>
</html>`;
    }
}
