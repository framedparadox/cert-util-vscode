import * as crypto from 'crypto';
import * as vscode from 'vscode';

interface ComponentDoc {
    title: string;
    purpose: string;
    usage: string[];
}

interface GlossaryTerm {
    term: string;
    definition: string;
}

/** Reference documentation for every tool/panel exposed by the extension. */
const COMPONENTS: ComponentDoc[] = [
    {
        title: 'Certificate Tools — Inspect',
        purpose:
            'Decodes a certificate (pasted PEM, a local file, the active editor, or a remote TLS endpoint) into structured ' +
            'fields: subject, issuer, serial number, validity window, SANs, fingerprints, public key info, signature ' +
            'algorithm, key usage, EKU, and the full set of decoded extensions (AKI/SKI, CRL distribution points, ' +
            'certificate policies, name constraints, basic constraints path length, SCT presence).',
        usage: [
            'Command Palette → "Certificate Utility: Open Certificate Tools", then the Inspect tab.',
            'Or run "Inspect Active Certificate" / "Inspect Certificate File" / "Inspect Remote Certificate" directly.',
            'Or right-click a certificate file in the Explorer, or the active editor title bar / context menu.',
        ],
    },
    {
        title: 'Certificate Tools — Validate',
        purpose:
            'Checks a certificate against practical correctness rules: validity window, hostname match, self-signed ' +
            'status, CA-vs-leaf usage, weak signature algorithms (MD5/SHA-1) and short keys, optional OpenSSL trust-chain ' +
            'verification against a CA bundle, and optional online revocation status (CRL/OCSP).',
        usage: [
            'Open Certificate Tools → Validate tab. Provide a hostname to check SAN/CN matching.',
            'Enable "Check revocation online" to query the certificate\'s CRL/OCSP endpoints (requires network access).',
            'Provide a CA file/path to additionally verify the chain of trust with OpenSSL.',
        ],
    },
    {
        title: 'Certificate Tools — Chain',
        purpose:
            'Analyzes a multi-certificate bundle: identifies the likely leaf, intermediate, and root certificates, flags ' +
            'duplicate serials and missing issuers, and cryptographically verifies that each certificate was actually ' +
            'signed by the next certificate in the chain (not just a subject/issuer string match).',
        usage: ['Open Certificate Tools → Chain tab and paste or load a PEM bundle containing the full chain.'],
    },
    {
        title: 'Certificate Tools — Remote',
        purpose: 'Connects to a remote TLS endpoint and retrieves the certificate chain it presents, for inspection or validation.',
        usage: [
            'Open Certificate Tools → Remote tab, or run "Inspect Remote Certificate" and enter host:port (e.g. example.com:443).',
            'Uses a native TLS connection when possible; falls back to OpenSSL `s_client` when available.',
        ],
    },
    {
        title: 'Conversion & Keystore — Convert',
        purpose: 'Builds OpenSSL command instructions for PEM ↔ DER conversion, and for PKCS#12 export from a certificate and private key.',
        usage: ['Open "Certificate Conversion & Keystore" → Convert tab, enter file paths, and copy the generated command.'],
    },
    {
        title: 'Conversion & Keystore — Keystore',
        purpose:
            'Inspects PKCS#12 (.p12/.pfx) and PKCS#7 (.p7b/.p7c/.p7s) bundles natively in-process (no OpenSSL required) ' +
            'and generates `keytool`/OpenSSL command instructions for JKS, PFX, and PKCS#12 export and conversion.',
        usage: [
            'Open "Certificate Conversion & Keystore" → Keystore tab.',
            'Native parsing is attempted first; if it fails for an unsupported variant, an OpenSSL-based fallback recipe is shown instead.',
        ],
    },
    {
        title: 'Certificate Generator',
        purpose:
            'Generates key pairs (RSA-2048/3072/4096, EC-P256/P384, Ed25519), certificate signing requests (CSRs), and ' +
            'self-signed certificates (including CA certificates) entirely on the local machine. Private keys never ' +
            'leave the extension host.',
        usage: [
            'Command Palette → "Certificate Utility: Open Certificate Generator".',
            'Choose an operation (Key Pair / CSR / Self-Signed Certificate), fill in the subject fields, and click Generate.',
            'Use "Inspect Private Key and Certificate Match" to confirm a key and certificate correspond to one another.',
        ],
    },
    {
        title: 'Certificate Expiry Checker',
        purpose:
            'Recursively scans a folder for certificate files, reports their expiry status (valid, expiring soon, expired), ' +
            'and can export the results as a JSON, Markdown, or CSV report for audits or CI pipelines.',
        usage: [
            'Command Palette → "Certificate Utility: Open Certificate Expiry Checker".',
            'Select a folder to scan, then sort/filter the table by status and export a report.',
        ],
    },
    {
        title: 'Remote Watchlist Report',
        purpose:
            'Fetches every endpoint listed in the `certificateUtil.remoteWatchlist` setting over native TLS and produces a ' +
            'single Markdown report of certificate validity/expiry across all of them, for monitoring fleets of endpoints.',
        usage: [
            'Add `host:port` entries to the "certificateUtil.remoteWatchlist" setting.',
            'Command Palette → "Certificate Utility: Open Remote Watchlist Report".',
        ],
    },
    {
        title: 'Certificate Viewer (custom editor)',
        purpose:
            'A read-only rich viewer that opens automatically when you double-click a supported certificate file, instead of raw text.',
        usage: ['Double-click a .pem/.crt/.cer/.cert/.der/.ca-bundle/.ca/.bundle/.p7b/.p7c file in the Explorer.'],
    },
    {
        title: 'Certificate Comparison (diff)',
        purpose: 'Opens two certificates side by side in a native diff editor so field-level differences are easy to spot.',
        usage: ['Command Palette → "Certificate Utility: Open Certificate Comparison", then pick two certificate files.'],
    },
    {
        title: 'Status bar indicator',
        purpose: 'Shows the validity/expiry of the certificate file currently open in the editor, color-coded by status.',
        usage: [
            'Open any supported certificate file; the status bar item appears automatically and links to the Inspect tool when clicked.',
        ],
    },
    {
        title: 'Explorer / editor context menus',
        purpose: 'Lets you jump straight into inspection from where the file already is, without opening the sidebar first.',
        usage: ['Right-click a certificate file in the Explorer, or use the editor context menu / title bar icon while it is open.'],
    },
    {
        title: 'Settings',
        purpose: 'Tunable behavior for expiry thresholds, remote defaults, external tool paths, and the watchlist.',
        usage: [
            '`certificateUtil.expiryWarningDays` (default 30) — days before expiry counted as "expiring soon".',
            '`certificateUtil.defaultRemotePort` (default 443) — port assumed when none is given for a remote target.',
            '`certificateUtil.opensslPath` / `certificateUtil.keytoolPath` — explicit executable paths if not on PATH.',
            '`certificateUtil.remoteWatchlist` — list of `host:port` endpoints for the Remote Watchlist Report.',
        ],
    },
];

/** Glossary of certificate/PKI terminology used throughout the extension's UI. */
const GLOSSARY: GlossaryTerm[] = [
    {
        term: 'X.509',
        definition:
            'The standard that defines the format of public-key certificates, including the fields and extensions this extension decodes.',
    },
    {
        term: 'PEM',
        definition:
            'Privacy-Enhanced Mail format: base64-encoded DER data wrapped in `-----BEGIN ...-----` / `-----END ...-----` ' +
            'header/footer lines. The most common text-based encoding for certificates, keys, and CSRs.',
    },
    {
        term: 'DER',
        definition:
            'Distinguished Encoding Rules: the binary ASN.1 encoding that PEM is a base64 wrapper around. Files with a `.der` extension are raw binary, not text.',
    },
    {
        term: 'PKCS#12 / PFX / P12',
        definition:
            'A binary container format (password-protected) that bundles a certificate, its private key, and optionally a chain of ' +
            'intermediate certificates into a single file. Common extensions: `.p12`, `.pfx`.',
    },
    {
        term: 'PKCS#7 / P7B / P7C',
        definition:
            'A container format for certificates and certificate chains (no private key). Common extensions: `.p7b`, `.p7c`, `.p7s`.',
    },
    {
        term: 'CSR (Certificate Signing Request)',
        definition:
            'A signed request containing a public key and subject information, submitted to a Certificate Authority to obtain a ' +
            'signed certificate. File extension: `.csr`.',
    },
    {
        term: 'CA (Certificate Authority)',
        definition:
            'An entity that signs certificates, vouching for the binding between a public key and an identity. A CA certificate has the CA flag set in Basic Constraints.',
    },
    {
        term: 'Self-signed certificate',
        definition:
            'A certificate whose issuer and subject are the same entity, and which is signed by its own private key rather than by a separate CA.',
    },
    {
        term: 'Root certificate',
        definition:
            'A self-signed CA certificate at the top of a chain of trust; trust ultimately derives from a trust store containing root certificates.',
    },
    {
        term: 'Intermediate certificate',
        definition:
            'A CA certificate signed by another CA (root or intermediate), used to issue leaf certificates without exposing the root key directly.',
    },
    {
        term: 'Leaf / end-entity certificate',
        definition:
            'The certificate actually presented by a server or used by an end user — not a CA certificate. The bottom of the chain of trust.',
    },
    {
        term: 'Chain of trust',
        definition:
            'The ordered sequence of certificates (leaf → intermediate(s) → root) where each certificate is signed by the next, establishing trust back to a trusted root.',
    },
    {
        term: 'Subject / Issuer (DN)',
        definition:
            'Distinguished Names identifying who the certificate is about (Subject) and who signed it (Issuer), made up of fields like CN, O, OU, C, ST, L.',
    },
    {
        term: 'SAN (Subject Alternative Name)',
        definition:
            'An extension listing additional identities (DNS names, IP addresses, email addresses, URIs) the certificate is valid for, used for hostname matching.',
    },
    {
        term: 'Serial number',
        definition:
            'A unique integer assigned by the issuing CA to identify the certificate; used together with the issuer to uniquely reference a certificate.',
    },
    {
        term: 'Validity period (notBefore / notAfter)',
        definition:
            'The date range during which the certificate is considered valid. Expiry checks compare the current date against `notAfter`.',
    },
    {
        term: 'Public key / Private key',
        definition:
            'An asymmetric key pair: the public key is embedded in the certificate and shared freely; the private key must be kept secret and is used to sign or decrypt.',
    },
    {
        term: 'RSA',
        definition:
            'A widely used public-key algorithm. Key strength is measured in bits (2048 is the current minimum recommendation; below that is flagged as weak).',
    },
    {
        term: 'EC (Elliptic Curve)',
        definition:
            'A public-key algorithm family offering equivalent security to RSA at much smaller key sizes (e.g. P-256, P-384 curves).',
    },
    {
        term: 'Ed25519',
        definition: 'A modern elliptic-curve signature algorithm known for speed and resistance to common implementation pitfalls.',
    },
    {
        term: 'Key usage',
        definition:
            "An extension restricting what the certificate's key may be used for (e.g. digital signature, key encipherment, certificate signing, CRL signing).",
    },
    {
        term: 'EKU (Extended Key Usage)',
        definition:
            'An extension further restricting usage to specific purposes (e.g. TLS server authentication, TLS client authentication, code signing) via OIDs.',
    },
    {
        term: 'AKI (Authority Key Identifier)',
        definition:
            "An extension identifying the issuing CA's key, used to help build a chain when multiple CA certificates share a subject name.",
    },
    {
        term: 'SKI (Subject Key Identifier)',
        definition: "An extension identifying this certificate's own public key, referenced by the AKI of certificates it issues.",
    },
    {
        term: 'Basic Constraints',
        definition:
            'An extension declaring whether a certificate is a CA certificate and, optionally, the maximum chain length (path length) it may issue under.',
    },
    {
        term: 'CRL (Certificate Revocation List)',
        definition: 'A signed, periodically published list of certificates a CA has revoked before their expiry date.',
    },
    {
        term: 'CRL Distribution Point',
        definition: 'An extension containing the URL(s) where the current CRL for a certificate can be downloaded.',
    },
    {
        term: 'OCSP (Online Certificate Status Protocol)',
        definition:
            'A protocol for checking the revocation status of a single certificate in real time, as an alternative to downloading a full CRL.',
    },
    {
        term: 'Revocation',
        definition: 'The act of a CA invalidating a certificate before its expiry (e.g. due to key compromise), checked via CRL or OCSP.',
    },
    {
        term: 'Certificate Policies',
        definition:
            "An extension identifying the policies under which the certificate was issued, often referencing the CA's practices via an OID and/or URL.",
    },
    {
        term: 'Name Constraints',
        definition: 'A CA-certificate extension restricting the namespaces (e.g. DNS domains) that certificates issued under it may use.',
    },
    {
        term: 'SCT (Signed Certificate Timestamp) / Certificate Transparency',
        definition:
            'Proof that a certificate was logged in a public Certificate Transparency log, often embedded directly in the certificate as an extension.',
    },
    {
        term: 'Fingerprint',
        definition:
            'A cryptographic hash (typically SHA-1 or SHA-256) of the entire DER-encoded certificate, used as a compact, unique identifier.',
    },
    {
        term: 'JKS (Java KeyStore)',
        definition:
            "Java's proprietary keystore format for certificates and private keys, managed with the `keytool` utility. File extension: `.jks`.",
    },
    {
        term: 'TLS / SSL',
        definition:
            'Transport Layer Security (the modern successor to SSL): the protocol that uses X.509 certificates to authenticate and encrypt network connections.',
    },
    {
        term: 'Hostname matching',
        definition: "Verifying that the hostname being connected to appears in the certificate's SAN list (or, legacy, the Subject CN).",
    },
    {
        term: 'Trust store',
        definition: 'A collection of root CA certificates that a system or application trusts as a starting point for chain validation.',
    },
    {
        term: 'Signature algorithm',
        definition:
            'The algorithm and hash function (e.g. SHA-256 with RSA) the issuing CA used to sign the certificate. MD5 and SHA-1 are considered weak/deprecated.',
    },
];

export class DocumentationPanel {
    public static readonly viewType = 'certificateUtilDocumentation';
    private static currentPanel: DocumentationPanel | undefined;

    private readonly panel: vscode.WebviewPanel;
    private readonly disposables: vscode.Disposable[] = [];

    private constructor(panel: vscode.WebviewPanel) {
        this.panel = panel;
        this.panel.webview.html = this.getWebviewContent();
        this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
    }

    public static render(extensionUri: vscode.Uri) {
        if (DocumentationPanel.currentPanel) {
            DocumentationPanel.currentPanel.panel.reveal(vscode.ViewColumn.One);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            DocumentationPanel.viewType,
            'Certificate Utility Documentation',
            vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
            }
        );
        DocumentationPanel.currentPanel = new DocumentationPanel(panel);
    }

    private dispose() {
        DocumentationPanel.currentPanel = undefined;
        this.panel.dispose();
        while (this.disposables.length) {
            this.disposables.pop()?.dispose();
        }
    }

    private escapeHtml(value: string): string {
        return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    private renderComponent(component: ComponentDoc): string {
        const usage = component.usage.map((step) => `<li>${this.escapeHtml(step)}</li>`).join('');
        return `<article class="card" data-search="${this.escapeHtml((component.title + ' ' + component.purpose).toLowerCase())}">
            <h3>${this.escapeHtml(component.title)}</h3>
            <p class="purpose"><strong>Purpose:</strong> ${this.escapeHtml(component.purpose)}</p>
            <p class="usage-label"><strong>How to use:</strong></p>
            <ul>${usage}</ul>
        </article>`;
    }

    private renderTerm(entry: GlossaryTerm): string {
        return `<article class="card term-card" data-search="${this.escapeHtml((entry.term + ' ' + entry.definition).toLowerCase())}">
            <h4>${this.escapeHtml(entry.term)}</h4>
            <p>${this.escapeHtml(entry.definition)}</p>
        </article>`;
    }

    private getWebviewContent(): string {
        const nonce = crypto.randomBytes(16).toString('base64url');
        const csp = `default-src 'none'; base-uri 'none'; form-action 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';`;

        const componentCards = COMPONENTS.map((component) => this.renderComponent(component)).join('');
        const glossaryCards = [...GLOSSARY]
            .sort((a, b) => a.term.localeCompare(b.term))
            .map((entry) => this.renderTerm(entry))
            .join('');

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="${csp}">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Certificate Utility Documentation</title>
    <style nonce="${nonce}">
        body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 16px 20px 40px; max-width: 980px; margin: 0 auto; }
        h1 { font-size: 1.4rem; margin-bottom: 4px; }
        .intro { color: var(--vscode-descriptionForeground); margin-top: 0; }
        .search-row { position: sticky; top: 0; background: var(--vscode-editor-background); padding: 10px 0; z-index: 1; }
        #search { width: 100%; box-sizing: border-box; padding: 8px 10px; background: var(--vscode-input-background); color: var(--vscode-input-foreground); border: 1px solid var(--vscode-input-border, var(--vscode-panel-border)); border-radius: 4px; font-size: 0.95rem; }
        nav.section-tabs { display: flex; gap: 8px; margin: 14px 0; }
        nav.section-tabs button { padding: 6px 14px; border: 1px solid var(--vscode-panel-border); border-radius: 14px; background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground); cursor: pointer; font: inherit; }
        nav.section-tabs button.active { background: var(--vscode-button-background); color: var(--vscode-button-foreground); }
        section { display: none; }
        section.active { display: block; }
        .card { border: 1px solid var(--vscode-panel-border); border-radius: 6px; padding: 12px 14px; margin-bottom: 12px; background: var(--vscode-editorWidget-background); }
        .card h3 { margin: 0 0 6px; font-size: 1rem; }
        .term-card h4 { margin: 0 0 4px; font-size: 0.95rem; }
        .card p { margin: 4px 0; font-size: 0.88rem; line-height: 1.45; }
        .card ul { margin: 4px 0 0 18px; font-size: 0.88rem; line-height: 1.5; }
        .usage-label { margin-bottom: 2px; }
        .glossary-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 10px; }
        .empty-state { color: var(--vscode-descriptionForeground); font-style: italic; padding: 20px 0; display: none; }
    </style>
</head>
<body>
    <h1>Certificate Utility Documentation</h1>
    <p class="intro">A reference library covering every tool in this extension and the PKI/certificate terminology used throughout it.</p>

    <div class="search-row">
        <input id="search" type="text" placeholder="Search components and glossary terms…" autocomplete="off">
    </div>

    <nav class="section-tabs">
        <button type="button" class="active" data-target="components-section">Components</button>
        <button type="button" data-target="glossary-section">Glossary</button>
    </nav>

    <section id="components-section" class="active">
        ${componentCards}
        <p class="empty-state" id="components-empty">No matching components.</p>
    </section>

    <section id="glossary-section">
        <div class="glossary-grid">${glossaryCards}</div>
        <p class="empty-state" id="glossary-empty">No matching terms.</p>
    </section>

    <script nonce="${nonce}">
        (function () {
            const search = document.getElementById('search');
            const tabs = document.querySelectorAll('nav.section-tabs button');
            const sections = document.querySelectorAll('section');

            tabs.forEach(function (tab) {
                tab.addEventListener('click', function () {
                    tabs.forEach(function (t) { t.classList.remove('active'); });
                    sections.forEach(function (s) { s.classList.remove('active'); });
                    tab.classList.add('active');
                    document.getElementById(tab.dataset.target).classList.add('active');
                });
            });

            function applyFilter() {
                const query = search.value.trim().toLowerCase();
                document.querySelectorAll('.card').forEach(function (card) {
                    const haystack = card.getAttribute('data-search') || '';
                    card.style.display = !query || haystack.indexOf(query) !== -1 ? '' : 'none';
                });
                ['components-section', 'glossary-section'].forEach(function (id) {
                    const section = document.getElementById(id);
                    const visible = Array.from(section.querySelectorAll('.card')).some(function (card) {
                        return card.style.display !== 'none';
                    });
                    const empty = section.querySelector('.empty-state');
                    if (empty) {
                        empty.style.display = visible ? 'none' : 'block';
                    }
                });
            }

            search.addEventListener('input', applyFilter);
        })();
    </script>
</body>
</html>`;
    }
}
