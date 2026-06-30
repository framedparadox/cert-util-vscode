# Certificate Utility

Certificate Utility is a VS Code extension for inspecting, validating, generating, and monitoring X.509 certificate artifacts without leaving the editor. It combines native in-process parsing (no OpenSSL required for the common path) with optional OpenSSL/keytool fallbacks for legacy formats.

## Features

### Certificate Tools (Inspect / Validate / Chain / Remote)

Run `Certificate Utility: Open Certificate Tools` from the Command Palette.

- Inspect pasted PEM content, explicit certificate files, the active editor, or a remote TLS endpoint.
- Classify X.509 certificates, certificate bundles, CSRs, private keys, PKCS#7 files, PKCS#12 files, and JKS keystores.
- Decode structured certificate details including subject, issuer, SANs, fingerprints, signature algorithm, public key metadata, key usage, EKU hints, and authority information.
- Decode the long tail of X.509 extensions: Authority/Subject Key Identifiers, CRL Distribution Points, Certificate Policies, Name Constraints, Basic Constraints path length, and embedded SCT presence.
- Validate validity windows, hostname matching, self-signed status, CA vs leaf usage, weak signature algorithms (MD5/SHA-1) and short keys, and optional OpenSSL trust verification.
- Check certificate revocation status online via CRL and OCSP.
- Analyze certificate chains with real cryptographic signature verification between links (not just subject/issuer string matching) and highlight likely leaf, intermediate, and root entries, duplicate serials, and missing issuers.
- Fetch and inspect remote TLS certificate chains over a native TLS connection (no OpenSSL required) or via `s_client` when available.
- Open the `Info` button at the bottom of each tool section to view inline usage guidance, then click it again to collapse the details.

### Certificate Generator

Run `Certificate Utility: Open Certificate Generator` from the Command Palette.

- Generate RSA (2048/3072/4096), EC (P-256/P-384), and Ed25519 key pairs as PEM.
- Generate certificate signing requests (CSRs) with subject and SAN fields.
- Generate self-signed certificates, including CA certificates, with configurable validity.
- Build a PKCS#12 (PFX) container natively from a certificate and private key.
- `Certificate Utility: Inspect Private Key and Certificate Match` verifies a private key corresponds to a certificate by signing and verifying a nonce — no key material leaves the machine.

### Conversion & Keystore

Run `Certificate Utility: Open Certificate Conversion & Keystore` from the Command Palette.

- Inspect PKCS#7 and PKCS#12 bundles natively (no OpenSSL required), with an OpenSSL fallback for unsupported variants.
- Build OpenSSL commands for PEM ↔ DER conversion from explicit file paths.
- Inspect CSR files.
- Generate OpenSSL command instructions for PKCS#12 export from a certificate and private key.
- Generate Java `keytool` commands for JKS alias export and JKS to PKCS#12 conversion.
- Generate PEM certificate and private-key export commands for JKS, PFX, and PKCS#12 files.

### Certificate Expiry Checker

Run `Certificate Utility: Open Certificate Expiry Checker` from the Command Palette.

- Select a folder and scan recursively for certificate files.
- Sort certificates by expiration date.
- Filter the result table by all, expiring soon, expired, and valid certificates.
- Toggle optional columns for certificate type, format, and valid-from date.
- Export the scan results as a JSON, Markdown, or CSV report for CI/audit use.

### Remote Watchlist

Run `Certificate Utility: Open Remote Watchlist Report` from the Command Palette.

- Configure a list of `host:port` endpoints in the `certificateUtil.remoteWatchlist` setting.
- Fetch every endpoint over native TLS and generate a Markdown report of validity/expiry status across all of them.

### Certificate Viewer & Diff

- Double-click a `.pem`, `.crt`, `.cer`, `.cert`, `.der`, `.ca-bundle`, `.ca`, `.bundle`, `.p7b`, or `.p7c` file to open the read-only Certificate Viewer custom editor.
- `Certificate Utility: Open Certificate Comparison` opens two certificates side-by-side in a diff editor.

### Status Bar & Context Menus

- The status bar shows the validity/expiry of the certificate file in the active editor and links to the Inspect tool.
- Right-click a certificate file in the Explorer, or the active editor, to inspect it directly.

### Documentation

Run `Certificate Utility: Open Documentation` from the Command Palette, or use the **Documentation** entry at the bottom of the sidebar tool list.

- A built-in reference covering the purpose and usage of every tool/component in the extension.
- A searchable glossary defining the certificate/PKI terminology used throughout the UI (X.509, PEM, DER, PKCS#12, CSR, SAN, AKI/SKI, CRL, OCSP, fingerprints, and more).

## Supported Formats

The expiry scanner parses certificate files that Node.js can read as X.509 certificates:

- `.crt`
- `.cer`
- `.cert`
- `.pem`
- `.der`
- `.ca-bundle`
- `.ca`
- `.bundle`

The certificate tools workbench also natively parses or guides workflows for:

- `.p12`
- `.pfx`
- `.p7b`
- `.p7c`
- `.p7s`
- `.csr`
- `.key`
- `.jks`

## Commands

- `certificateUtil.openCertificateTools`: Open Certificate Tools
- `certificateUtil.openCertificateOperations`: Open Certificate Conversion & Keystore
- `certificateUtil.inspectActiveCertificate`: Inspect Active Certificate
- `certificateUtil.inspectCertificateFile`: Inspect Certificate File
- `certificateUtil.inspectRemoteCertificate`: Inspect Remote Certificate
- `certificateUtil.openInspectTool`: Open Inspect Tool
- `certificateUtil.openValidateTool`: Open Validate Tool
- `certificateUtil.openChainTool`: Open Chain Tool
- `certificateUtil.openConvertTool`: Open Convert Tool
- `certificateUtil.openKeystoreTool`: Open Keystore Tool
- `certificateUtil.openRemoteTool`: Open Remote Tool
- `certificateUtil.openExpiryChecker`: Open Certificate Expiry Checker
- `certificateUtil.openGenerateTool`: Open Certificate Generator
- `certificateUtil.verifyKeyMatchesCertificate`: Inspect Private Key and Certificate Match
- `certificateUtil.compareCertificates`: Open Certificate Comparison
- `certificateUtil.checkRemoteWatchlist`: Open Remote Watchlist Report
- `certificateUtil.openDocumentation`: Open Documentation

## Settings

- `certificateUtil.expiryWarningDays` (default `30`): Days before expiry to report a certificate as "expiring soon" in validation, the expiry scanner, and the status bar.
- `certificateUtil.defaultRemotePort` (default `443`): Default TCP port assumed when a remote TLS endpoint is entered without an explicit port.
- `certificateUtil.opensslPath`: Path to the OpenSSL executable. Leave empty to use `openssl` from the system PATH.
- `certificateUtil.keytoolPath`: Path to the Java `keytool` executable. Leave empty to use `keytool` from the system PATH.
- `certificateUtil.remoteWatchlist`: Remote TLS endpoints (`host:port`) monitored by the Remote Watchlist Report command.

## Requirements

- VS Code 1.105.0 or newer.
- Java `keytool` is required only for JKS-specific actions.
- OpenSSL is required only as a fallback for PKCS#7/PKCS#12 variants that native parsing doesn't support, trust verification, and `s_client`-based remote inspection.

## Privacy

Certificate parsing, generation, and revocation checks run inside the local or remote VS Code extension host. The extension does not upload certificate contents, private keys, or scan results. Remote inspection, revocation checks (CRL/OCSP), and watchlist monitoring only make the outbound network connections explicitly requested or configured by the user; OpenSSL/keytool operations run on the extension host machine.

## Development

```bash
npm ci
npm run lint
npm run compile
npm run compile-tests
npm test
npm run package:vsix
```
