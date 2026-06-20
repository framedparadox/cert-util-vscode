# Certificate Utility

Certificate Utility is a VS Code extension for inspecting certificate artifacts without leaving the editor. It provides a compact Activity Bar launcher, certificate inspection and validation tools, dedicated conversion and keystore workflows, and an expiry scanner.

## Features

### Certificate Tools

Open `Certificate Utility: Certificate Tools` from the Command Palette or the Certificates Activity Bar view.

- Inspect pasted PEM content or explicit certificate files. The command surface also supports inspecting the active editor directly.
- Classify X.509 certificates, certificate bundles, CSRs, private keys, PKCS#7 files, PKCS#12 files, and JKS keystores.
- Decode structured certificate details including subject, issuer, SANs, fingerprints, signature algorithm, public key metadata, key usage, EKU hints, and authority information.
- Validate validity windows, hostname matching, self-signed status, CA vs leaf usage, and optional trust verification through OpenSSL.
- Analyze certificate chains and highlight likely leaf, intermediate, and root entries, duplicate serials, and missing issuers.
- Fetch and inspect remote TLS certificate chains using OpenSSL `s_client` when available.
- Open the `Info` button at the bottom of each tool section to view inline usage guidance, then click it again to collapse the details.

### Conversion & Keystore

Open `Certificate Utility: Certificate Conversion & Keystore` from the Command Palette or the Certificates Activity Bar view.

- Build OpenSSL commands for PEM to DER and DER to PEM conversion from explicit file paths.
- Inspect PKCS#7 and PKCS#12 bundles when OpenSSL is available.
- Inspect CSR files.
- Generate OpenSSL command instructions for PKCS#12 export from a certificate and private key.
- Generate Java `keytool` commands for JKS alias export and JKS to PKCS#12 conversion.
- Generate PEM certificate and private-key export commands for JKS, PFX, and PKCS#12 files.

### Certificate Expiry Checker

Open `Certificate Utility: Certificate Expiry Checker` from the Command Palette or the Certificates Activity Bar view.

- Select a folder and scan recursively for certificate files.
- Sort certificates by expiration date.
- Filter the result table by all, expiring soon, expired, and valid certificates.
- Toggle optional columns for certificate type, format, and valid-from date.

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

The certificate tools workbench also classifies and guides workflows for:

- `.p12`
- `.pfx`
- `.p7b`
- `.p7c`
- `.p7s`
- `.csr`
- `.key`
- `.jks`

## Commands

- `certificateUtil.openCertificateTools`: Certificate Tools
- `certificateUtil.openCertificateOperations`: Certificate Conversion & Keystore
- `certificateUtil.inspectActiveCertificate`: Inspect Active Certificate
- `certificateUtil.inspectCertificateFile`: Inspect Certificate File
- `certificateUtil.inspectRemoteCertificate`: Inspect Remote Certificate
- `certificateUtil.openInspectTool`: Open Inspect Tool
- `certificateUtil.openValidateTool`: Open Validate Tool
- `certificateUtil.openChainTool`: Open Chain Tool
- `certificateUtil.openConvertTool`: Open Convert Tool
- `certificateUtil.openKeystoreTool`: Open Keystore Tool
- `certificateUtil.openRemoteTool`: Open Remote Tool
- `certificateUtil.openExpiryChecker`: Certificate Expiry Checker

## Requirements

- VS Code 1.105.0 or newer.
- Java `keytool` is required only when you run or generate JKS-specific actions.
- OpenSSL is required only for external-tool workflows such as PKCS#7 or PKCS#12 inspection, trust verification, and remote TLS inspection.

## Development

```bash
npm ci
npm run lint
npm run compile
npm run compile-tests
npm test
npx vsce package --no-dependencies --out certi.vsix
```

## Privacy

Certificate parsing runs locally inside VS Code. The extension does not upload certificate contents, private keys, or scan results.
