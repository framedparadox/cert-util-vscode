# Changelog

All notable changes to the Certificate Utility extension are documented in this file.

## [0.0.5] - Unreleased

### Added

- Built-in Documentation panel (`certificateUtil.openDocumentation`, plus a "Documentation" entry at the bottom of the sidebar tool list): a reference for every component's purpose and usage, and a searchable glossary of certificate/PKI terminology.

### Changed

- Lazy-load `node-forge`, `@peculiar/x509`, and `pkijs`/`asn1js` so they are only evaluated when a user actually triggers keystore parsing, certificate generation, or a revocation check, instead of at extension activation. This significantly reduces activation cost (the bundled extension entry chunk dropped from eagerly including all crypto dependencies to ~459 KiB, with the heavy libraries split into separate on-demand chunks).

## [0.0.4]

### Added

- Certificate generation (`certificateUtil.openGenerateTool`): RSA/EC/Ed25519 key pairs, CSRs, and self-signed certificates, plus native PKCS#12 (PFX) building.
- Private key ↔ certificate match verification (`certificateUtil.verifyKeyMatchesCertificate`).
- Certificate revocation checking via CRL and OCSP, wired into the Validate tab.
- Native PKCS#12 and PKCS#7 parsing (no OpenSSL required) with an OpenSSL fallback.
- Full X.509 extension decoding: AKI/SKI, CRL Distribution Points, Certificate Policies, Name Constraints, Basic Constraints path length, and SCT presence.
- Read-only Certificate Viewer custom editor for certificate files.
- Certificate comparison/diff (`certificateUtil.compareCertificates`).
- Cryptographic chain-signature verification (replacing subject/issuer string comparison) with verified/broken link badges in the Chain view.
- Expiry report export (JSON/Markdown/CSV) from the expiry scanner.
- Remote TLS endpoint watchlist (`certificateUtil.checkRemoteWatchlist`, `certificateUtil.remoteWatchlist` setting).
- Weak signature algorithm (MD5/SHA-1) and short-key warnings.
- Configuration settings: `expiryWarningDays`, `defaultRemotePort`, `opensslPath`, `keytoolPath`, `remoteWatchlist`.
- Explorer and editor context menus for inspecting certificate files directly.
- Status bar indicator showing the validity/expiry of the certificate file in the active editor.

## [0.0.3] and earlier

- Initial certificate inspection, validation, chain analysis, conversion/keystore recipes (OpenSSL/keytool), remote TLS inspection, and folder-based expiry scanning.
