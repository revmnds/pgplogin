# Security Policy

## Reporting a Vulnerability

Please **do not** open a public issue for security problems.

Report privately via GitHub's [Security Advisories](https://github.com/revmnds/pgplogin/security/advisories/new) for this repository. If that is not available, email the maintainer at the address listed on the GitHub profile.

You can expect an initial response within 7 days. Coordinated disclosure is appreciated — give us a reasonable window to ship a fix before publishing details.

## Supported Versions

Only the latest minor version receives security fixes. Pin a version in `composer.json` (`"revmnds/pgplogin": "^0.1"`) and watch the repository for releases.

## Scope

In scope:
- Bypasses of the decryption-challenge flow (impersonation without holding the private key).
- Token-handling bugs (leak of cleartext, replay, weak randomness).
- Command-injection or path-traversal via inputs to the `gpg` subprocess.
- TTL / expiry bypasses.

Out of scope (documented limitations, see README):
- Phishing relay attacks — the protocol is not phishing-resistant by design.
- Loss of private key as account-recovery vector.
- Fingerprint reuse correlating accounts across services.
