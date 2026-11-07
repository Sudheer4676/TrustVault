# Threat model

This is an initial working document. Update it to match the implementation and tests you actually complete.

| Threat | Intended defence | Verification needed |
|---|---|---|
| Unauthenticated document access | Require valid authentication on every protected endpoint | Test missing/invalid token |
| Cross-owner access | Check ownership or explicit grant on the server for every document operation | Test a second user attempting access |
| Revoked user reuses access | Re-check current grants on every request | Test access after revocation |
| Malicious upload | Validate size, extension and file signature; consider malware scanning | Test invalid and oversized files |
| Password disclosure | Store only salted password hashes | Inspect database and test login |
| Audit tampering | Restrict audit access and verify event-chain integrity | Modify an event and verify failure |

## Accepted risks / unfinished controls
The starter uses SQLite and local disk storage. It does not provide production-grade multi-instance storage, malware scanning, MFA, rate limiting, or an externally anchored immutable audit log. These must be addressed or clearly disclosed before production use.
