# Security Standards Policy

Cybersecurity features in this backend should include standards alignment metadata.

Current alignment targets:

```text
OWASP SAMM
CIS Controls v8
```

Important wording:

```text
alignedWith
```

Do not claim formal compliance or certification unless a real audit has been performed.

## Implementation Rule

Every cybersecurity check or alert should map to one or more controls in:

```text
src/config/securityStandards.js
```

When adding a new security check:

1. Add or reuse a control mapping in `securityStandards.js`.
2. Include `standards: getStandards("CONTROL_ID")` in the check result.
3. Include the same `standards` object in generated alerts.
4. Add the control id to the scan-level `buildStandardsSummary([...])`.
5. Update `API_DOCUMENTATION.md` with the new response field.

## Current Coverage

```text
DNS_RESOLUTION      -> OWASP SAMM Verification/Operations, CIS Control 12
HTTPS_REQUIRED     -> OWASP SAMM Verification/Implementation, CIS Control 4/16
TLS_CERTIFICATE    -> OWASP SAMM Verification/Operations, CIS Control 4
HTTPS_REDIRECT     -> OWASP SAMM Verification, CIS Control 4
SECURITY_HEADERS   -> OWASP SAMM Verification/Implementation, CIS Control 4/16
HTTP_AVAILABILITY  -> OWASP SAMM Operations, CIS Control 8
SECURITY_MONITORING -> OWASP SAMM Operations, CIS Control 8/16
```
