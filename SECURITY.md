# Security policy

Shar has not reached GA. Do not treat the current 0.x line as independently
audited or deploy it as the only control protecting a high-value operation.
The no-policy-rejection invariant is intentional and is not a vulnerability:
a valid, unexpired proof must succeed regardless of client classification.

Please report suspected vulnerabilities privately through GitHub Security
Advisories for `shar-project/shar`. Include affected versions, reproduction
steps, impact, and any suggested mitigation. Do not include secrets, raw client
IP addresses, session bindings, or production tokens in a report. If private
advisories are unavailable, contact the repository security maintainers through
the address published on the project organization profile before disclosing.

Maintainers should acknowledge a complete report within three business days,
provide a status update within seven days, and coordinate disclosure after a
fix is available. Cryptographic key compromise requires immediate signing,
time-lock, trust-token, fallback-secret, and network-pseudonym key rotation;
storage credentials and affected verification nonces must also be treated as
compromised.

Every change is checked against npm and RustSec advisories. Both container
images publish a complete vulnerability report and fail before publication on
high or critical findings for which the vendor has released a fix. Unfixed
upstream findings require explicit review; a passing actionable gate is not a
claim that an image contains no advisory entries.

Supported versions will be listed here after the first GA release. Until then,
security fixes are made only on the latest 0.x revision.
