# Threat model

Shar prices automated consumption; it does not attest that a human or browser
exists. Attackers may run raw clients, reimplement the open algorithms, use
headless browsers, rent GPU farms, distribute solving, spoof timing, race
replays, forge tokens, or exhaust storage and network capacity.

Cryptographic signatures prevent quote alteration. The sequential time-lock
makes parallel hardware less useful for one proof, while independently repeated
rendering rounds create parallel work. Atomic nonce consumption limits every
issued token to one success. Work pricing makes repeated failure and sustained
velocity increasingly expensive without banning a client.

The protocol does not claim that CSS work is unforgeable attestation. Transport
rate/connection/body limits remain necessary against volumetric attacks. Key
factors, signing keys, proxy configuration, storage durability, host fallback
verifiers, and application sessions are trusted components.

Each reference standalone has a bounded aggregate in-flight admission gate.
Exhausting it yields a retryable operational error and does not create pressure
debt or a bot verdict. This protects application and state-store capacity but
does not replace a TLS proxy's connection, header, slow-client, and byte-rate
controls; an attacker can consume sockets before an HTTP request reaches Shar.

Canonical CBOR/COSE inputs are hostile even after the HTTP body limit. Decoders
cap nesting and item count before allocating recursive structures, reject
non-canonical lengths/order and invalid UTF-8, and do not touch replay,
pressure, or audit state until a signed claims envelope has decoded. The shared
malformed corpus is executed by both language cores.

Assurance mode trusts the configured reverse proxy, not a browser header. The
reference servers default it off, require an immediate trusted CIDR before
accepting the numeric header, and ignore browser-body or untrusted-peer values.
A compromised trusted proxy can raise future work prices to tier 32, but cannot
forge a proof, reject correctly completed signed work, lower an already issued
quote, or bypass replay protection. Operators must configure the proxy to
overwrite the header and keep raw behavioral inputs outside Shar.
