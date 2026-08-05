# Time-lock calibration

`npm run bench:timelock` measures the mandatory pure-JavaScript BigInt solver
against a retained public modulus from a generated 2048-bit RSW semiprime. Its
protected factors and Carmichael value are not retained or distributed. The
benchmark validates that the default 100,000-iteration/second lifetime
allowance is conservative on the current host and publishes atomically only
when the local minimum rate exceeds it.

This is local solver evidence, not a physical browser/device, energy, or
Tier-32 completion result. The artifact always leaves `ga_scope_pass` false.
