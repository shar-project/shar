//! Shar's blinded trust-credit primitive.
//!
//! This module deliberately stops at the RFC 9497 VOPRF transcript. The
//! issuance envelope, retention policy, and single-use storage live in the
//! server layer so that a privacy-preserving deployment can choose its own
//! transport without changing the cryptographic bytes. Rust and TypeScript
//! use the same `ristretto255-SHA512` suite, key derivation info, and input
//! framing.

use crate::{Cbor, decode_cbor, encode_cbor};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use voprf::{
    BlindedElement, EvaluationElement, Group, Proof, Ristretto255, VoprfClient, VoprfServer,
};

pub const TRUST_TOKEN_VERSION: &str = "trust-voprf-v1";
pub const TRUST_VOPRF_SUITE: &str = "ristretto255-SHA512";
pub const TRUST_KEY_INFO: &[u8] = b"shar/trust/v1";
pub const TRUST_OUTPUT_BYTES: usize = 64;
pub const TRUST_POINT_BYTES: usize = 32;
pub const TRUST_SCALAR_BYTES: usize = 32;
pub const TRUST_PROOF_BYTES: usize = 64;
pub const TRUST_CREDIT_PREFIX: &str = "shrtrust1_";

pub type TrustResult<T> = Result<T, TrustError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustError {
    KeyIdLength,
    SeedLength,
    InputLength,
    NonceLength,
    ChallengeDigestLength,
    TokenTypeLength,
    BlindLength,
    SecretKeyLength,
    PublicKeyLength,
    BlindedLength,
    EvaluatedLength,
    ProofLength,
    Token,
    Voprf(voprf::Error),
}

impl From<voprf::Error> for TrustError {
    fn from(error: voprf::Error) -> Self {
        Self::Voprf(error)
    }
}

/// An issuer key and its public identifier.
#[derive(Clone)]
pub struct TrustKeyPair {
    pub key_id: Vec<u8>,
    server: VoprfServer<Ristretto255>,
}

/// Client state that must be held privately until finalization.
pub struct TrustBlindState {
    client: VoprfClient<Ristretto255>,
    pub blinded: Vec<u8>,
}

pub struct TrustEvaluation {
    pub evaluated: Vec<u8>,
    pub proof: Vec<u8>,
}

pub struct TrustScope<'a> {
    pub tenant: &'a str,
    pub site_key: &'a str,
    pub action: &'a str,
    pub origin: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustCreditToken {
    pub key_id: Vec<u8>,
    pub challenge_nonce: Vec<u8>,
    pub challenge_digest: Vec<u8>,
    pub tenant: String,
    pub site_key: String,
    pub action: String,
    pub origin: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub output: Vec<u8>,
}

/// Coarse lifetime shared by many issuances, with at least 23/24 retention.
pub fn trust_credit_lifetime(now: u64, retention_seconds: u64) -> TrustResult<(u64, u64)> {
    if retention_seconds == 0 {
        return Err(TrustError::Token);
    }
    let bucket = 3_600_u64.min((retention_seconds / 24).max(1));
    let issued_at = now - (now % bucket);
    let expires_at = issued_at
        .checked_add(retention_seconds)
        .ok_or(TrustError::Token)?;
    Ok((issued_at, expires_at))
}

/// Public metadata digest bound into a credit's hidden VOPRF input.
pub fn trust_credit_challenge_digest(
    key_id_bytes: &[u8],
    scope: &TrustScope<'_>,
    issued_at: u64,
    expires_at: u64,
) -> TrustResult<Vec<u8>> {
    if expires_at < issued_at {
        return Err(TrustError::Token);
    }
    let mut hash = Sha256::new();
    hash.update(b"shar/trust/challenge/v1\0");
    hash.update(length_prefix(&key_id(key_id_bytes)?)?);
    for value in [scope.tenant, scope.site_key, scope.action, scope.origin] {
        hash.update(length_prefix(&trust_text(value, 512, TrustError::Token)?)?);
    }
    hash.update(issued_at.to_be_bytes());
    hash.update(expires_at.to_be_bytes());
    Ok(hash.finalize().to_vec())
}

/// Stable one-shot identity; re-encoding clear metadata cannot bypass replay.
pub fn trust_credit_replay_id(key_id_bytes: &[u8], output: &[u8]) -> TrustResult<Vec<u8>> {
    if output.len() != TRUST_OUTPUT_BYTES {
        return Err(TrustError::InputLength);
    }
    let mut hash = Sha256::new();
    hash.update(b"shar/trust/replay/v1\0");
    hash.update(length_prefix(&key_id(key_id_bytes)?)?);
    hash.update(output);
    Ok(hash.finalize().to_vec())
}

/// A small deterministic stream used when a caller supplies a random seed for
/// a proof. Production HTTP callers derive the seed from fresh response
/// nonces; tests can inject the same bytes in both language implementations.
pub struct TrustRng {
    seed: [u8; 32],
    counter: u64,
    buffer: Vec<u8>,
}

impl TrustRng {
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut value = [0_u8; 32];
        let digest = Sha256::digest(seed);
        value.copy_from_slice(&digest);
        Self {
            seed: value,
            counter: 0,
            buffer: Vec::new(),
        }
    }
}

impl RngCore for TrustRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        while self.buffer.len() < destination.len() {
            let mut hash = Sha256::new();
            hash.update(b"shar/trust/rng/v1\0");
            hash.update(self.seed);
            hash.update(self.counter.to_be_bytes());
            self.counter = self.counter.wrapping_add(1);
            self.buffer.extend(hash.finalize());
        }
        destination.copy_from_slice(&self.buffer[..destination.len()]);
        self.buffer.drain(..destination.len());
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for TrustRng {}

fn key_id(key_id: &[u8]) -> TrustResult<Vec<u8>> {
    if key_id.is_empty() || key_id.len() > 32 {
        return Err(TrustError::KeyIdLength);
    }
    Ok(key_id.to_vec())
}

fn seed(seed: &[u8]) -> TrustResult<&[u8]> {
    if seed.len() != 32 {
        return Err(TrustError::SeedLength);
    }
    Ok(seed)
}

fn input(input: &[u8]) -> TrustResult<&[u8]> {
    if input.is_empty() || input.len() > u16::MAX as usize {
        return Err(TrustError::InputLength);
    }
    Ok(input)
}

fn point(value: &[u8], error: TrustError) -> TrustResult<&[u8]> {
    if value.len() != TRUST_POINT_BYTES {
        return Err(error);
    }
    Ok(value)
}

fn proof(value: &[u8]) -> TrustResult<&[u8]> {
    if value.len() != TRUST_PROOF_BYTES {
        return Err(TrustError::ProofLength);
    }
    Ok(value)
}

impl TrustKeyPair {
    /// Derive a stable VOPRF key from a deployment seed and key identifier.
    pub fn from_seed(seed_bytes: &[u8], key_id_bytes: &[u8]) -> TrustResult<Self> {
        let server = VoprfServer::<Ristretto255>::new_from_seed(seed(seed_bytes)?, TRUST_KEY_INFO)?;
        Ok(Self {
            key_id: key_id(key_id_bytes)?,
            server,
        })
    }

    /// Restore a serialized server key while retaining its public identifier.
    pub fn from_serialized(key_id_bytes: &[u8], serialized_server: &[u8]) -> TrustResult<Self> {
        if serialized_server.len() != TRUST_SCALAR_BYTES + TRUST_POINT_BYTES {
            return Err(TrustError::SecretKeyLength);
        }
        Ok(Self {
            key_id: key_id(key_id_bytes)?,
            server: VoprfServer::<Ristretto255>::deserialize(serialized_server)?,
        })
    }

    pub fn serialized(&self) -> Vec<u8> {
        self.server.serialize().to_vec()
    }

    pub fn public_key(&self) -> Vec<u8> {
        <Ristretto255 as Group>::serialize_elem(self.server.get_public_key()).to_vec()
    }

    /// Derive a cryptographically distinct issuer key for one complete scope.
    pub fn for_scope(&self, scope: &TrustScope<'_>) -> TrustResult<Self> {
        let serialized = self.serialized();
        let mut hash = Sha256::new();
        hash.update(b"shar/trust/scoped-key/v1\0");
        hash.update(&serialized[..TRUST_SCALAR_BYTES]);
        for value in [scope.tenant, scope.site_key, scope.action, scope.origin] {
            hash.update(length_prefix(&trust_text(value, 512, TrustError::Token)?)?);
        }
        Self::from_seed(&hash.finalize(), &self.key_id)
    }

    /// Evaluate an already blinded request and create its verifiable proof.
    pub fn evaluate<R: RngCore + CryptoRng>(
        &self,
        blinded_bytes: &[u8],
        rng: &mut R,
    ) -> TrustResult<TrustEvaluation> {
        let blinded = BlindedElement::<Ristretto255>::deserialize(point(
            blinded_bytes,
            TrustError::BlindedLength,
        )?)?;
        let result = self.server.blind_evaluate(rng, &blinded);
        Ok(TrustEvaluation {
            evaluated: result.message.serialize().to_vec(),
            proof: result.proof.serialize().to_vec(),
        })
    }

    /// Compute a direct output for a server-known input (useful for vectors and
    /// non-blind internal checks). It matches client finalization exactly.
    pub fn evaluate_direct(&self, input_bytes: &[u8]) -> TrustResult<Vec<u8>> {
        let output = self.server.evaluate(input(input_bytes)?)?;
        if output.len() != TRUST_OUTPUT_BYTES {
            return Err(TrustError::InputLength);
        }
        Ok(output.to_vec())
    }

    pub fn evaluate_with_seed(
        &self,
        blinded_bytes: &[u8],
        random_seed: &[u8],
    ) -> TrustResult<TrustEvaluation> {
        let mut rng = TrustRng::from_seed(random_seed);
        self.evaluate(blinded_bytes, &mut rng)
    }
}

impl TrustBlindState {
    /// Blind an input before sending it to an issuer.
    pub fn blind<R: RngCore + CryptoRng>(input_bytes: &[u8], rng: &mut R) -> TrustResult<Self> {
        let result = VoprfClient::<Ristretto255>::blind(input(input_bytes)?, rng)?;
        Ok(Self {
            client: result.state,
            blinded: result.message.serialize().to_vec(),
        })
    }

    /// Return the finalized, proof-verified output.
    pub fn finalize(
        &self,
        input_bytes: &[u8],
        evaluation: &TrustEvaluation,
        public_key_bytes: &[u8],
    ) -> TrustResult<Vec<u8>> {
        let evaluation_element = EvaluationElement::<Ristretto255>::deserialize(point(
            &evaluation.evaluated,
            TrustError::EvaluatedLength,
        )?)?;
        let proof_element = Proof::<Ristretto255>::deserialize(proof(&evaluation.proof)?)?;
        let public_key = <Ristretto255 as Group>::deserialize_elem(point(
            public_key_bytes,
            TrustError::PublicKeyLength,
        )?)?;
        let output = self.client.finalize(
            input(input_bytes)?,
            &evaluation_element,
            &proof_element,
            public_key,
        )?;
        if output.len() != TRUST_OUTPUT_BYTES {
            return Err(TrustError::InputLength);
        }
        Ok(output.to_vec())
    }
}

fn length_prefix(value: &[u8]) -> TrustResult<Vec<u8>> {
    if value.len() > u16::MAX as usize {
        return Err(TrustError::InputLength);
    }
    let mut out = Vec::with_capacity(2 + value.len());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    Ok(out)
}

/// Build the domain-separated input used by Shar's credit envelope.
pub fn trust_input(
    token_type: &str,
    nonce: &[u8],
    challenge_digest: &[u8],
    key_id_bytes: &[u8],
) -> TrustResult<Vec<u8>> {
    let token_type_bytes = token_type.as_bytes();
    if token_type_bytes.is_empty() || token_type_bytes.len() > 128 {
        return Err(TrustError::TokenTypeLength);
    }
    if nonce.len() != 32 {
        return Err(TrustError::NonceLength);
    }
    if challenge_digest.len() != 32 {
        return Err(TrustError::ChallengeDigestLength);
    }
    let key_id_bytes = key_id(key_id_bytes)?;
    let fields = [
        length_prefix(token_type_bytes)?,
        length_prefix(nonce)?,
        length_prefix(challenge_digest)?,
        length_prefix(&key_id_bytes)?,
    ];
    let length = b"shar/trust/input/v1\0".len() + fields.iter().map(Vec::len).sum::<usize>();
    let mut out = Vec::with_capacity(length);
    out.extend_from_slice(b"shar/trust/input/v1\0");
    for field in fields {
        out.extend(field);
    }
    Ok(out)
}

fn trust_text(value: &str, maximum: usize, error: TrustError) -> TrustResult<Vec<u8>> {
    if value.is_empty()
        || value.len() > maximum
        || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(error);
    }
    Ok(value.as_bytes().to_vec())
}

pub fn trust_input_for_scope(
    token_type: &str,
    nonce: &[u8],
    challenge_digest: &[u8],
    key_id_bytes: &[u8],
    scope: &TrustScope<'_>,
) -> TrustResult<Vec<u8>> {
    let mut output = trust_input(token_type, nonce, challenge_digest, key_id_bytes)?;
    for value in [scope.tenant, scope.site_key, scope.action, scope.origin] {
        let bytes = trust_text(value, 512, TrustError::Token)?;
        output.extend(length_prefix(&bytes)?);
    }
    Ok(output)
}

pub fn encode_trust_credit_token(token: &TrustCreditToken) -> TrustResult<String> {
    let key_id = key_id(&token.key_id)?;
    if token.challenge_nonce.len() != 32 {
        return Err(TrustError::NonceLength);
    }
    if token.challenge_digest.len() != 32 {
        return Err(TrustError::ChallengeDigestLength);
    }
    if token.output.len() != TRUST_OUTPUT_BYTES {
        return Err(TrustError::InputLength);
    }
    if token.expires_at < token.issued_at {
        return Err(TrustError::Token);
    }
    let map = Cbor::Map(vec![
        (Cbor::Unsigned(0), Cbor::Text("trust-credit".into())),
        (Cbor::Unsigned(1), Cbor::Text("shar-v1".into())),
        (Cbor::Unsigned(2), Cbor::Bytes(key_id)),
        (
            Cbor::Unsigned(3),
            Cbor::Bytes(token.challenge_nonce.clone()),
        ),
        (
            Cbor::Unsigned(4),
            Cbor::Bytes(token.challenge_digest.clone()),
        ),
        (
            Cbor::Unsigned(5),
            Cbor::Text(
                String::from_utf8(trust_text(&token.tenant, 128, TrustError::Token)?)
                    .map_err(|_| TrustError::Token)?,
            ),
        ),
        (
            Cbor::Unsigned(6),
            Cbor::Text(
                String::from_utf8(trust_text(&token.site_key, 256, TrustError::Token)?)
                    .map_err(|_| TrustError::Token)?,
            ),
        ),
        (
            Cbor::Unsigned(7),
            Cbor::Text(
                String::from_utf8(trust_text(&token.action, 128, TrustError::Token)?)
                    .map_err(|_| TrustError::Token)?,
            ),
        ),
        (
            Cbor::Unsigned(8),
            Cbor::Text(
                String::from_utf8(trust_text(&token.origin, 512, TrustError::Token)?)
                    .map_err(|_| TrustError::Token)?,
            ),
        ),
        (Cbor::Unsigned(9), Cbor::Unsigned(token.issued_at)),
        (Cbor::Unsigned(10), Cbor::Unsigned(token.expires_at)),
        (Cbor::Unsigned(11), Cbor::Bytes(token.output.clone())),
        (Cbor::Unsigned(12), Cbor::Text(TRUST_VOPRF_SUITE.into())),
    ]);
    let encoded = encode_cbor(&map).map_err(|_| TrustError::Token)?;
    Ok(format!(
        "{TRUST_CREDIT_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(encoded)
    ))
}

fn token_map_value(map: &[(Cbor, Cbor)], key: u64) -> Option<&Cbor> {
    map.iter()
        .find_map(|(candidate, value)| (candidate == &Cbor::Unsigned(key)).then_some(value))
}

fn token_string(map: &[(Cbor, Cbor)], key: u64, maximum: usize) -> TrustResult<String> {
    let Cbor::Text(value) = token_map_value(map, key).ok_or(TrustError::Token)? else {
        return Err(TrustError::Token);
    };
    trust_text(value, maximum, TrustError::Token)?;
    Ok(value.clone())
}

fn token_bytes(map: &[(Cbor, Cbor)], key: u64, length: usize) -> TrustResult<Vec<u8>> {
    let Cbor::Bytes(value) = token_map_value(map, key).ok_or(TrustError::Token)? else {
        return Err(TrustError::Token);
    };
    if value.len() != length {
        return Err(TrustError::Token);
    }
    Ok(value.clone())
}

fn token_number(map: &[(Cbor, Cbor)], key: u64) -> TrustResult<u64> {
    match token_map_value(map, key).ok_or(TrustError::Token)? {
        Cbor::Unsigned(value) => Ok(*value),
        _ => Err(TrustError::Token),
    }
}

pub fn decode_trust_credit_token(token: &str) -> TrustResult<TrustCreditToken> {
    let encoded = token
        .strip_prefix(TRUST_CREDIT_PREFIX)
        .ok_or(TrustError::Token)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| TrustError::Token)?;
    let Cbor::Map(map) = decode_cbor(&bytes).map_err(|_| TrustError::Token)? else {
        return Err(TrustError::Token);
    };
    if token_string(&map, 0, 64)? != "trust-credit"
        || token_string(&map, 1, 64)? != "shar-v1"
        || token_string(&map, 12, 64)? != TRUST_VOPRF_SUITE
    {
        return Err(TrustError::Token);
    }
    let issued_at = token_number(&map, 9)?;
    let expires_at = token_number(&map, 10)?;
    if expires_at < issued_at {
        return Err(TrustError::Token);
    }
    let key = match token_map_value(&map, 2).ok_or(TrustError::Token)? {
        Cbor::Bytes(value) => key_id(value)?,
        _ => return Err(TrustError::Token),
    };
    Ok(TrustCreditToken {
        key_id: key,
        challenge_nonce: token_bytes(&map, 3, 32)?,
        challenge_digest: token_bytes(&map, 4, 32)?,
        tenant: token_string(&map, 5, 128)?,
        site_key: token_string(&map, 6, 256)?,
        action: token_string(&map, 7, 128)?,
        origin: token_string(&map, 8, 512)?,
        issued_at,
        expires_at,
        output: token_bytes(&map, 11, TRUST_OUTPUT_BYTES)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    #[derive(Clone, Debug)]
    struct FixedRng {
        byte: u8,
    }

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            u32::from_be_bytes([self.byte; 4])
        }

        fn next_u64(&mut self) -> u64 {
            u64::from_be_bytes([self.byte; 8])
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(self.byte);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for FixedRng {}

    #[derive(Clone, Debug)]
    struct StreamRng {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl StreamRng {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, offset: 0 }
        }
    }

    impl RngCore for StreamRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0_u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_be_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0_u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_be_bytes(bytes)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                *byte = self.bytes.get(self.offset).copied().unwrap_or(0);
                self.offset += 1;
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for StreamRng {}

    fn vector_bytes(value: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(value).unwrap()
    }

    fn scalar_rng(value: &str) -> StreamRng {
        let mut bytes = vector_bytes(value);
        bytes.resize(64, 0);
        StreamRng::new(bytes)
    }

    #[test]
    fn blind_round_matches_direct_evaluation() {
        let seed = [7_u8; 32];
        let key_id = [1_u8, 2, 3, 4];
        let input = b"trust-vector-input";
        let key = TrustKeyPair::from_seed(&seed, &key_id).unwrap();
        let mut client_rng = FixedRng { byte: 9 };
        let blind = TrustBlindState::blind(input, &mut client_rng).unwrap();
        let mut server_rng = FixedRng { byte: 11 };
        let evaluation = key.evaluate(&blind.blinded, &mut server_rng).unwrap();
        let output = blind
            .finalize(input, &evaluation, &key.public_key())
            .unwrap();
        assert_eq!(output, key.evaluate_direct(input).unwrap());
        assert_eq!(output.len(), TRUST_OUTPUT_BYTES);
    }

    #[test]
    fn scoped_issuer_keys_prevent_cross_scope_credit_laundering() {
        let root = TrustKeyPair::from_seed(&[17; 32], &[7, 7, 7, 1]).unwrap();
        let first = root
            .for_scope(&TrustScope {
                tenant: "tenant-a",
                site_key: "site-a",
                action: "signup",
                origin: "https://app.example",
            })
            .unwrap();
        let second = root
            .for_scope(&TrustScope {
                tenant: "tenant-a",
                site_key: "site-a",
                action: "checkout",
                origin: "https://app.example",
            })
            .unwrap();
        let input = b"hidden-client-input-for-the-second-scope";
        let mut client_rng = FixedRng { byte: 9 };
        let blind = TrustBlindState::blind(input, &mut client_rng).unwrap();
        let mut server_rng = FixedRng { byte: 11 };
        let evaluated_under_first = first.evaluate(&blind.blinded, &mut server_rng).unwrap();
        let output_under_first = blind
            .finalize(input, &evaluated_under_first, &first.public_key())
            .unwrap();
        assert_ne!(output_under_first, second.evaluate_direct(input).unwrap());
        assert_ne!(first.public_key(), second.public_key());
    }

    #[test]
    fn trust_input_is_unambiguous_and_bounded() {
        let value = trust_input("credit", &[1; 32], &[2; 32], &[3; 4]).unwrap();
        assert_eq!(&value[..20], b"shar/trust/input/v1\0");
        assert!(matches!(
            trust_input("", &[1; 32], &[2; 32], &[3; 4]),
            Err(TrustError::TokenTypeLength)
        ));
        assert!(matches!(
            trust_input("credit", &[1; 31], &[2; 32], &[3; 4]),
            Err(TrustError::NonceLength)
        ));
    }

    #[test]
    fn trust_transcript_matches_typescript_vector() {
        let seed = (0_u8..32).collect::<Vec<_>>();
        let key_id = [1_u8, 2, 3, 4];
        let input = b"trust-vector-input";
        let key = TrustKeyPair::from_seed(&seed, &key_id).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&key.serialized()[..TRUST_SCALAR_BYTES]),
            "Ga7lO5tQUVaYTGJb1E70fsZySkw9HVcLGqGcWvZZfgo"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(key.public_key()),
            "Wrtk9NcX4ZSrQG30-r5Jz_m0OkDgIwxZss2i3Bgm-nc"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(
                key.for_scope(&TrustScope {
                    tenant: "tenant-a",
                    site_key: "site-a",
                    action: "signup",
                    origin: "https://app.example",
                })
                .unwrap()
                .public_key()
            ),
            "xiI4whkQKB-TtqJ1ITeanmQQ-kNTfZz01NPhXInixQE"
        );

        let mut client_rng = scalar_rng("NujC38hSqmVS4PLy8oD5cRFGjderasJM3hZfCkbTPw0");
        let blind = TrustBlindState::blind(input, &mut client_rng).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&blind.blinded),
            "XNunxeL3DH5h0HzhWycTfWYLZjctOYVaaalGmw37T2k"
        );
        let mut server_rng = scalar_rng("uOwMiyhPWhM1KEfoE2b_2_iqrJW113sIZTh0fo5Xoww");
        let evaluation = key.evaluate(&blind.blinded, &mut server_rng).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&evaluation.evaluated),
            "TP-h5lEnLTwThB08yXmLudFe_598OSt-dQRrDAUFtwE"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&evaluation.proof),
            "5Ym-yzdp5qoj4TyTN9XPuU-jK5ym3yUcN2iblPQO-wfal5235q_wVSj1ePG5w1AkAbpeHuHeSwMfdHpC3tBBDw"
        );
        let output = blind
            .finalize(input, &evaluation, &key.public_key())
            .unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(output),
            "4tyr6QsIkk491-JXgiJxghPGwspgdiyeOrzr7w93_Gi7PgAn10ynuX-MKuqfHx8SWUrAjOEN3M8Xt0PgDeEYrA"
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .encode(trust_input("credit", &[0x21; 32], &[0x42; 32], &key_id).unwrap()),
            "c2hhci90cnVzdC9pbnB1dC92MQAABmNyZWRpdAAgISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEAIEJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCAAQBAgME"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(
                trust_input_for_scope(
                    "credit",
                    &seed,
                    &[0x42; 32],
                    &key_id,
                    &TrustScope {
                        tenant: "tenant-a",
                        site_key: "site-a",
                        action: "signup",
                        origin: "https://app.example",
                    },
                )
                .unwrap(),
            ),
            "c2hhci90cnVzdC9pbnB1dC92MQAABmNyZWRpdAAgAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8AIEJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCAAQBAgMEAAh0ZW5hbnQtYQAGc2l0ZS1hAAZzaWdudXAAE2h0dHBzOi8vYXBwLmV4YW1wbGU"
        );
        let scope = TrustScope {
            tenant: "tenant-a",
            site_key: "site-a",
            action: "signup",
            origin: "https://app.example",
        };
        assert_eq!(
            URL_SAFE_NO_PAD.encode(
                trust_credit_challenge_digest(&key_id, &scope, 1_800_000_000, 1_800_086_400)
                    .unwrap()
            ),
            "ML4XC8oLbukj-_NQ0GfYhzk57iv73797xcxH-0OsrzE"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(trust_credit_replay_id(&key_id, &[0x55; 64]).unwrap()),
            "8_LAj66CJVhUCTd3yPMp5tzTgEM3vWM7zNqOiZTa14g"
        );
        assert_eq!(
            trust_credit_lifetime(1_800_001_234, 86_400).unwrap(),
            (1_800_000_000, 1_800_086_400)
        );
    }
}
