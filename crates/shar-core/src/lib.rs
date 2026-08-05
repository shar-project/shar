#![forbid(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(test)]
use ed25519_dalek::Signer;
use ed25519_dalek::{
    Signature, SigningKey, Verifier, VerifyingKey,
    hazmat::{ExpandedSecretKey, raw_sign_byupdate},
};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use trust::{TrustKeyPair, TrustScope};

pub const TOKEN_PREFIX: &str = "shr1_";
pub const MAX_RENDER_ROUNDS: u32 = 65_536;
pub const DEFAULT_RENDER_TRIANGLES: u32 = 256;
pub const DEFAULT_RENDER_SAMPLES: u32 = 4_096;
pub const DEFAULT_RENDER_PREDICATES: u32 = DEFAULT_RENDER_TRIANGLES * DEFAULT_RENDER_SAMPLES;
pub const MAX_CBOR_DEPTH: usize = 64;
pub const MAX_CBOR_ITEMS: usize = 4_096;
pub const MAX_STORED_FALLBACK_LIFETIME_SECONDS: u64 = 300;

pub mod trust;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cbor {
    Null,
    Bool(bool),
    Unsigned(u64),
    Negative(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
}

pub fn encode_cbor(value: &Cbor) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    encode_into(value, &mut out)?;
    Ok(out)
}

fn encode_into(value: &Cbor, out: &mut Vec<u8>) -> Result<(), &'static str> {
    match value {
        Cbor::Null => out.push(0xf6),
        Cbor::Bool(value) => out.push(if *value { 0xf5 } else { 0xf4 }),
        Cbor::Unsigned(value) => head(0, *value, out),
        Cbor::Negative(value) if *value < 0 => head(1, (-1_i128 - i128::from(*value)) as u64, out),
        Cbor::Negative(_) => return Err("invalid negative"),
        Cbor::Bytes(bytes) => {
            head(
                2,
                bytes.len().try_into().map_err(|_| "length overflow")?,
                out,
            );
            out.extend(bytes);
        }
        Cbor::Text(text) => {
            head(
                3,
                text.len().try_into().map_err(|_| "length overflow")?,
                out,
            );
            out.extend(text.as_bytes());
        }
        Cbor::Array(items) => {
            head(
                4,
                items.len().try_into().map_err(|_| "length overflow")?,
                out,
            );
            for item in items {
                encode_into(item, out)?;
            }
        }
        Cbor::Map(entries) => {
            let mut encoded = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                encoded.push((encode_cbor(key)?, encode_cbor(value)?));
            }
            encoded.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
            for pair in encoded.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err("duplicate map key");
                }
            }
            head(
                5,
                encoded.len().try_into().map_err(|_| "length overflow")?,
                out,
            );
            for (key, value) in encoded {
                out.extend(key);
                out.extend(value);
            }
        }
    }
    Ok(())
}

fn head(major: u8, value: u64, out: &mut Vec<u8>) {
    if value < 24 {
        out.push((major << 5) | value as u8);
    } else if u8::try_from(value).is_ok() {
        out.extend([(major << 5) | 24, value as u8]);
    } else if u16::try_from(value).is_ok() {
        out.push((major << 5) | 25);
        out.extend((value as u16).to_be_bytes());
    } else if u32::try_from(value).is_ok() {
        out.push((major << 5) | 26);
        out.extend((value as u32).to_be_bytes());
    } else {
        out.push((major << 5) | 27);
        out.extend(value.to_be_bytes());
    }
}

pub fn decode_cbor(bytes: &[u8]) -> Result<Cbor, &'static str> {
    fn take(
        bytes: &[u8],
        offset: &mut usize,
        depth: usize,
        item_count: &mut usize,
    ) -> Result<Cbor, &'static str> {
        if depth > MAX_CBOR_DEPTH {
            return Err("cbor depth exceeded");
        }
        *item_count = item_count.checked_add(1).ok_or("cbor items exceeded")?;
        if *item_count > MAX_CBOR_ITEMS {
            return Err("cbor items exceeded");
        }
        let first = *bytes.get(*offset).ok_or("truncated cbor")?;
        *offset += 1;
        let major = first >> 5;
        let info = first & 31;
        if major == 7 {
            return match info {
                20 => Ok(Cbor::Bool(false)),
                21 => Ok(Cbor::Bool(true)),
                22 => Ok(Cbor::Null),
                _ => Err("unsupported simple"),
            };
        }
        let length = read_length(bytes, offset, info)?;
        match major {
            0 => Ok(Cbor::Unsigned(length)),
            1 if length <= i64::MAX as u64 => Ok(Cbor::Negative(-1 - length as i64)),
            1 => Err("negative overflow"),
            2 | 3 => {
                let size: usize = length.try_into().map_err(|_| "length overflow")?;
                let end = offset.checked_add(size).ok_or("length overflow")?;
                let part = bytes.get(*offset..end).ok_or("truncated cbor")?;
                *offset = end;
                if major == 2 {
                    Ok(Cbor::Bytes(part.to_vec()))
                } else {
                    Ok(Cbor::Text(
                        std::str::from_utf8(part)
                            .map_err(|_| "invalid utf8")?
                            .to_owned(),
                    ))
                }
            }
            4 => {
                let mut items = Vec::new();
                for _ in 0..length {
                    items.push(take(bytes, offset, depth + 1, item_count)?);
                }
                Ok(Cbor::Array(items))
            }
            5 => {
                let mut entries = Vec::new();
                let mut previous: Option<Vec<u8>> = None;
                for _ in 0..length {
                    let start = *offset;
                    let key = take(bytes, offset, depth + 1, item_count)?;
                    let encoded = bytes[start..*offset].to_vec();
                    if let Some(old) = &previous
                        && (old.len(), old) >= (encoded.len(), &encoded)
                    {
                        return Err("noncanonical map");
                    }
                    previous = Some(encoded);
                    let value = take(bytes, offset, depth + 1, item_count)?;
                    entries.push((key, value));
                }
                Ok(Cbor::Map(entries))
            }
            _ => Err("unsupported cbor major"),
        }
    }
    fn read_length(bytes: &[u8], offset: &mut usize, info: u8) -> Result<u64, &'static str> {
        if info < 24 {
            return Ok(u64::from(info));
        }
        let width = match info {
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err("invalid cbor length"),
        };
        let end = offset.checked_add(width).ok_or("length overflow")?;
        let part = bytes.get(*offset..end).ok_or("truncated cbor")?;
        *offset = end;
        let mut padded = [0_u8; 8];
        padded[8 - width..].copy_from_slice(part);
        let value = u64::from_be_bytes(padded);
        if (width == 1 && value < 24)
            || (width == 2 && value <= u8::MAX.into())
            || (width == 4 && value <= u16::MAX.into())
            || (width == 8 && value <= u32::MAX.into())
        {
            return Err("noncanonical integer");
        }
        Ok(value)
    }
    let mut offset = 0;
    let mut items = 0;
    let value = take(bytes, &mut offset, 0, &mut items)?;
    if offset != bytes.len() {
        return Err("trailing cbor");
    }
    Ok(value)
}

#[derive(Clone)]
pub struct SigningMaterial {
    pub key_id: Vec<u8>,
    pub seed: [u8; 32],
}

#[derive(Clone)]
pub struct VerificationMaterial {
    pub key_id: Vec<u8>,
    pub public_key: [u8; 32],
}

pub fn public_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

pub fn daily_network_pseudonym(
    secret: &[u8],
    ip_bytes: &[u8],
    unix_seconds: u64,
) -> Result<[u8; 16], &'static str> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| "invalid hmac key")?;
    mac.update(b"shar/network/v1\0");
    mac.update((unix_seconds / 86_400).to_string().as_bytes());
    mac.update(&[0]);
    mac.update(ip_bytes);
    let digest = mac.finalize().into_bytes();
    let mut output = [0; 16];
    output.copy_from_slice(&digest[..16]);
    Ok(output)
}

pub const SITE_VERIFY_SECRET_PREFIX: &str = "shrs1_";

pub fn derive_site_verify_secret(
    master: &[u8; 32],
    tenant: &str,
    site_key: &str,
) -> Result<String, &'static str> {
    validate_site_scope(tenant, 128)?;
    validate_site_scope(site_key, 256)?;
    let tenant_length: u16 = tenant.len().try_into().map_err(|_| "invalid tenant")?;
    let site_length: u16 = site_key.len().try_into().map_err(|_| "invalid site key")?;
    let mut body = Vec::with_capacity(5 + tenant.len() + site_key.len());
    body.push(1);
    body.extend(tenant_length.to_be_bytes());
    body.extend(tenant.as_bytes());
    body.extend(site_length.to_be_bytes());
    body.extend(site_key.as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(master).map_err(|_| "invalid hmac key")?;
    mac.update(b"shar/siteverify/v1\0");
    mac.update(&body);
    body.extend(mac.finalize().into_bytes());
    Ok(format!(
        "{SITE_VERIFY_SECRET_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(body)
    ))
}

pub fn verify_site_verify_secret(
    master: &[u8; 32],
    secret: &str,
) -> Result<Option<(String, String)>, &'static str> {
    let Some(encoded) = secret.strip_prefix(SITE_VERIFY_SECRET_PREFIX) else {
        return Ok(None);
    };
    let decoded = match URL_SAFE_NO_PAD.decode(encoded) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if decoded.len() < 39 || decoded[0] != 1 {
        return Ok(None);
    }
    let tenant_length = usize::from(u16::from_be_bytes([decoded[1], decoded[2]]));
    let site_length_offset = 3_usize.saturating_add(tenant_length);
    if site_length_offset + 2 > decoded.len() - 32 {
        return Ok(None);
    }
    let site_length = usize::from(u16::from_be_bytes([
        decoded[site_length_offset],
        decoded[site_length_offset + 1],
    ]));
    let body_length = site_length_offset
        .saturating_add(2)
        .saturating_add(site_length);
    if body_length + 32 != decoded.len() {
        return Ok(None);
    }
    let (body, supplied_mac) = decoded.split_at(body_length);
    let mut mac = Hmac::<Sha256>::new_from_slice(master).map_err(|_| "invalid hmac key")?;
    mac.update(b"shar/siteverify/v1\0");
    mac.update(body);
    if mac.verify_slice(supplied_mac).is_err() {
        return Ok(None);
    }
    let tenant = match std::str::from_utf8(&body[3..site_length_offset]) {
        Ok(value) => value.to_owned(),
        Err(_) => return Ok(None),
    };
    let site_key = match std::str::from_utf8(&body[site_length_offset + 2..]) {
        Ok(value) => value.to_owned(),
        Err(_) => return Ok(None),
    };
    if validate_site_scope(&tenant, 128).is_err() || validate_site_scope(&site_key, 256).is_err() {
        return Ok(None);
    }
    Ok(Some((tenant, site_key)))
}

fn validate_site_scope(value: &str, maximum: usize) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > maximum
        || value.chars().any(|character| character.is_control())
    {
        return Err("invalid site scope");
    }
    Ok(())
}

pub fn cose_sign(payload: &[u8], material: &SigningMaterial) -> Result<String, &'static str> {
    CoseSigner::new(material)?.sign(payload)
}

struct CoseSigner {
    protected: Vec<u8>,
    signature_prefix: Vec<u8>,
    expanded: ExpandedSecretKey,
    verifying: VerifyingKey,
}

impl CoseSigner {
    fn new(material: &SigningMaterial) -> Result<Self, &'static str> {
        let key = SigningKey::from_bytes(&material.seed);
        let protected = encode_cbor(&Cbor::Map(vec![
            (Cbor::Unsigned(1), Cbor::Negative(-8)),
            (Cbor::Unsigned(4), Cbor::Bytes(material.key_id.clone())),
        ]))?;
        let mut signature_prefix = Vec::with_capacity(15 + protected.len());
        head(4, 4, &mut signature_prefix);
        head(3, 10, &mut signature_prefix);
        signature_prefix.extend_from_slice(b"Signature1");
        head(2, protected.len() as u64, &mut signature_prefix);
        signature_prefix.extend_from_slice(&protected);
        head(2, 0, &mut signature_prefix);
        Ok(Self {
            protected,
            signature_prefix,
            expanded: ExpandedSecretKey::from(&material.seed),
            verifying: key.verifying_key(),
        })
    }

    fn sign(&self, payload: &[u8]) -> Result<String, &'static str> {
        // This is the fixed COSE Sig_structure
        // ["Signature1", protected, external_aad, payload]. Encoding it
        // directly avoids building a generic CBOR tree and cloning the full
        // challenge payload before every Ed25519 operation.
        let (payload_head, payload_head_length) = fixed_head(2, payload.len() as u64);
        // The verifying key and expanded secret are derived together from the
        // same validated seed. Keeping the expansion on the long-lived signer
        // avoids hashing an unchanged secret for every ordinary Ed25519
        // signature. The update closure supplies the same fixed Sig_structure
        // bytes twice, as required by Ed25519, without allocating and copying
        // a contiguous message for every quote.
        let signature = raw_sign_byupdate::<Sha512, _>(
            &self.expanded,
            |digest| {
                digest.update(&self.signature_prefix);
                digest.update(&payload_head[..payload_head_length]);
                digest.update(payload);
                Ok(())
            },
            &self.verifying,
        )
        .map_err(|_| "signature failed")?
        .to_bytes();
        // The fixed COSE_Sign1 shape is [protected, {}, payload, signature].
        let mut sign1 = Vec::with_capacity(8 + self.protected.len() + payload.len() + 64);
        head(4, 4, &mut sign1);
        head(2, self.protected.len() as u64, &mut sign1);
        sign1.extend_from_slice(&self.protected);
        head(5, 0, &mut sign1);
        head(2, payload.len() as u64, &mut sign1);
        sign1.extend_from_slice(payload);
        head(2, signature.len() as u64, &mut sign1);
        sign1.extend_from_slice(&signature);
        let mut token = String::with_capacity(TOKEN_PREFIX.len() + sign1.len().div_ceil(3) * 4);
        token.push_str(TOKEN_PREFIX);
        URL_SAFE_NO_PAD.encode_string(sign1, &mut token);
        Ok(token)
    }
}

fn fixed_head(major: u8, value: u64) -> ([u8; 9], usize) {
    let mut encoded = [0_u8; 9];
    let length = if value < 24 {
        encoded[0] = (major << 5) | value as u8;
        1
    } else if value <= u8::MAX.into() {
        encoded[0] = (major << 5) | 24;
        encoded[1] = value as u8;
        2
    } else if value <= u16::MAX.into() {
        encoded[0] = (major << 5) | 25;
        encoded[1..3].copy_from_slice(&(value as u16).to_be_bytes());
        3
    } else if value <= u32::MAX.into() {
        encoded[0] = (major << 5) | 26;
        encoded[1..5].copy_from_slice(&(value as u32).to_be_bytes());
        5
    } else {
        encoded[0] = (major << 5) | 27;
        encoded[1..9].copy_from_slice(&value.to_be_bytes());
        9
    };
    (encoded, length)
}

pub fn cose_verify(token: &str, keys: &[VerificationMaterial]) -> Result<Vec<u8>, &'static str> {
    let encoded = token.strip_prefix(TOKEN_PREFIX).ok_or("token prefix")?;
    let decoded = decode_cbor(
        &URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "invalid base64url")?,
    )?;
    let Cbor::Array(parts) = decoded else {
        return Err("cose shape");
    };
    if parts.len() != 4 {
        return Err("cose shape");
    }
    let Cbor::Bytes(protected) = &parts[0] else {
        return Err("cose shape");
    };
    let Cbor::Map(unprotected) = &parts[1] else {
        return Err("cose shape");
    };
    if !unprotected.is_empty() {
        return Err("cose shape");
    }
    let Cbor::Bytes(payload) = &parts[2] else {
        return Err("cose shape");
    };
    let Cbor::Bytes(signature) = &parts[3] else {
        return Err("cose shape");
    };
    let signature: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| "cose signature")?;
    let headers = decode_cbor(protected)?;
    let Cbor::Map(headers) = headers else {
        return Err("cose headers");
    };
    let algorithm = map_get(&headers, 1).ok_or("cose headers")?;
    if algorithm != &Cbor::Negative(-8) {
        return Err("cose algorithm");
    }
    let Cbor::Bytes(kid) = map_get(&headers, 4).ok_or("cose headers")? else {
        return Err("cose kid");
    };
    let key = keys
        .iter()
        .find(|key| key.key_id == *kid)
        .ok_or("unknown key")?;
    let structure = encode_cbor(&Cbor::Array(vec![
        Cbor::Text("Signature1".into()),
        Cbor::Bytes(protected.clone()),
        Cbor::Bytes(vec![]),
        Cbor::Bytes(payload.clone()),
    ]))?;
    VerifyingKey::from_bytes(&key.public_key)
        .map_err(|_| "invalid key")?
        .verify(&structure, &Signature::from_bytes(&signature))
        .map_err(|_| "bad signature")?;
    Ok(payload.clone())
}

fn map_get(entries: &[(Cbor, Cbor)], key: u64) -> Option<&Cbor> {
    entries.iter().find_map(|(k, v)| {
        if k == &Cbor::Unsigned(key) {
            Some(v)
        } else {
            None
        }
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PressureInput {
    pub base_tier: u8,
    pub velocity_tier: u8,
    pub outstanding_tier: u8,
    pub network_tier: u8,
    pub failure_debt: u8,
    pub assurance_debt: u8,
    pub trust_credits: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkPolicy {
    pub version: String,
    pub base_iterations: u64,
    pub base_render_rounds: u32,
    pub quiet_window_seconds: u64,
    pub base_lifetime_seconds: u64,
    pub iteration_allowance: u64,
    pub round_allowance_seconds: u64,
    pub max_lifetime_seconds: u64,
}

pub fn default_work_policy() -> WorkPolicy {
    WorkPolicy {
        version: "policy-v1".into(),
        base_iterations: 1_024,
        base_render_rounds: 1,
        quiet_window_seconds: 60,
        base_lifetime_seconds: 120,
        iteration_allowance: 100_000,
        round_allowance_seconds: 15,
        max_lifetime_seconds: 63_072_000,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkQuote {
    pub version: String,
    pub tier: u8,
    pub time_lock_iterations: String,
    pub render_rounds: u32,
    pub issued_at: u64,
    pub expires_at: u64,
}

pub fn price_work(
    input: &PressureInput,
    policy: &WorkPolicy,
    now: u64,
) -> Result<WorkQuote, &'static str> {
    if policy.base_iterations == 0
        || policy.base_render_rounds == 0
        || policy.iteration_allowance == 0
        || policy.quiet_window_seconds == 0
        || policy.base_lifetime_seconds == 0
        || policy.max_lifetime_seconds == 0
    {
        return Err("invalid policy");
    }
    let debt = u16::from(input.failure_debt)
        .saturating_add(input.assurance_debt.into())
        .saturating_sub(input.trust_credits.into())
        .min(32);
    let tier = u16::from(input.base_tier)
        .saturating_add(input.velocity_tier.into())
        .saturating_add(input.outstanding_tier.into())
        .saturating_add(input.network_tier.min(4).into())
        .saturating_add(debt)
        .min(32) as u8;
    let iterations = policy
        .base_iterations
        .checked_mul(1_u64 << tier)
        .ok_or("work overflow")?;
    let rounds = policy
        .base_render_rounds
        .checked_mul(1_u32 << tier.min(8))
        .ok_or("work overflow")?;
    if rounds > MAX_RENDER_ROUNDS {
        return Err("work overflow");
    }
    let additional_iterations = iterations
        .checked_sub(policy.base_iterations)
        .ok_or("work overflow")?;
    let iteration_seconds = additional_iterations / policy.iteration_allowance
        + u64::from(additional_iterations % policy.iteration_allowance != 0);
    let additional_rounds = rounds
        .checked_sub(policy.base_render_rounds)
        .ok_or("work overflow")?;
    let round_seconds = u64::from(additional_rounds)
        .checked_mul(policy.round_allowance_seconds)
        .ok_or("work overflow")?;
    let lifetime = policy
        .base_lifetime_seconds
        .checked_add(iteration_seconds)
        .and_then(|value| value.checked_add(round_seconds))
        .ok_or("work overflow")?
        .min(policy.max_lifetime_seconds);
    Ok(WorkQuote {
        version: "work-price-v1".into(),
        tier,
        time_lock_iterations: iterations.to_string(),
        render_rounds: rounds,
        issued_at: now,
        expires_at: now.checked_add(lifetime).ok_or("time overflow")?,
    })
}

pub fn decay_tier(
    value: u8,
    last_activity: u64,
    now: u64,
    quiet_window: u64,
) -> Result<u8, &'static str> {
    if quiet_window == 0 || now < last_activity {
        return Err("invalid decay input");
    }
    Ok(value.saturating_sub(((now - last_activity) / quiet_window).min(u64::from(u8::MAX)) as u8))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Triangle {
    pub id: u32,
    pub z: u32,
    pub ax: i32,
    pub ay: i32,
    pub bx: i32,
    pub by: i32,
    pub cx: i32,
    pub cy: i32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriangleProgram {
    pub version: String,
    pub triangles: Vec<Triangle>,
    pub samples: Vec<(i32, i32)>,
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().expect("slice"))
}
fn next(state: &mut u32) -> u32 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    x
}
fn word(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalCssTranscript {
    pub version: String,
    pub chain_width: u32,
    pub layout_height: u32,
    pub grid_first_width: u32,
    pub grid_second_width: u32,
    pub flex_first_width: u32,
    pub flex_second_width: u32,
    pub intrinsic_width: u32,
    pub query_branch: u32,
    pub style_branch: u32,
    pub nested_branch: u32,
    pub transform_x: u32,
    pub transform_y: u32,
    pub vertical_writing: u32,
    pub hit_id: u32,
    pub topology_depth: u32,
}

impl CanonicalCssTranscript {
    fn words(&self) -> [u32; 15] {
        [
            self.chain_width,
            self.layout_height,
            self.grid_first_width,
            self.grid_second_width,
            self.flex_first_width,
            self.flex_second_width,
            self.intrinsic_width,
            self.query_branch,
            self.style_branch,
            self.nested_branch,
            self.transform_x,
            self.transform_y,
            self.vertical_writing,
            self.hit_id,
            self.topology_depth,
        ]
    }
}

pub fn derive_canonical_css_transcript(
    seed: &[u8],
) -> Result<CanonicalCssTranscript, &'static str> {
    if seed.len() != 32 {
        return Err("render seed");
    }
    let chain_width = 64 + u32::from(seed[0] % 64);
    let grid_first_width = 16 + u32::from(seed[2] % 32);
    let flex_first_width = 4 + u32::from(seed[3]) % (grid_first_width - 8);
    Ok(CanonicalCssTranscript {
        version: "css-transcript-v1".into(),
        chain_width,
        layout_height: 48 + u32::from(seed[1] % 48),
        grid_first_width,
        grid_second_width: chain_width - grid_first_width,
        flex_first_width,
        flex_second_width: grid_first_width - flex_first_width,
        intrinsic_width: 8 + u32::from(seed[11] % 24),
        query_branch: 12 + u32::from(seed[4] % 32),
        style_branch: 12 + u32::from(seed[5] % 32),
        nested_branch: 1,
        transform_x: 4 + u32::from(seed[6] % 24),
        transform_y: 4 + u32::from(seed[7] % 24),
        vertical_writing: u32::from(seed[8] & 1),
        hit_id: 1 + u32::from(seed[9] & 1),
        topology_depth: 3 + u32::from(seed[10] % 6),
    })
}

fn encode_css_transcript(seed: &[u8]) -> Result<Vec<u8>, &'static str> {
    let words = derive_canonical_css_transcript(seed)?.words();
    let mut encoded = Vec::with_capacity(words.len() * 4);
    for value in words {
        encoded.extend_from_slice(&word(value));
    }
    Ok(encoded)
}

pub fn create_triangle_program(
    seed: &[u8],
    triangle_count: u32,
    sample_count: u32,
) -> Result<TriangleProgram, &'static str> {
    if triangle_count == 0 || triangle_count > 512 || sample_count == 0 || sample_count > 4096 {
        return Err("render bounds");
    }
    const LIMIT: i32 = 1 << 20;
    const GUARD: i32 = 64;
    let material = hash(&[b"shar/render-v1/program\0", seed]);
    let mut state = u32le(&material, 0);
    if state == 0 {
        state = 0x6d2b79f5
    }
    let mut triangles = Vec::new();
    for id in 1..=triangle_count {
        let cx = GUARD + (next(&mut state) % (LIMIT - 2 * GUARD) as u32) as i32;
        let cy = GUARD + (next(&mut state) % (LIMIT - 2 * GUARD) as u32) as i32;
        let rx = 4096 + (next(&mut state) % (LIMIT as u32 >> 2)) as i32;
        let ry = 4096 + (next(&mut state) % (LIMIT as u32 >> 2)) as i32;
        let ax = (cx - rx).max(GUARD);
        let ay = (cy + ry).min(LIMIT - GUARD);
        let bx = (cx + rx).min(LIMIT - GUARD);
        let by = (cy + (ry >> 1)).min(LIMIT - GUARD);
        let tx = (cx + (next(&mut state) % (rx as u32 + 1)) as i32 - (rx >> 1))
            .clamp(GUARD, LIMIT - GUARD);
        let ty = (cy - ry).max(GUARD);
        triangles.push(Triangle {
            id,
            z: next(&mut state),
            ax,
            ay,
            bx,
            by,
            cx: tx,
            cy: ty,
        });
    }
    let mut samples = Vec::new();
    for _ in 0..sample_count {
        samples.push((
            GUARD + (next(&mut state) % (LIMIT - 2 * GUARD) as u32) as i32,
            GUARD + (next(&mut state) % (LIMIT - 2 * GUARD) as u32) as i32,
        ));
    }
    Ok(TriangleProgram {
        version: "render-v1".into(),
        triangles,
        samples,
    })
}
fn edge(ax: i32, ay: i32, bx: i32, by: i32, px: i32, py: i32) -> i64 {
    i64::from(px - ax) * i64::from(by - ay) - i64::from(py - ay) * i64::from(bx - ax)
}
fn contains(t: &Triangle, x: i32, y: i32) -> bool {
    let a = edge(t.ax, t.ay, t.bx, t.by, x, y);
    let b = edge(t.bx, t.by, t.cx, t.cy, x, y);
    let c = edge(t.cx, t.cy, t.ax, t.ay, x, y);
    (a >= 0 && b >= 0 && c >= 0) || (a <= 0 && b <= 0 && c <= 0)
}
pub fn select_triangles(p: &TriangleProgram) -> Vec<(u32, u32)> {
    p.samples
        .iter()
        .map(|(x, y)| {
            p.triangles
                .iter()
                .filter(|triangle| contains(triangle, *x, *y))
                .max_by_key(|triangle| (triangle.z, triangle.id))
                .map_or((0, 0), |triangle| (triangle.id, triangle.z))
        })
        .collect()
}
pub fn reduce_triangle_selections(selections: &[(u32, u32)]) -> Result<[u8; 32], &'static str> {
    if selections.is_empty() || selections.len() > 4096 {
        return Err("render bounds");
    }
    let mut h = Sha256::new();
    h.update(b"shar/render-v1/output\0");
    for (i, (id, z)) in selections.iter().enumerate() {
        h.update(word(i as u32));
        h.update(word(*id));
        h.update(word(*z));
    }
    Ok(h.finalize().into())
}
pub fn evaluate_triangle_program(p: &TriangleProgram) -> [u8; 32] {
    reduce_triangle_selections(&select_triangles(p)).expect("program bounds validated")
}
pub fn solve_rendering(
    seed: &[u8],
    rounds: u32,
    triangles: u32,
    samples: u32,
) -> Result<[u8; 32], &'static str> {
    if rounds == 0 || rounds > MAX_RENDER_ROUNDS {
        return Err("render bounds");
    }
    let transcript = encode_css_transcript(seed)?;
    let program_root = hash(&[b"shar/render-v1/css-program\0", seed, &transcript]);
    let mut final_hash = Sha256::new();
    final_hash.update(b"shar/render-v1/final\0");
    for round in 0..rounds {
        let round_seed = hash(&[b"shar/render-v1/round\0", &program_root, &word(round)]);
        final_hash.update(evaluate_triangle_program(&create_triangle_program(
            &round_seed,
            triangles,
            samples,
        )?));
    }
    Ok(final_hash.finalize().into())
}

#[derive(Clone)]
pub struct TimeLockKey {
    pub id: String,
    pub modulus: BigUint,
    pub lambda: BigUint,
}
const MAX_VALIDATED_MODULUS_BITS: u64 = 4096;
const TIME_LOCK_VALIDATION_MARGIN_BITS: u64 = 64;
const TIME_LOCK_VALIDATION_OFFSETS: [u64; 3] = [0, 1, 31];

/// Checks that protected RSW trapdoor material agrees with actual sequential
/// squaring before the key can be used to issue work. This establishes the
/// operational property Shar needs; any valid multiple of the group exponent
/// is accepted even if it is not the minimally reduced Carmichael value.
pub fn validate_time_lock_key(key: &TimeLockKey) -> bool {
    if key.id.is_empty()
        || key.id.len() > 64
        || key.modulus <= BigUint::from(3_u8)
        || &key.modulus % BigUint::from(2_u8) == BigUint::from(0_u8)
        || key.lambda <= BigUint::from(1_u8)
        || key.lambda >= key.modulus
        || key.modulus.bits() > MAX_VALIDATED_MODULUS_BITS
    {
        return false;
    }
    let starts = [
        BigUint::from(2_u8),
        BigUint::from(65_537_u32),
        BigUint::from(4_294_967_291_u64),
    ];
    for (index, start) in starts.into_iter().enumerate() {
        let mut base = start % &key.modulus;
        if base <= BigUint::from(1_u8) {
            base = BigUint::from(2_u8);
        }
        while !coprime_timelock_candidate(&base, &key.modulus) {
            base += BigUint::from(1_u8);
            if base >= key.modulus {
                base = BigUint::from(2_u8);
            }
        }
        let iterations = key.modulus.bits()
            + TIME_LOCK_VALIDATION_MARGIN_BITS
            + TIME_LOCK_VALIDATION_OFFSETS[index];
        let sequential = solve_timelock(&base, iterations, &key.modulus);
        let exponent = BigUint::from(2_u8).modpow(&BigUint::from(iterations), &key.lambda);
        if base.modpow(&exponent, &key.modulus) != sequential {
            return false;
        }
    }
    true
}
pub fn derive_timelock_input(nonce: &[u8], modulus: &BigUint) -> BigUint {
    assert!(modulus > &BigUint::from(3_u8), "invalid modulus");
    for counter in 0..=u32::MAX {
        let digest = BigUint::from_bytes_be(&hash(&[
            b"shar/rsw-v1/input\0",
            nonce,
            &counter.to_be_bytes(),
        ]));
        // A production RSW modulus is 2048 bits while the digest is 256 bits,
        // so avoid an allocation-only `% modulus` in the overwhelmingly
        // common case. Small deterministic test moduli still take the exact
        // reduction required by the protocol.
        let candidate = if &digest >= modulus {
            digest % modulus
        } else {
            digest
        };
        if coprime_timelock_candidate(&candidate, modulus) {
            return candidate;
        }
    }
    unreachable!("u32 counter space exhausted")
}
fn coprime_timelock_candidate(candidate: &BigUint, modulus: &BigUint) -> bool {
    if candidate.bits() <= 1 {
        return false;
    }
    if candidate.trailing_zeros().is_some_and(|zeros| zeros > 0)
        && modulus.trailing_zeros().is_some_and(|zeros| zeros > 0)
    {
        return false;
    }
    // Reduce the 2048-bit modulus once, then use binary GCD over two values no
    // wider than the 256-bit digest. The RSW modulus is odd, so powers of two
    // can be removed independently without changing whether the gcd is one.
    let mut a = candidate.clone();
    let mut b = modulus % candidate;
    if b.bits() == 0 {
        return a.bits() == 1;
    }
    if let Some(zeros) = a.trailing_zeros() {
        a >>= zeros as usize;
    }
    if let Some(zeros) = b.trailing_zeros() {
        b >>= zeros as usize;
    }
    loop {
        match a.cmp(&b) {
            std::cmp::Ordering::Equal => return a.bits() == 1,
            std::cmp::Ordering::Greater => {
                a -= &b;
                if let Some(zeros) = a.trailing_zeros() {
                    a >>= zeros as usize;
                }
            }
            std::cmp::Ordering::Less => {
                b -= &a;
                if let Some(zeros) = b.trailing_zeros() {
                    b >>= zeros as usize;
                }
            }
        }
    }
}
pub fn solve_timelock(input: &BigUint, iterations: u64, modulus: &BigUint) -> BigUint {
    let mut value = input.clone();
    for _ in 0..iterations {
        value = (&value * &value) % modulus;
    }
    value
}
pub fn verify_timelock(
    key: &TimeLockKey,
    input: &BigUint,
    iterations: u64,
    output: &BigUint,
) -> bool {
    if iterations == 0 {
        return false;
    }
    let exponent = BigUint::from(2_u8).modpow(&BigUint::from(iterations), &key.lambda);
    input.modpow(&exponent, &key.modulus) == *output
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub tenant: String,
    pub site_key: String,
    pub action: String,
    pub origin: String,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub session_binding: Option<String>,
    #[serde(default)]
    pub network_pseudonym: Option<String>,
    #[serde(default)]
    pub assurance_tier: Option<u8>,
    #[serde(default)]
    pub trust_token: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderingProofPlan {
    pub version: String,
    pub seed: String,
    pub rounds: u32,
    pub triangles: u32,
    pub samples: u32,
}
pub type RenderingPlan = RenderingProofPlan;

pub fn css_transcript_commitment(plan: &RenderingProofPlan) -> Result<String, &'static str> {
    if plan.version != "render-v1"
        || plan.rounds == 0
        || plan.rounds > MAX_RENDER_ROUNDS
        || plan.triangles == 0
        || plan.triangles > 512
        || plan.samples == 0
        || plan.samples > 4096
    {
        return Err("render bounds");
    }
    let seed = URL_SAFE_NO_PAD
        .decode(&plan.seed)
        .map_err(|_| "render seed")?;
    if seed.len() != 32 {
        return Err("render seed");
    }
    let transcript = encode_css_transcript(&seed)?;
    Ok(URL_SAFE_NO_PAD.encode(hash(&[
        b"shar/css-transcript-v1\0",
        &seed,
        &word(plan.rounds),
        &word(plan.triangles),
        &word(plan.samples),
        &transcript,
    ])))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeLockPlan {
    pub version: String,
    pub modulus_id: String,
    pub modulus: String,
    pub input: String,
    pub iterations: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub token: String,
    pub quote: WorkQuote,
    pub render: RenderingPlan,
    pub time_lock: TimeLockPlan,
    pub presence: PresencePlan,
    pub fallback: FallbackPlan,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustTokenPlan>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode")]
pub enum TrustTokenPlan {
    #[serde(rename = "disabled")]
    Disabled,
    #[serde(rename = "voprf-v1")]
    Voprf {
        suite: String,
        token_type: String,
        key_id: String,
        public_key: String,
        challenge_digest: String,
        issued_at: u64,
        expires_at: u64,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum PresencePlan {
    None,
    Host,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackPlan {
    pub available: bool,
    pub methods: Vec<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RenderingBackend {
    Webgpu,
    Webgl2,
    Css,
}
impl RenderingBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Webgpu => "webgpu",
            Self::Webgl2 => "webgl2",
            Self::Css => "css",
        }
    }
    fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "webgpu" => Ok(Self::Webgpu),
            "webgl2" => Ok(Self::Webgl2),
            "css" => Ok(Self::Css),
            _ => Err("rendering backend"),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CssTranscriptCommitment {
    pub version: String,
    pub digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeLockProof {
    pub output: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderingProof {
    pub digest: String,
    pub backend: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_css_commitment"
    )]
    pub css_commitment: Option<CssTranscriptCommitment>,
}

fn deserialize_present_css_commitment<'de, D>(
    deserializer: D,
) -> Result<Option<CssTranscriptCommitment>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<CssTranscriptCommitment>::deserialize(deserializer)?
        .map(Some)
        .ok_or_else(|| serde::de::Error::custom("css_commitment cannot be null"))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemRequest {
    pub token: String,
    pub time_lock: TimeLockProof,
    pub rendering: RenderingProof,
    #[serde(default)]
    pub trust_blinded: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkReceipt {
    pub version: String,
    pub tier: u8,
    pub time_lock_iterations: String,
    pub render_rounds: u32,
    pub rendering_backend: String,
    pub completed_at: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemResponse {
    pub token: String,
    pub expires_at: u64,
    pub receipt: WorkReceipt,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_evaluation: Option<TrustEvaluationEnvelope>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEvaluationEnvelope {
    pub version: String,
    pub suite: String,
    pub key_id: String,
    pub evaluated: String,
    pub proof: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteVerifyRequest {
    pub token: String,
    pub tenant: Option<String>,
    pub site_key: Option<String>,
    pub action: Option<String>,
    pub origin: Option<String>,
    pub region: Option<String>,
    pub session_binding: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteVerifyResponse {
    pub success: bool,
    pub tenant: String,
    pub site_key: String,
    pub action: String,
    pub origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub receipt: WorkReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackCompletionRequest {
    pub tenant: String,
    pub site_key: String,
    pub action: String,
    pub origin: String,
    #[serde(default)]
    pub region: Option<String>,
    pub method: String,
    pub assertion_id: String,
    #[serde(default)]
    pub session_binding: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FallbackCompletionResponse {
    pub success: bool,
    pub tenant: String,
    pub site_key: String,
    pub action: String,
    pub origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub verification_method: String,
    pub method: String,
}

/// A short-lived host result written only after an alternative verification
/// method succeeds. The host store is read idempotently; Shar consumes its own
/// replay nonce only after every binding is verified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredFallbackAssertion {
    pub version: String,
    pub tenant: String,
    pub site_key: String,
    pub action: String,
    pub origin: String,
    #[serde(default)]
    pub region: Option<String>,
    pub method: String,
    pub assertion_id: String,
    #[serde(default)]
    pub session_binding: Option<String>,
    pub verified_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharError {
    pub status: u16,
    pub code: &'static str,
    pub retryable: bool,
    pub next_action: &'static str,
    pub retry_after: Option<u64>,
}
impl SharError {
    fn new(status: u16, code: &'static str, retryable: bool, next: &'static str) -> Self {
        Self {
            status,
            code,
            retryable,
            next_action: next,
            retry_after: None,
        }
    }
    fn retry_after(mut self, seconds: u64) -> Self {
        self.retry_after = Some(seconds);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreError;

/// Privacy-filtered operational metadata.  It intentionally has no origin,
/// session binding, network pseudonym, address, user-agent, or device field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub version: String,
    pub kind: String,
    pub occurred_at: u64,
    pub tenant: String,
    pub site_key: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

pub trait AuditStore: Send + Sync {
    fn record(&self, event: &AuditEvent) -> Result<(), StoreError>;
    fn record_batch(&self, events: &[AuditEvent]) -> Result<(), StoreError> {
        for event in events {
            self.record(event)?;
        }
        Ok(())
    }
    fn list(
        &self,
        tenant: &str,
        site_key: &str,
        action: &str,
        limit: u32,
    ) -> Result<Vec<AuditEvent>, StoreError> {
        let _ = (tenant, site_key, action, limit);
        Err(StoreError)
    }
}

pub trait NonceStore: Send + Sync {
    /// Read-only dependency probe. Implementations must not consume state.
    fn health(&self) -> Result<(), StoreError> {
        Ok(())
    }
    fn consume(&self, namespace: &str, nonce: &[u8], expires_at: u64) -> Result<bool, StoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    Invalid,
    Replay,
    Expired,
}

pub trait PressureStore: Send + Sync {
    /// Read-only dependency probe. Implementations must not mutate pressure.
    fn health(&self) -> Result<(), StoreError> {
        Ok(())
    }
    fn read(
        &self,
        input: &ChallengeRequest,
        now: u64,
        quiet_window_seconds: u64,
    ) -> Result<PressureInput, StoreError>;
    /// Atomically prices and reserves one outstanding quote. Implementations
    /// must not expose the observed pressure before reserving the quote; doing
    /// so would let concurrent issuers all purchase the same lower tier.
    fn price_and_record(
        &self,
        input: &ChallengeRequest,
        policy: &WorkPolicy,
        now: u64,
    ) -> Result<WorkQuote, StoreError>;
    fn record_issued(
        &self,
        input: &ChallengeRequest,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError>;
    fn record_success(
        &self,
        input: &ChallengeRequest,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError>;
    fn record_failure(
        &self,
        input: &ChallengeRequest,
        kind: FailureKind,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError>;
    fn record_trust(&self, _input: &ChallengeRequest, _now: u64) -> Result<(), StoreError> {
        Ok(())
    }
}

pub trait ConfigStore: Send + Sync {
    /// Read-only dependency probe used by the standalone readiness endpoint.
    fn health(&self) -> Result<(), StoreError> {
        Ok(())
    }
    fn policy(&self, tenant: &str, site_key: &str, action: &str) -> Result<WorkPolicy, StoreError>;
    fn set_policy(
        &self,
        _tenant: &str,
        _site_key: &str,
        _action: &str,
        _policy: &WorkPolicy,
    ) -> Result<(), StoreError> {
        Err(StoreError)
    }
}

/// Trusted host-side assurance signals. Implementations can only contribute a
/// future work tier; they are never consulted while validating completed work.
pub trait SignalProvider: Send + Sync {
    fn health(&self) -> Result<(), StoreError> {
        Ok(())
    }
    fn assurance_tier(&self, request: &ChallengeRequest) -> Result<u8, StoreError>;
}

/// Host-provided alternative verification. Shar treats the result as fallback
/// completion, never as a proof-of-work classification.
pub trait FallbackVerifier: Send + Sync {
    fn health(&self) -> Result<(), StoreError> {
        Ok(())
    }
    fn verify(&self, method: &str, payload: &serde_json::Value) -> Result<bool, StoreError>;
}

pub trait FallbackAssertionStore: Send + Sync {
    fn health(&self) -> Result<(), StoreError> {
        Ok(())
    }

    /// Return an immutable record without consuming it.
    fn find(&self, assertion_id: &str) -> Result<Option<StoredFallbackAssertion>, StoreError>;
}

/// Exact-binding verifier for host-owned stored fallback assertions.
pub struct StoredFallbackVerifier {
    store: Arc<dyn FallbackAssertionStore>,
    clock: Arc<dyn Fn() -> Result<u64, StoreError> + Send + Sync>,
}

impl StoredFallbackVerifier {
    pub fn new(store: Arc<dyn FallbackAssertionStore>) -> Self {
        Self::with_clock(store, || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .map_err(|_| StoreError)
        })
    }

    pub fn with_clock<F>(store: Arc<dyn FallbackAssertionStore>, clock: F) -> Self
    where
        F: Fn() -> Result<u64, StoreError> + Send + Sync + 'static,
    {
        Self {
            store,
            clock: Arc::new(clock),
        }
    }
}

impl FallbackVerifier for StoredFallbackVerifier {
    fn health(&self) -> Result<(), StoreError> {
        self.store.health()
    }

    fn verify(&self, method: &str, payload: &serde_json::Value) -> Result<bool, StoreError> {
        let request: FallbackCompletionRequest =
            serde_json::from_value(payload.clone()).map_err(|_| StoreError)?;
        if request.method != method {
            return Ok(false);
        }
        let Some(assertion) = self.store.find(&request.assertion_id)? else {
            return Ok(false);
        };
        if assertion.version != "fallback-assertion-v1"
            || assertion.expires_at < assertion.verified_at
        {
            return Err(StoreError);
        }
        let now = (self.clock)()?;
        if assertion.verified_at > now
            || assertion.expires_at < now
            || assertion.expires_at - assertion.verified_at > MAX_STORED_FALLBACK_LIFETIME_SECONDS
        {
            return Ok(false);
        }
        Ok(assertion.tenant == request.tenant
            && assertion.site_key == request.site_key
            && assertion.action == request.action
            && assertion.origin == request.origin
            && assertion.region == request.region
            && assertion.method == request.method
            && assertion.assertion_id == request.assertion_id
            && assertion.session_binding == request.session_binding)
    }
}

pub struct StaticConfigStore(pub WorkPolicy);
impl ConfigStore for StaticConfigStore {
    fn policy(
        &self,
        _tenant: &str,
        _site_key: &str,
        _action: &str,
    ) -> Result<WorkPolicy, StoreError> {
        Ok(self.0.clone())
    }
}

#[derive(Clone)]
struct PressureState {
    pressure: PressureInput,
    last_activity: u64,
    window_start: u64,
    request_count: u64,
    outstanding: Vec<u64>,
}

pub struct MemoryPressureStore {
    values: Mutex<HashMap<String, PressureState>>,
}

impl MemoryPressureStore {
    pub fn new(quiet_window_seconds: u64) -> Result<Self, StoreError> {
        if quiet_window_seconds == 0 {
            return Err(StoreError);
        }
        Ok(Self {
            values: Mutex::new(HashMap::new()),
        })
    }
    fn base_key(input: &ChallengeRequest) -> String {
        format!("{}\0{}\0{}", input.tenant, input.site_key, input.action)
    }
    fn action_key(input: &ChallengeRequest) -> String {
        format!("action\0{}", Self::base_key(input))
    }
    fn client_key(input: &ChallengeRequest) -> String {
        format!(
            "client\0{}\0{}",
            Self::base_key(input),
            input.session_binding.as_deref().unwrap_or("")
        )
    }
    fn network_key(input: &ChallengeRequest) -> Option<String> {
        input
            .network_pseudonym
            .as_ref()
            .map(|network| format!("network\0{}\0{network}", Self::base_key(input)))
    }
    fn failure_key(input: &ChallengeRequest) -> String {
        if input.session_binding.is_some() || input.network_pseudonym.is_none() {
            Self::client_key(input)
        } else {
            Self::network_key(input).expect("network pseudonym present")
        }
    }
    fn initial(now: u64) -> PressureState {
        PressureState {
            pressure: PressureInput {
                base_tier: 0,
                velocity_tier: 0,
                outstanding_tier: 0,
                network_tier: 0,
                failure_debt: 0,
                assurance_debt: 0,
                trust_credits: 0,
            },
            last_activity: now,
            window_start: now,
            request_count: 0,
            outstanding: Vec::new(),
        }
    }

    fn read_locked(
        values: &mut HashMap<String, PressureState>,
        input: &ChallengeRequest,
        now: u64,
        quiet_window_seconds: u64,
    ) -> PressureInput {
        let (velocity_tier, outstanding_tier) = {
            let state = values
                .entry(Self::action_key(input))
                .or_insert_with(|| Self::initial(now));
            // Signed expiries are inclusive: an outstanding quote at
            // `now == expiry` is still live for this pricing read.
            state.outstanding.retain(|expiry| *expiry >= now);
            roll_pressure_window(state, now, quiet_window_seconds);
            state.request_count = state.request_count.saturating_add(1);
            state.last_activity = now;
            (
                logarithmic_tier(state.request_count),
                logarithmic_tier(state.outstanding.len() as u64 + 1),
            )
        };
        let (base_tier, failure_debt, assurance_debt, trust_credits) = {
            let state = values
                .entry(Self::client_key(input))
                .or_insert_with(|| Self::initial(now));
            decay_pressure_state(state, now, quiet_window_seconds);
            let assurance = state
                .pressure
                .assurance_debt
                .max(input.assurance_tier.unwrap_or(0));
            if input.session_binding.is_some() {
                state.pressure.assurance_debt = assurance;
            }
            state.last_activity = now;
            (
                state.pressure.base_tier,
                state.pressure.failure_debt,
                assurance,
                state.pressure.trust_credits,
            )
        };
        let network_tier = if let Some(key) = Self::network_key(input) {
            let state = values.entry(key).or_insert_with(|| Self::initial(now));
            decay_pressure_state(state, now, quiet_window_seconds);
            roll_pressure_window(state, now, quiet_window_seconds);
            state.request_count = state.request_count.saturating_add(1);
            let tier = state
                .pressure
                .network_tier
                .max(state.pressure.failure_debt)
                .max(logarithmic_tier(state.request_count));
            state.last_activity = now;
            tier
        } else {
            0
        };
        PressureInput {
            base_tier,
            velocity_tier,
            outstanding_tier,
            network_tier,
            failure_debt,
            assurance_debt,
            trust_credits,
        }
    }
}

fn logarithmic_tier(count: u64) -> u8 {
    if count <= 1 {
        0
    } else {
        (u64::BITS - (count - 1).leading_zeros()).min(32) as u8
    }
}

impl PressureStore for MemoryPressureStore {
    fn read(
        &self,
        input: &ChallengeRequest,
        now: u64,
        quiet_window_seconds: u64,
    ) -> Result<PressureInput, StoreError> {
        if quiet_window_seconds == 0 {
            return Err(StoreError);
        }
        let mut values = self.values.lock().map_err(|_| StoreError)?;
        Ok(Self::read_locked(
            &mut values,
            input,
            now,
            quiet_window_seconds,
        ))
    }
    fn price_and_record(
        &self,
        input: &ChallengeRequest,
        policy: &WorkPolicy,
        now: u64,
    ) -> Result<WorkQuote, StoreError> {
        if policy.quiet_window_seconds == 0 {
            return Err(StoreError);
        }
        let mut values = self.values.lock().map_err(|_| StoreError)?;
        let pressure = Self::read_locked(&mut values, input, now, policy.quiet_window_seconds);
        let quote = price_work(&pressure, policy, now).map_err(|_| StoreError)?;
        let state = values
            .entry(Self::action_key(input))
            .or_insert_with(|| Self::initial(now));
        state.outstanding.push(quote.expires_at);
        state.last_activity = now;
        Ok(quote)
    }
    fn record_issued(
        &self,
        input: &ChallengeRequest,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError> {
        let key = Self::action_key(input);
        let mut values = self.values.lock().map_err(|_| StoreError)?;
        let state = values.entry(key).or_insert_with(|| Self::initial(now));
        state.outstanding.retain(|expiry| *expiry >= now);
        state.outstanding.push(expires_at);
        state.last_activity = now;
        Ok(())
    }
    fn record_success(
        &self,
        input: &ChallengeRequest,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError> {
        let key = Self::failure_key(input);
        let mut values = self.values.lock().map_err(|_| StoreError)?;
        let state = values.entry(key).or_insert_with(|| Self::initial(now));
        state.pressure.failure_debt = state.pressure.failure_debt.saturating_sub(1);
        state.last_activity = now;
        let action = values
            .entry(Self::action_key(input))
            .or_insert_with(|| Self::initial(now));
        if let Some(index) = action
            .outstanding
            .iter()
            .position(|candidate| *candidate == expires_at)
        {
            action.outstanding.remove(index);
        }
        Ok(())
    }
    fn record_failure(
        &self,
        input: &ChallengeRequest,
        kind: FailureKind,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError> {
        let key = Self::failure_key(input);
        let mut values = self.values.lock().map_err(|_| StoreError)?;
        let state = values.entry(key).or_insert_with(|| Self::initial(now));
        state.pressure.failure_debt = state.pressure.failure_debt.saturating_add(1).min(32);
        state.last_activity = now;
        if kind == FailureKind::Expired {
            let action = values
                .entry(Self::action_key(input))
                .or_insert_with(|| Self::initial(now));
            if let Some(index) = action
                .outstanding
                .iter()
                .position(|candidate| *candidate == expires_at)
            {
                action.outstanding.remove(index);
            }
        }
        Ok(())
    }

    fn record_trust(&self, input: &ChallengeRequest, now: u64) -> Result<(), StoreError> {
        // Trust credits never reduce the rotating network-pressure bucket.
        let key = Self::client_key(input);
        let mut values = self.values.lock().map_err(|_| StoreError)?;
        let state = values.entry(key).or_insert_with(|| Self::initial(now));
        if state.pressure.failure_debt > 0 {
            state.pressure.failure_debt -= 1;
        } else {
            state.pressure.assurance_debt = state.pressure.assurance_debt.saturating_sub(1);
        }
        state.last_activity = now;
        Ok(())
    }
}

fn decay_pressure_state(state: &mut PressureState, now: u64, quiet_window_seconds: u64) {
    let decay = now.saturating_sub(state.last_activity) / quiet_window_seconds;
    let decay = decay.min(u64::from(u8::MAX)) as u8;
    state.pressure.failure_debt = state.pressure.failure_debt.saturating_sub(decay);
    state.pressure.assurance_debt = state.pressure.assurance_debt.saturating_sub(decay);
}

fn roll_pressure_window(state: &mut PressureState, now: u64, quiet_window_seconds: u64) {
    if now.saturating_sub(state.window_start) >= quiet_window_seconds {
        state.window_start = now;
        state.request_count = 0;
    }
}

pub struct MemoryNonceStore {
    used: Mutex<HashMap<(String, Vec<u8>), u64>>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl Default for MemoryNonceStore {
    fn default() -> Self {
        Self::with_clock(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs())
        })
    }
}

impl MemoryNonceStore {
    pub fn with_clock<F>(clock: F) -> Self
    where
        F: Fn() -> u64 + Send + Sync + 'static,
    {
        Self {
            used: Mutex::new(HashMap::new()),
            clock: Arc::new(clock),
        }
    }
}

impl NonceStore for MemoryNonceStore {
    fn consume(&self, namespace: &str, nonce: &[u8], expires_at: u64) -> Result<bool, StoreError> {
        let now = (self.clock)();
        let mut used = self.used.lock().map_err(|_| StoreError)?;
        used.retain(|_, expiry| *expiry >= now);
        let key = (namespace.to_owned(), nonce.to_vec());
        if used.contains_key(&key) {
            return Ok(false);
        }
        used.insert(key, expires_at);
        Ok(true)
    }
}

#[derive(Clone)]
struct ChallengeClaims {
    tenant: String,
    site: String,
    action: String,
    origin: String,
    region: Option<String>,
    iat: u64,
    exp: u64,
    policy: String,
    tier: u8,
    iterations: u64,
    rounds: u32,
    nonce: [u8; 16],
    seed: [u8; 32],
    modulus: String,
    session: Option<String>,
    network_pseudonym: Option<String>,
    triangles: u32,
    samples: u32,
    trust_key_id: Option<Vec<u8>>,
}
#[derive(Clone)]
struct VerificationClaims {
    tenant: String,
    site: String,
    action: String,
    origin: String,
    region: Option<String>,
    iat: u64,
    exp: u64,
    nonce: Vec<u8>,
    session: Option<String>,
    receipt: WorkReceipt,
}

pub struct Engine {
    signer: CoseSigner,
    keys: Vec<VerificationMaterial>,
    pub time_lock: TimeLockKey,
    time_lock_modulus: String,
    time_locks: Vec<TimeLockKey>,
    pub policy: WorkPolicy,
    nonces: Arc<dyn NonceStore>,
    pressure: Arc<dyn PressureStore>,
    config: Arc<dyn ConfigStore>,
    audit: Option<Arc<dyn AuditStore>>,
    pub triangles: u32,
    pub samples: u32,
    trust_keys: Vec<TrustKeyPair>,
    trust_retention_seconds: u64,
    presence: PresencePlan,
    fallback: FallbackPlan,
    signals: Option<Arc<dyn SignalProvider>>,
    fallback_verifier: Option<Arc<dyn FallbackVerifier>>,
}
impl Engine {
    pub fn new(signing: SigningMaterial, time_lock: TimeLockKey, policy: WorkPolicy) -> Self {
        let pressure = Arc::new(
            MemoryPressureStore::new(policy.quiet_window_seconds).expect("validated policy"),
        );
        let config = Arc::new(StaticConfigStore(policy.clone()));
        Self::with_stores(
            signing,
            time_lock,
            policy,
            Arc::new(MemoryNonceStore::default()),
            pressure,
            config,
        )
    }

    /// Probe only the state required to issue and redeem work. Audit storage
    /// remains best-effort and therefore cannot make the service unready.
    pub fn ready(&self) -> Result<(), SharError> {
        self.config
            .health()
            .and_then(|_| self.pressure.health())
            .and_then(|_| self.nonces.health())
            .and_then(|_| {
                self.signals
                    .as_ref()
                    .map_or(Ok(()), |provider| provider.health())
            })
            .and_then(|_| {
                self.fallback_verifier
                    .as_ref()
                    .map_or(Ok(()), |provider| provider.health())
            })
            .map_err(|_| SharError::new(503, "readiness_unavailable", true, "retry").retry_after(1))
    }

    pub fn admin_policy(
        &self,
        tenant: &str,
        site_key: &str,
        action: &str,
    ) -> Result<WorkPolicy, SharError> {
        validate_scope(tenant, site_key, action)?;
        self.config.policy(tenant, site_key, action).map_err(|_| {
            SharError::new(503, "config_store_unavailable", true, "retry").retry_after(1)
        })
    }

    pub fn set_admin_policy(
        &self,
        tenant: &str,
        site_key: &str,
        action: &str,
        policy: &WorkPolicy,
    ) -> Result<(), SharError> {
        validate_scope(tenant, site_key, action)?;
        let maximum = PressureInput {
            base_tier: 32,
            velocity_tier: 0,
            outstanding_tier: 0,
            network_tier: 0,
            failure_debt: 0,
            assurance_debt: 0,
            trust_credits: 0,
        };
        price_work(&maximum, policy, 0)
            .map_err(|_| SharError::new(400, "invalid_policy", false, "none"))?;
        if policy.version.is_empty()
            || policy.version.len() > 128
            || policy
                .version
                .bytes()
                .any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(SharError::new(400, "invalid_policy", false, "none"));
        }
        self.config
            .set_policy(tenant, site_key, action, policy)
            .map_err(|_| {
                SharError::new(503, "config_store_unavailable", true, "retry").retry_after(1)
            })
    }

    pub fn admin_audit(
        &self,
        tenant: &str,
        site_key: &str,
        action: &str,
        limit: u32,
    ) -> Result<Vec<AuditEvent>, SharError> {
        validate_scope(tenant, site_key, action)?;
        if !(1..=100).contains(&limit) {
            return Err(SharError::new(400, "invalid_audit_limit", false, "none"));
        }
        let Some(audit) = &self.audit else {
            return Err(SharError::new(501, "audit_not_configured", false, "none"));
        };
        audit
            .list(tenant, site_key, action, limit)
            .map_err(|_| SharError::new(503, "audit_unavailable", true, "retry").retry_after(1))
    }
    pub fn with_nonce_store(
        signing: SigningMaterial,
        time_lock: TimeLockKey,
        policy: WorkPolicy,
        nonces: Arc<dyn NonceStore>,
    ) -> Self {
        let pressure = Arc::new(
            MemoryPressureStore::new(policy.quiet_window_seconds).expect("validated policy"),
        );
        let config = Arc::new(StaticConfigStore(policy.clone()));
        Self::with_stores(signing, time_lock, policy, nonces, pressure, config)
    }
    pub fn with_stores(
        signing: SigningMaterial,
        time_lock: TimeLockKey,
        policy: WorkPolicy,
        nonces: Arc<dyn NonceStore>,
        pressure: Arc<dyn PressureStore>,
        config: Arc<dyn ConfigStore>,
    ) -> Self {
        Self::with_stores_and_verification_keys(
            signing,
            time_lock,
            policy,
            nonces,
            pressure,
            config,
            Vec::new(),
        )
    }
    pub fn with_stores_and_verification_keys(
        signing: SigningMaterial,
        time_lock: TimeLockKey,
        policy: WorkPolicy,
        nonces: Arc<dyn NonceStore>,
        pressure: Arc<dyn PressureStore>,
        config: Arc<dyn ConfigStore>,
        previous_keys: Vec<VerificationMaterial>,
    ) -> Self {
        Self::with_stores_and_rotation(
            signing,
            time_lock,
            policy,
            nonces,
            pressure,
            config,
            previous_keys,
            Vec::new(),
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn with_stores_and_rotation(
        signing: SigningMaterial,
        time_lock: TimeLockKey,
        policy: WorkPolicy,
        nonces: Arc<dyn NonceStore>,
        pressure: Arc<dyn PressureStore>,
        config: Arc<dyn ConfigStore>,
        previous_keys: Vec<VerificationMaterial>,
        previous_time_locks: Vec<TimeLockKey>,
    ) -> Self {
        Self::with_stores_and_rotation_and_audit(
            signing,
            time_lock,
            policy,
            nonces,
            pressure,
            config,
            previous_keys,
            previous_time_locks,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_stores_and_rotation_and_audit(
        signing: SigningMaterial,
        time_lock: TimeLockKey,
        policy: WorkPolicy,
        nonces: Arc<dyn NonceStore>,
        pressure: Arc<dyn PressureStore>,
        config: Arc<dyn ConfigStore>,
        previous_keys: Vec<VerificationMaterial>,
        previous_time_locks: Vec<TimeLockKey>,
        audit: Option<Arc<dyn AuditStore>>,
    ) -> Self {
        assert!(
            validate_time_lock_key(&time_lock),
            "invalid RSW time-lock key"
        );
        let signer = CoseSigner::new(&signing).expect("valid static COSE protected header");
        let current = VerificationMaterial {
            key_id: signing.key_id.clone(),
            public_key: signer.verifying.to_bytes(),
        };
        let mut keys = vec![current];
        for key in previous_keys {
            if !keys.iter().any(|existing| existing.key_id == key.key_id) {
                keys.push(key);
            }
        }
        let mut time_locks = vec![time_lock.clone()];
        for key in previous_time_locks {
            assert!(
                validate_time_lock_key(&key),
                "invalid previous RSW time-lock key"
            );
            if let Some(existing) = time_locks.iter().find(|existing| existing.id == key.id) {
                assert!(
                    existing.modulus == key.modulus && existing.lambda == key.lambda,
                    "RSW time-lock key id collision"
                );
            } else {
                time_locks.push(key);
            }
        }
        let time_lock_modulus = URL_SAFE_NO_PAD.encode(time_lock.modulus.to_bytes_be());
        Self {
            signer,
            keys,
            time_lock,
            time_lock_modulus,
            time_locks,
            policy,
            nonces,
            pressure,
            config,
            audit,
            triangles: DEFAULT_RENDER_TRIANGLES,
            samples: DEFAULT_RENDER_SAMPLES,
            trust_keys: Vec::new(),
            trust_retention_seconds: 86_400,
            presence: PresencePlan::None,
            fallback: FallbackPlan {
                available: false,
                methods: Vec::new(),
            },
            signals: None,
            fallback_verifier: None,
        }
    }

    pub fn with_browser_plans(
        mut self,
        presence: PresencePlan,
        fallback: FallbackPlan,
    ) -> Result<Self, StoreError> {
        if fallback.methods.len() > 16
            || (fallback.available && fallback.methods.is_empty())
            || (!fallback.available && !fallback.methods.is_empty())
            || fallback.methods.iter().any(|method| {
                method.is_empty()
                    || method.len() > 64
                    || !method
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            })
            || fallback
                .methods
                .iter()
                .enumerate()
                .any(|(index, method)| fallback.methods[..index].contains(method))
        {
            return Err(StoreError);
        }
        self.presence = presence;
        self.fallback = fallback;
        Ok(self)
    }

    /// Install a trusted assurance source used only by [`Engine::issue`].
    /// Redemption and final verification never consult this provider.
    pub fn with_signal_provider(mut self, provider: Arc<dyn SignalProvider>) -> Self {
        self.signals = Some(provider);
        self
    }

    /// Install an optional host assertion verifier. The verifier runs before
    /// the assertion nonce is consumed and should be idempotent by assertion id.
    pub fn with_fallback_verifier(mut self, verifier: Arc<dyn FallbackVerifier>) -> Self {
        self.fallback_verifier = Some(verifier);
        self
    }

    pub fn with_trust_keys(
        mut self,
        keys: Vec<TrustKeyPair>,
        retention_seconds: u64,
    ) -> Result<Self, StoreError> {
        if keys.is_empty()
            || !(60..=2_592_000).contains(&retention_seconds)
            || keys
                .iter()
                .any(|key| key.key_id.is_empty() || key.key_id.len() > 32)
        {
            return Err(StoreError);
        }
        self.trust_keys = keys;
        self.trust_retention_seconds = retention_seconds;
        Ok(self)
    }

    pub fn with_render_work(mut self, triangles: u32, samples: u32) -> Result<Self, StoreError> {
        if !(1..=512).contains(&triangles) || !(1..=4_096).contains(&samples) {
            return Err(StoreError);
        }
        self.triangles = triangles;
        self.samples = samples;
        Ok(self)
    }

    pub fn trust_keys(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.trust_keys
            .iter()
            .map(|key| (key.key_id.clone(), key.public_key()))
            .collect()
    }

    fn record_audit(&self, event: AuditEvent) {
        if let Some(audit) = &self.audit {
            let _ = audit.record(&event);
        }
    }

    fn record_proof_failure(&self, claims: &ChallengeClaims, now: u64, code: &str) {
        self.record_audit(AuditEvent {
            version: "audit-v1".into(),
            kind: "proof_failed".into(),
            occurred_at: now,
            tenant: claims.tenant.clone(),
            site_key: claims.site.clone(),
            action: claims.action.clone(),
            tier: Some(claims.tier),
            backend: None,
            code: Some(code.into()),
        });
    }

    fn record_verification_failure(&self, claims: &VerificationClaims, now: u64, code: &str) {
        self.record_audit(AuditEvent {
            version: "audit-v1".into(),
            kind: "verification_failed".into(),
            occurred_at: now,
            tenant: claims.tenant.clone(),
            site_key: claims.site.clone(),
            action: claims.action.clone(),
            tier: Some(claims.receipt.tier),
            backend: None,
            code: Some(code.into()),
        });
    }

    fn consume_trust_credit(&self, request: &ChallengeRequest, now: u64) -> Result<(), SharError> {
        let Some(encoded) = request.trust_token.as_deref() else {
            return Ok(());
        };
        if self.trust_keys.is_empty() {
            return Err(SharError::new(
                400,
                "trust_not_configured",
                false,
                "new_challenge",
            ));
        }
        let token = trust::decode_trust_credit_token(encoded)
            .map_err(|_| SharError::new(400, "invalid_trust_token", false, "new_challenge"))?;
        if token.issued_at > now.saturating_add(60)
            || now > token.expires_at
            || token.expires_at.saturating_sub(token.issued_at) > self.trust_retention_seconds
        {
            return Err(SharError::new(
                400,
                "expired_trust_token",
                false,
                "new_challenge",
            ));
        }
        if token.tenant != request.tenant
            || token.site_key != request.site_key
            || token.action != request.action
            || token.origin != request.origin
        {
            return Err(SharError::new(
                400,
                "trust_binding_mismatch",
                false,
                "new_challenge",
            ));
        }
        let Some(key) = self
            .trust_keys
            .iter()
            .find(|candidate| candidate.key_id.ct_eq(&token.key_id).into())
        else {
            return Err(SharError::new(
                400,
                "unknown_trust_key",
                false,
                "new_challenge",
            ));
        };
        let scope = TrustScope {
            tenant: &request.tenant,
            site_key: &request.site_key,
            action: &request.action,
            origin: &request.origin,
        };
        let expected_digest = trust::trust_credit_challenge_digest(
            &token.key_id,
            &scope,
            token.issued_at,
            token.expires_at,
        )
        .map_err(|_| SharError::new(400, "invalid_trust_token", false, "new_challenge"))?;
        if expected_digest.ct_eq(&token.challenge_digest).unwrap_u8() != 1 {
            return Err(SharError::new(
                400,
                "invalid_trust_token",
                false,
                "new_challenge",
            ));
        }
        let scoped_key = key
            .for_scope(&scope)
            .map_err(|_| SharError::new(400, "invalid_trust_token", false, "new_challenge"))?;
        let input = trust::trust_input_for_scope(
            "credit",
            &token.challenge_nonce,
            &token.challenge_digest,
            &token.key_id,
            &scope,
        )
        .map_err(|_| SharError::new(400, "invalid_trust_token", false, "new_challenge"))?;
        let expected = scoped_key
            .evaluate_direct(&input)
            .map_err(|_| SharError::new(400, "invalid_trust_token", false, "new_challenge"))?;
        if expected.ct_eq(&token.output).unwrap_u8() != 1 {
            return Err(SharError::new(
                400,
                "invalid_trust_token",
                false,
                "new_challenge",
            ));
        }
        let replay_id = trust::trust_credit_replay_id(&token.key_id, &token.output)
            .map_err(|_| SharError::new(400, "invalid_trust_token", false, "new_challenge"))?;
        let fresh = self
            .nonces
            .consume("trust", &replay_id, token.expires_at)
            .map_err(|_| {
                SharError::new(503, "nonce_store_unavailable", true, "retry").retry_after(1)
            })?;
        if !fresh {
            return Err(SharError::new(
                409,
                "replayed_trust_token",
                false,
                "new_challenge",
            ));
        }
        // The nonce consumption is the durable one-shot boundary. Trust debt
        // is only a future pricing hint, so a pressure adapter failure must
        // not turn an already-consumed credit into a retryable loss.
        let _ = self.pressure.record_trust(request, now);
        Ok(())
    }
    pub fn verification_keys(&self) -> Vec<VerificationMaterial> {
        self.keys.clone()
    }
    pub fn time_lock_ids(&self) -> Vec<String> {
        self.time_locks.iter().map(|key| key.id.clone()).collect()
    }
    pub fn issue(
        &self,
        request: &ChallengeRequest,
        now: u64,
        nonce: [u8; 16],
        seed: [u8; 32],
    ) -> Result<ChallengeResponse, SharError> {
        validate_request(request)?;
        let mut priced_request = request.clone();
        if let Some(signals) = &self.signals {
            let tier = signals.assurance_tier(request).map_err(|_| {
                SharError::new(503, "pricing_unavailable", true, "retry").retry_after(1)
            })?;
            if tier > 32 {
                return Err(
                    SharError::new(503, "pricing_unavailable", true, "retry").retry_after(1)
                );
            }
            priced_request.assurance_tier = Some(request.assurance_tier.unwrap_or(0).max(tier));
        }
        let policy = self
            .config
            .policy(
                &priced_request.tenant,
                &priced_request.site_key,
                &priced_request.action,
            )
            .map_err(|_| {
                SharError::new(503, "pricing_unavailable", true, "retry").retry_after(1)
            })?;
        let quote = self
            .pressure
            .price_and_record(&priced_request, &policy, now)
            .map_err(|_| {
                SharError::new(503, "pricing_unavailable", true, "retry").retry_after(1)
            })?;
        let response = self.challenge_with_quote(&priced_request, quote, &policy, nonce, seed)?;
        // Consume an optional credit only after every quote-producing
        // operation has succeeded. This preserves a client's one-shot credit
        // when config, pricing, randomness, signing, or outstanding-work
        // storage is down.
        self.consume_trust_credit(&priced_request, now)?;
        self.record_audit(AuditEvent {
            version: "audit-v1".into(),
            kind: "challenge_issued".into(),
            occurred_at: now,
            tenant: priced_request.tenant.clone(),
            site_key: priced_request.site_key.clone(),
            action: priced_request.action.clone(),
            tier: Some(response.quote.tier),
            backend: None,
            code: None,
        });
        Ok(response)
    }

    fn trust_plan(&self, claims: &ChallengeClaims) -> Option<TrustTokenPlan> {
        let key = self.trust_keys.first()?;
        let (issued_at, expires_at) =
            trust::trust_credit_lifetime(claims.iat, self.trust_retention_seconds).ok()?;
        let scope = TrustScope {
            tenant: &claims.tenant,
            site_key: &claims.site,
            action: &claims.action,
            origin: &claims.origin,
        };
        let scoped_key = key.for_scope(&scope).ok()?;
        let challenge_digest =
            trust::trust_credit_challenge_digest(&key.key_id, &scope, issued_at, expires_at)
                .ok()?;
        Some(TrustTokenPlan::Voprf {
            suite: trust::TRUST_VOPRF_SUITE.into(),
            token_type: "credit".into(),
            key_id: URL_SAFE_NO_PAD.encode(&key.key_id),
            public_key: URL_SAFE_NO_PAD.encode(scoped_key.public_key()),
            challenge_digest: URL_SAFE_NO_PAD.encode(challenge_digest),
            issued_at,
            // The credit's lifetime starts when the challenge is issued, not
            // when the two-minute work envelope expires.
            expires_at,
        })
    }

    pub fn challenge(
        &self,
        request: &ChallengeRequest,
        pressure: &PressureInput,
        now: u64,
        nonce: [u8; 16],
        seed: [u8; 32],
    ) -> Result<ChallengeResponse, SharError> {
        self.challenge_with_policy(request, pressure, &self.policy, now, nonce, seed)
    }
    fn challenge_with_policy(
        &self,
        request: &ChallengeRequest,
        pressure: &PressureInput,
        policy: &WorkPolicy,
        now: u64,
        nonce: [u8; 16],
        seed: [u8; 32],
    ) -> Result<ChallengeResponse, SharError> {
        validate_request(request)?;
        let quote = price_work(pressure, policy, now).map_err(|_| {
            SharError::new(503, "pricing_unavailable", true, "retry").retry_after(1)
        })?;
        self.challenge_with_quote(request, quote, policy, nonce, seed)
    }

    fn challenge_with_quote(
        &self,
        request: &ChallengeRequest,
        quote: WorkQuote,
        policy: &WorkPolicy,
        nonce: [u8; 16],
        seed: [u8; 32],
    ) -> Result<ChallengeResponse, SharError> {
        let iterations = quote
            .time_lock_iterations
            .parse::<u64>()
            .map_err(|_| SharError::new(500, "internal_error", true, "retry"))?;
        let claims = ChallengeClaims {
            tenant: request.tenant.clone(),
            site: request.site_key.clone(),
            action: request.action.clone(),
            origin: request.origin.clone(),
            region: request.region.clone(),
            iat: quote.issued_at,
            exp: quote.expires_at,
            policy: policy.version.clone(),
            tier: quote.tier,
            iterations,
            rounds: quote.render_rounds,
            nonce,
            seed,
            modulus: self.time_lock.id.clone(),
            session: request.session_binding.clone(),
            network_pseudonym: request.network_pseudonym.clone(),
            triangles: self.triangles,
            samples: self.samples,
            trust_key_id: self.trust_keys.first().map(|key| key.key_id.clone()),
        };
        let input = derive_timelock_input(&nonce, &self.time_lock.modulus);
        let payload = encode_challenge(&claims)
            .map_err(|_| SharError::new(500, "internal_error", true, "retry"))?;
        let trust = self.trust_plan(&claims);
        let iteration_text = quote.time_lock_iterations.clone();
        Ok(ChallengeResponse {
            token: self
                .signer
                .sign(&payload)
                .map_err(|_| SharError::new(500, "internal_error", true, "retry"))?,
            quote,
            render: RenderingPlan {
                version: "render-v1".into(),
                seed: URL_SAFE_NO_PAD.encode(seed),
                rounds: claims.rounds,
                triangles: claims.triangles,
                samples: claims.samples,
            },
            time_lock: TimeLockPlan {
                version: "rsw-v1".into(),
                modulus_id: self.time_lock.id.clone(),
                modulus: self.time_lock_modulus.clone(),
                input: URL_SAFE_NO_PAD.encode(input.to_bytes_be()),
                iterations: iteration_text,
            },
            presence: self.presence,
            fallback: self.fallback.clone(),
            region: request.region.clone(),
            trust,
        })
    }
    pub fn redeem(
        &self,
        request: &RedeemRequest,
        now: u64,
        verification_nonce: [u8; 16],
    ) -> Result<RedeemResponse, SharError> {
        let payload = cose_verify(&request.token, &self.keys)
            .map_err(|_| SharError::new(400, "invalid_challenge", false, "new_challenge"))?;
        let c = decode_challenge(&payload)
            .map_err(|_| SharError::new(400, "invalid_challenge", false, "new_challenge"))?;
        let pressure_request = claims_request(&c);
        if now > c.exp {
            let _ =
                self.pressure
                    .record_failure(&pressure_request, FailureKind::Expired, c.exp, now);
            self.record_proof_failure(&c, now, "expired_challenge");
            return Err(SharError::new(
                400,
                "expired_challenge",
                false,
                "new_challenge",
            ));
        }
        let Some(time_lock) = self.time_locks.iter().find(|key| key.id == c.modulus) else {
            let _ =
                self.pressure
                    .record_failure(&pressure_request, FailureKind::Invalid, c.exp, now);
            self.record_proof_failure(&c, now, "unsupported_modulus");
            return Err(SharError::new(
                400,
                "unsupported_modulus",
                false,
                "new_challenge",
            ));
        };
        let output = match URL_SAFE_NO_PAD.decode(&request.time_lock.output) {
            Ok(bytes) => BigUint::from_bytes_be(&bytes),
            Err(_) => {
                let _ = self.pressure.record_failure(
                    &pressure_request,
                    FailureKind::Invalid,
                    c.exp,
                    now,
                );
                self.record_proof_failure(&c, now, "invalid_work");
                return Err(SharError::new(400, "invalid_work", false, "new_challenge"));
            }
        };
        let input = derive_timelock_input(&c.nonce, &time_lock.modulus);
        if !verify_timelock(time_lock, &input, c.iterations, &output) {
            let _ =
                self.pressure
                    .record_failure(&pressure_request, FailureKind::Invalid, c.exp, now);
            self.record_proof_failure(&c, now, "invalid_work");
            return Err(SharError::new(400, "invalid_work", false, "new_challenge"));
        }
        let render_plan = RenderingProofPlan {
            version: "render-v1".into(),
            seed: URL_SAFE_NO_PAD.encode(c.seed),
            rounds: c.rounds,
            triangles: c.triangles,
            samples: c.samples,
        };
        let valid_css_commitment =
            request
                .rendering
                .css_commitment
                .as_ref()
                .is_none_or(|commitment| {
                    commitment.version == "css-transcript-v1"
                        && css_transcript_commitment(&render_plan)
                            .is_ok_and(|expected| commitment.digest == expected)
                });
        if !matches!(
            request.rendering.backend.as_str(),
            "webgpu" | "webgl2" | "css"
        ) || !valid_css_commitment
        {
            let _ =
                self.pressure
                    .record_failure(&pressure_request, FailureKind::Invalid, c.exp, now);
            self.record_proof_failure(&c, now, "invalid_work");
            return Err(SharError::new(400, "invalid_work", false, "new_challenge"));
        }
        let expected =
            solve_rendering(&c.seed, c.rounds, c.triangles, c.samples).map_err(|_| {
                self.record_proof_failure(&c, now, "invalid_work");
                SharError::new(400, "invalid_work", false, "new_challenge")
            })?;
        if URL_SAFE_NO_PAD
            .decode(&request.rendering.digest)
            .ok()
            .as_deref()
            != Some(expected.as_slice())
        {
            let _ =
                self.pressure
                    .record_failure(&pressure_request, FailureKind::Invalid, c.exp, now);
            self.record_proof_failure(&c, now, "invalid_work");
            return Err(SharError::new(400, "invalid_work", false, "new_challenge"));
        }
        let trust_evaluation = request.trust_blinded.as_ref().and_then(|blinded_text| {
            let trust_key_id = c.trust_key_id.as_ref()?;
            let key = self
                .trust_keys
                .iter()
                .find(|candidate| candidate.key_id.ct_eq(trust_key_id).into())?;
            let scoped_key = key
                .for_scope(&TrustScope {
                    tenant: &c.tenant,
                    site_key: &c.site,
                    action: &c.action,
                    origin: &c.origin,
                })
                .ok()?;
            let blinded = URL_SAFE_NO_PAD.decode(blinded_text).ok()?;
            if blinded.len() != 32 {
                return None;
            }
            let proof_seed = hash(&[b"shar/trust/proof/v1\0", &verification_nonce, &c.nonce]);
            let evaluation = scoped_key.evaluate_with_seed(&blinded, &proof_seed).ok()?;
            let (issued_at, expires_at) =
                trust::trust_credit_lifetime(c.iat, self.trust_retention_seconds).ok()?;
            Some(TrustEvaluationEnvelope {
                version: "trust-evaluation-v1".into(),
                suite: trust::TRUST_VOPRF_SUITE.into(),
                key_id: URL_SAFE_NO_PAD.encode(&key.key_id),
                evaluated: URL_SAFE_NO_PAD.encode(evaluation.evaluated),
                proof: URL_SAFE_NO_PAD.encode(evaluation.proof),
                issued_at,
                expires_at,
            })
        });
        let receipt = WorkReceipt {
            version: "work-receipt-v1".into(),
            tier: c.tier,
            time_lock_iterations: c.iterations.to_string(),
            render_rounds: c.rounds,
            rendering_backend: request.rendering.backend.clone(),
            completed_at: now,
        };
        let v = VerificationClaims {
            tenant: c.tenant.clone(),
            site: c.site.clone(),
            action: c.action.clone(),
            origin: c.origin.clone(),
            region: c.region.clone(),
            iat: now,
            exp: now.checked_add(300).ok_or_else(|| {
                SharError::new(503, "clock_unavailable", true, "retry").retry_after(1)
            })?,
            nonce: verification_nonce.to_vec(),
            session: c.session.clone(),
            receipt: receipt.clone(),
        };
        // Sign before consuming the challenge nonce so a response-generation
        // failure cannot turn a correct proof into an unretryable loss.
        let verification_token = self
            .signer
            .sign(
                &encode_verification(&v)
                    .map_err(|_| SharError::new(500, "internal_error", true, "retry"))?,
            )
            .map_err(|_| SharError::new(500, "internal_error", true, "retry"))?;
        if !self
            .nonces
            .consume("challenge", &c.nonce, c.exp)
            .map_err(|_| {
                SharError::new(503, "nonce_store_unavailable", true, "retry").retry_after(1)
            })?
        {
            let _ =
                self.pressure
                    .record_failure(&pressure_request, FailureKind::Replay, c.exp, now);
            self.record_proof_failure(&c, now, "replayed_challenge");
            return Err(SharError::new(
                409,
                "replayed_challenge",
                false,
                "new_challenge",
            ));
        }
        let _ = self.pressure.record_success(&pressure_request, c.exp, now);
        self.record_audit(AuditEvent {
            version: "audit-v1".into(),
            kind: "proof_redeemed".into(),
            occurred_at: now,
            tenant: c.tenant.clone(),
            site_key: c.site.clone(),
            action: c.action.clone(),
            tier: Some(c.tier),
            backend: Some(request.rendering.backend.clone()),
            code: None,
        });
        Ok(RedeemResponse {
            token: verification_token,
            expires_at: v.exp,
            receipt,
            trust_evaluation,
        })
    }
    pub fn siteverify(
        &self,
        request: &SiteVerifyRequest,
        now: u64,
    ) -> Result<SiteVerifyResponse, SharError> {
        let payload = cose_verify(&request.token, &self.keys)
            .map_err(|_| SharError::new(400, "invalid_verification", false, "new_challenge"))?;
        let c = decode_verification(&payload)
            .map_err(|_| SharError::new(400, "invalid_verification", false, "new_challenge"))?;
        if now > c.exp {
            self.record_verification_failure(&c, now, "expired_verification");
            return Err(SharError::new(
                400,
                "expired_verification",
                false,
                "new_challenge",
            ));
        }
        if request.tenant.as_ref().is_some_and(|x| x != &c.tenant)
            || request.site_key.as_ref().is_some_and(|x| x != &c.site)
            || request.action.as_ref().is_some_and(|x| x != &c.action)
            || request.origin.as_ref().is_some_and(|x| x != &c.origin)
            || request
                .session_binding
                .as_ref()
                .is_some_and(|x| Some(x) != c.session.as_ref())
            || request
                .region
                .as_ref()
                .is_some_and(|x| Some(x) != c.region.as_ref())
        {
            self.record_verification_failure(&c, now, "binding_mismatch");
            return Err(SharError::new(
                400,
                "binding_mismatch",
                false,
                "new_challenge",
            ));
        }
        if !self
            .nonces
            .consume("verification", &c.nonce, c.exp)
            .map_err(|_| {
                SharError::new(503, "nonce_store_unavailable", true, "retry").retry_after(1)
            })?
        {
            self.record_verification_failure(&c, now, "replayed_verification");
            return Err(SharError::new(
                409,
                "replayed_verification",
                false,
                "new_challenge",
            ));
        }
        self.record_audit(AuditEvent {
            version: "audit-v1".into(),
            kind: "site_verified".into(),
            occurred_at: now,
            tenant: c.tenant.clone(),
            site_key: c.site.clone(),
            action: c.action.clone(),
            tier: Some(c.receipt.tier),
            backend: None,
            code: None,
        });
        Ok(SiteVerifyResponse {
            success: true,
            tenant: c.tenant,
            site_key: c.site,
            action: c.action,
            origin: c.origin,
            region: c.region,
            receipt: c.receipt,
        })
    }

    pub fn complete_fallback(
        &self,
        request: &FallbackCompletionRequest,
        now: u64,
    ) -> Result<FallbackCompletionResponse, SharError> {
        validate_request(&ChallengeRequest {
            tenant: request.tenant.clone(),
            site_key: request.site_key.clone(),
            action: request.action.clone(),
            origin: request.origin.clone(),
            region: request.region.clone(),
            session_binding: request.session_binding.clone(),
            network_pseudonym: None,
            assurance_tier: None,
            trust_token: None,
        })?;
        if request.method.is_empty()
            || request.method.len() > 64
            || !request
                .method
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(SharError::new(
                400,
                "invalid_fallback_method",
                false,
                "none",
            ));
        }
        if self.fallback.available && !self.fallback.methods.contains(&request.method) {
            return Err(SharError::new(
                400,
                "invalid_fallback_method",
                false,
                "none",
            ));
        }
        if request.assertion_id.len() < 16 || request.assertion_id.len() > 256 {
            return Err(SharError::new(400, "invalid_assertion_id", false, "none"));
        }
        if !self.fallback.available {
            return Err(SharError::new(
                501,
                "fallback_not_configured",
                false,
                "fallback",
            ));
        }
        if let Some(verifier) = &self.fallback_verifier {
            let payload = serde_json::to_value(request)
                .map_err(|_| SharError::new(500, "internal_error", true, "retry"))?;
            let verified = verifier.verify(&request.method, &payload).map_err(|_| {
                SharError::new(503, "fallback_unavailable", true, "retry").retry_after(1)
            })?;
            if !verified {
                self.record_audit(AuditEvent {
                    version: "audit-v1".into(),
                    kind: "verification_failed".into(),
                    occurred_at: now,
                    tenant: request.tenant.clone(),
                    site_key: request.site_key.clone(),
                    action: request.action.clone(),
                    tier: None,
                    backend: None,
                    code: Some("fallback_not_verified".into()),
                });
                return Err(SharError::new(
                    400,
                    "fallback_not_verified",
                    false,
                    "fallback",
                ));
            }
        }
        let nonce = hash(&[
            b"shar/fallback-assertion/v1\0",
            request.assertion_id.as_bytes(),
        ]);
        if !self
            .nonces
            .consume(
                "fallback",
                &nonce,
                now.checked_add(300).ok_or_else(|| {
                    SharError::new(503, "clock_unavailable", true, "retry").retry_after(1)
                })?,
            )
            .map_err(|_| {
                SharError::new(503, "nonce_store_unavailable", true, "retry").retry_after(1)
            })?
        {
            self.record_audit(AuditEvent {
                version: "audit-v1".into(),
                kind: "verification_failed".into(),
                occurred_at: now,
                tenant: request.tenant.clone(),
                site_key: request.site_key.clone(),
                action: request.action.clone(),
                tier: None,
                backend: None,
                code: Some("replayed_fallback_assertion".into()),
            });
            return Err(SharError::new(
                409,
                "replayed_fallback_assertion",
                false,
                "none",
            ));
        }
        self.record_audit(AuditEvent {
            version: "audit-v1".into(),
            kind: "fallback_completed".into(),
            occurred_at: now,
            tenant: request.tenant.clone(),
            site_key: request.site_key.clone(),
            action: request.action.clone(),
            tier: None,
            backend: None,
            code: None,
        });
        Ok(FallbackCompletionResponse {
            success: true,
            tenant: request.tenant.clone(),
            site_key: request.site_key.clone(),
            action: request.action.clone(),
            origin: request.origin.clone(),
            region: request.region.clone(),
            verification_method: "fallback".into(),
            method: request.method.clone(),
        })
    }
}

fn validate_scope(tenant: &str, site_key: &str, action: &str) -> Result<(), SharError> {
    for (value, limit, code) in [
        (tenant, 128, "invalid_tenant"),
        (site_key, 256, "invalid_site_key"),
        (action, 128, "invalid_action"),
    ] {
        if value.is_empty() || value.len() > limit || value.chars().any(char::is_control) {
            return Err(SharError::new(400, code, false, "none"));
        }
    }
    Ok(())
}

fn validate_request(r: &ChallengeRequest) -> Result<(), SharError> {
    for (value, limit, code) in [
        (&r.tenant, 128, "invalid_tenant"),
        (&r.site_key, 256, "invalid_site_key"),
        (&r.action, 128, "invalid_action"),
    ] {
        if value.is_empty() || value.len() > limit || value.chars().any(char::is_control) {
            return Err(SharError::new(400, code, false, "none"));
        }
    }
    if r.origin.is_empty() || r.origin.len() > 512 || r.origin.chars().any(char::is_control) {
        return Err(SharError::new(400, "invalid_origin", false, "none"));
    }
    if let Some(value) = &r.region
        && (value.is_empty() || value.len() > 64 || value.chars().any(char::is_control))
    {
        return Err(SharError::new(400, "invalid_region", false, "none"));
    }
    if r.assurance_tier.is_some_and(|tier| tier > 32) {
        return Err(SharError::new(400, "invalid_assurance_tier", false, "none"));
    }
    if let Some(value) = &r.session_binding
        && (value.is_empty() || value.len() > 256 || value.chars().any(char::is_control))
    {
        return Err(SharError::new(
            400,
            "invalid_session_binding",
            false,
            "none",
        ));
    }
    if let Some(value) = &r.network_pseudonym
        && (value.is_empty() || value.len() > 128 || value.chars().any(char::is_control))
    {
        return Err(SharError::new(
            400,
            "invalid_network_pseudonym",
            false,
            "none",
        ));
    }
    if let Some(value) = &r.trust_token
        && (value.is_empty() || value.len() > 4096)
    {
        return Err(SharError::new(400, "invalid_trust_token", false, "none"));
    }
    let parsed = url::Url::parse(&r.origin)
        .map_err(|_| SharError::new(400, "invalid_origin", false, "none"))?;
    let local_http = parsed.scheme() == "http"
        && matches!(
            parsed.host_str(),
            Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
        );
    if parsed.origin().ascii_serialization() != r.origin
        || (parsed.scheme() != "https" && !local_http)
    {
        return Err(SharError::new(400, "invalid_origin", false, "none"));
    }
    Ok(())
}
fn encode_challenge(c: &ChallengeClaims) -> Result<Vec<u8>, &'static str> {
    fn key(out: &mut Vec<u8>, value: u64) {
        head(0, value, out);
    }
    fn unsigned(out: &mut Vec<u8>, key_value: u64, value: u64) {
        key(out, key_value);
        head(0, value, out);
    }
    fn bytes(out: &mut Vec<u8>, key_value: u64, value: &[u8]) -> Result<(), &'static str> {
        key(out, key_value);
        head(
            2,
            value.len().try_into().map_err(|_| "length overflow")?,
            out,
        );
        out.extend_from_slice(value);
        Ok(())
    }
    fn text(out: &mut Vec<u8>, key_value: u64, value: &str) -> Result<(), &'static str> {
        key(out, key_value);
        head(
            3,
            value.len().try_into().map_err(|_| "length overflow")?,
            out,
        );
        out.extend_from_slice(value.as_bytes());
        Ok(())
    }

    // All challenge keys are unsigned integers below 24, so canonical CBOR
    // orders them numerically. Keep this fixed protocol map in that order and
    // avoid allocating/sorting a generic tree on every issuance.
    let optional = usize::from(c.session.is_some())
        + usize::from(c.network_pseudonym.is_some())
        + usize::from(c.region.is_some())
        + usize::from(c.trust_key_id.is_some());
    let mut out = Vec::with_capacity(256 + c.origin.len());
    head(5, (17 + optional) as u64, &mut out);
    text(&mut out, 0, "challenge")?;
    text(&mut out, 1, "shar-v1")?;
    text(&mut out, 2, &c.tenant)?;
    text(&mut out, 3, &c.site)?;
    text(&mut out, 4, &c.action)?;
    text(&mut out, 5, &c.origin)?;
    unsigned(&mut out, 6, c.iat);
    unsigned(&mut out, 7, c.exp);
    text(&mut out, 8, &c.policy)?;
    unsigned(&mut out, 9, c.tier.into());
    unsigned(&mut out, 10, c.iterations);
    unsigned(&mut out, 11, c.rounds.into());
    bytes(&mut out, 12, &c.nonce)?;
    bytes(&mut out, 13, &c.seed)?;
    text(&mut out, 14, &c.modulus)?;
    if let Some(session) = &c.session {
        text(&mut out, 15, session)?;
    }
    unsigned(&mut out, 16, c.triangles.into());
    unsigned(&mut out, 17, c.samples.into());
    if let Some(network) = &c.network_pseudonym {
        text(&mut out, 19, network)?;
    }
    if let Some(region) = &c.region {
        text(&mut out, 20, region)?;
    }
    if let Some(key_id) = &c.trust_key_id {
        bytes(&mut out, 21, key_id)?;
    }
    Ok(out)
}
fn decode_challenge(b: &[u8]) -> Result<ChallengeClaims, &'static str> {
    let Cbor::Map(m) = decode_cbor(b)? else {
        return Err("claims");
    };
    if text(&m, 0)? != "challenge" || text(&m, 1)? != "shar-v1" {
        return Err("claims");
    }
    let c = ChallengeClaims {
        tenant: text(&m, 2)?.into(),
        site: text(&m, 3)?.into(),
        action: text(&m, 4)?.into(),
        origin: text(&m, 5)?.into(),
        region: map_get(&m, 20)
            .map(|x| match x {
                Cbor::Text(s) => Ok(s.clone()),
                _ => Err("claims"),
            })
            .transpose()?,
        iat: uint(&m, 6)?,
        exp: uint(&m, 7)?,
        policy: text(&m, 8)?.into(),
        tier: uint(&m, 9)?.try_into().map_err(|_| "bounds")?,
        iterations: uint(&m, 10)?,
        rounds: uint(&m, 11)?.try_into().map_err(|_| "bounds")?,
        nonce: bytes(&m, 12)?.try_into().map_err(|_| "claims")?,
        seed: bytes(&m, 13)?.try_into().map_err(|_| "claims")?,
        modulus: text(&m, 14)?.into(),
        session: map_get(&m, 15)
            .map(|x| match x {
                Cbor::Text(s) => Ok(s.clone()),
                _ => Err("claims"),
            })
            .transpose()?,
        network_pseudonym: map_get(&m, 19)
            .map(|x| match x {
                Cbor::Text(s) => Ok(s.clone()),
                _ => Err("claims"),
            })
            .transpose()?,
        triangles: uint(&m, 16)?.try_into().map_err(|_| "bounds")?,
        samples: uint(&m, 17)?.try_into().map_err(|_| "bounds")?,
        trust_key_id: map_get(&m, 21)
            .map(|x| match x {
                Cbor::Bytes(value) if !value.is_empty() && value.len() <= 32 => Ok(value.clone()),
                _ => Err("claims"),
            })
            .transpose()?,
    };
    if c.tier > 32
        || c.iterations == 0
        || c.rounds == 0
        || c.rounds > MAX_RENDER_ROUNDS
        || c.triangles == 0
        || c.triangles > 512
        || c.samples == 0
        || c.samples > 4096
        || c.exp < c.iat
        || c.trust_key_id
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 32)
        || c.region.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > 64 || value.chars().any(char::is_control)
        })
        || c.session.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
        })
        || c.network_pseudonym.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
        })
    {
        return Err("bounds");
    }
    Ok(c)
}

fn claims_request(c: &ChallengeClaims) -> ChallengeRequest {
    ChallengeRequest {
        tenant: c.tenant.clone(),
        site_key: c.site.clone(),
        action: c.action.clone(),
        origin: c.origin.clone(),
        region: c.region.clone(),
        session_binding: c.session.clone(),
        network_pseudonym: c.network_pseudonym.clone(),
        assurance_tier: None,
        trust_token: None,
    }
}
fn encode_verification(c: &VerificationClaims) -> Result<Vec<u8>, &'static str> {
    let r = &c.receipt;
    let receipt = Cbor::Map(vec![
        (u(0), t(&r.version)),
        (u(1), u(r.tier.into())),
        (u(2), t(&r.time_lock_iterations)),
        (u(3), u(r.render_rounds.into())),
        (u(4), t(&r.rendering_backend)),
        (u(5), u(r.completed_at)),
    ]);
    let mut e = vec![
        (0, t("verification")),
        (1, t("shar-v1")),
        (2, t(&c.tenant)),
        (3, t(&c.site)),
        (4, t(&c.action)),
        (5, t(&c.origin)),
        (6, u(c.iat)),
        (7, u(c.exp)),
        (12, Cbor::Bytes(c.nonce.clone())),
        (18, receipt),
    ];
    if let Some(region) = &c.region {
        e.push((20, t(region)));
    }
    if let Some(s) = &c.session {
        e.push((15, t(s)))
    }
    encode_cbor(&Cbor::Map(e.into_iter().map(|(k, v)| (u(k), v)).collect()))
}
fn decode_verification(b: &[u8]) -> Result<VerificationClaims, &'static str> {
    let Cbor::Map(m) = decode_cbor(b)? else {
        return Err("claims");
    };
    if text(&m, 0)? != "verification" || text(&m, 1)? != "shar-v1" {
        return Err("claims");
    }
    let Cbor::Map(r) = map_get(&m, 18).ok_or("claims")? else {
        return Err("claims");
    };
    let backend = text(r, 4)?;
    if RenderingBackend::parse(backend).is_err() {
        return Err("claims");
    }
    let time_lock_iterations = text(r, 2)?.to_owned();
    let c = VerificationClaims {
        tenant: text(&m, 2)?.into(),
        site: text(&m, 3)?.into(),
        action: text(&m, 4)?.into(),
        origin: text(&m, 5)?.into(),
        region: map_get(&m, 20)
            .map(|x| match x {
                Cbor::Text(s) => Ok(s.clone()),
                _ => Err("claims"),
            })
            .transpose()?,
        iat: uint(&m, 6)?,
        exp: uint(&m, 7)?,
        nonce: bytes(&m, 12)?.to_vec(),
        session: map_get(&m, 15)
            .map(|x| match x {
                Cbor::Text(s) => Ok(s.clone()),
                _ => Err("claims"),
            })
            .transpose()?,
        receipt: WorkReceipt {
            version: text(r, 0)?.into(),
            tier: uint(r, 1)?.try_into().map_err(|_| "bounds")?,
            time_lock_iterations,
            render_rounds: uint(r, 3)?.try_into().map_err(|_| "bounds")?,
            rendering_backend: backend.into(),
            completed_at: uint(r, 5)?,
        },
    };
    if c.nonce.len() != 16
        || c.exp < c.iat
        || c.receipt.version != "work-receipt-v1"
        || c.receipt.tier > 32
        || c.receipt.render_rounds == 0
        || c.receipt.render_rounds > MAX_RENDER_ROUNDS
        || c.receipt
            .time_lock_iterations
            .parse::<u64>()
            .map_or(true, |value| {
                value == 0 || value.to_string() != c.receipt.time_lock_iterations
            })
        || c.region.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > 64 || value.chars().any(char::is_control)
        })
    {
        return Err("bounds");
    }
    Ok(c)
}
fn u(v: u64) -> Cbor {
    Cbor::Unsigned(v)
}
fn t(v: &str) -> Cbor {
    Cbor::Text(v.into())
}
fn uint(m: &[(Cbor, Cbor)], k: u64) -> Result<u64, &'static str> {
    match map_get(m, k) {
        Some(Cbor::Unsigned(v)) => Ok(*v),
        _ => Err("claims"),
    }
}
fn text(m: &[(Cbor, Cbor)], k: u64) -> Result<&str, &'static str> {
    match map_get(m, k) {
        Some(Cbor::Text(v)) => Ok(v),
        _ => Err("claims"),
    }
}
fn bytes(m: &[(Cbor, Cbor)], k: u64) -> Result<&[u8], &'static str> {
    match map_get(m, k) {
        Some(Cbor::Bytes(v)) => Ok(v),
        _ => Err("claims"),
    }
}

pub fn conformance_values() -> BTreeMap<&'static str, String> {
    let mut out = BTreeMap::new();
    let seed = [7_u8; 32];
    out.insert(
        "ed25519_public",
        URL_SAFE_NO_PAD.encode(public_from_seed(&seed)),
    );
    let render = solve_rendering(&[0_u8; 32], 2, 8, 16).expect("fixed bounds");
    out.insert("render_digest", URL_SAFE_NO_PAD.encode(render));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::{TrustBlindState, TrustEvaluation, TrustRng};

    #[derive(serde::Deserialize)]
    struct WorkPriceVectorDocument {
        policy: WorkPricePolicy,
        now: u64,
        vectors: Vec<WorkPriceVector>,
    }

    #[derive(serde::Deserialize)]
    struct WorkPricePolicy {
        version: String,
        base_iterations: String,
        base_render_rounds: u32,
        quiet_window_seconds: u64,
        base_lifetime_seconds: u64,
        iteration_allowance: String,
        round_allowance_seconds: u64,
        max_lifetime_seconds: u64,
    }

    #[derive(serde::Deserialize)]
    struct WorkPriceVector {
        name: String,
        pressure: PressureInput,
        quote: WorkQuote,
    }

    #[derive(serde::Deserialize)]
    struct MalformedCborDocument {
        limits: MalformedCborLimits,
        vectors: Vec<MalformedCborVector>,
    }

    #[derive(serde::Deserialize)]
    struct MalformedCborLimits {
        maximum_depth: usize,
        maximum_items: usize,
    }

    #[derive(serde::Deserialize)]
    struct MalformedCborVector {
        name: String,
        segments: Vec<MalformedCborSegment>,
        outcome: String,
    }

    #[derive(serde::Deserialize)]
    struct MalformedCborSegment {
        hex: String,
        repeat: usize,
    }

    #[derive(serde::Deserialize)]
    struct RswKeyValidationDocument {
        vectors: Vec<RswKeyValidationVector>,
    }

    #[derive(serde::Deserialize)]
    struct RswKeyValidationVector {
        name: String,
        modulus: String,
        lambda: String,
        valid: bool,
    }

    #[derive(serde::Deserialize)]
    struct BoundedTextDocument {
        version: String,
        vectors: Vec<BoundedTextVector>,
    }

    #[derive(serde::Deserialize)]
    struct BoundedTextVector {
        name: String,
        field: String,
        unit: String,
        repetitions: usize,
        valid: bool,
        error: Option<String>,
    }

    fn malformed_bytes(vector: &MalformedCborVector) -> Vec<u8> {
        let mut output = Vec::new();
        for segment in &vector.segments {
            assert_eq!(segment.hex.len() % 2, 0, "{}", vector.name);
            let bytes = segment
                .hex
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let text = std::str::from_utf8(pair).unwrap();
                    u8::from_str_radix(text, 16).unwrap()
                })
                .collect::<Vec<_>>();
            for _ in 0..segment.repeat {
                output.extend(&bytes);
            }
        }
        output
    }
    fn policy() -> WorkPolicy {
        WorkPolicy {
            version: "policy-test-v1".into(),
            base_iterations: 16,
            base_render_rounds: 1,
            quiet_window_seconds: 60,
            base_lifetime_seconds: 120,
            iteration_allowance: 1000,
            round_allowance_seconds: 1,
            max_lifetime_seconds: 86400,
        }
    }
    fn pressure() -> PressureInput {
        PressureInput {
            base_tier: 0,
            velocity_tier: 0,
            outstanding_tier: 0,
            network_tier: 0,
            failure_debt: 0,
            assurance_debt: 0,
            trust_credits: 0,
        }
    }

    #[test]
    fn work_pricing_matches_language_neutral_vectors() {
        let document: WorkPriceVectorDocument =
            serde_json::from_str(include_str!("../../../protocol/work-price-vectors.json"))
                .unwrap();
        let policy = WorkPolicy {
            version: document.policy.version,
            base_iterations: document.policy.base_iterations.parse().unwrap(),
            base_render_rounds: document.policy.base_render_rounds,
            quiet_window_seconds: document.policy.quiet_window_seconds,
            base_lifetime_seconds: document.policy.base_lifetime_seconds,
            iteration_allowance: document.policy.iteration_allowance.parse().unwrap(),
            round_allowance_seconds: document.policy.round_allowance_seconds,
            max_lifetime_seconds: document.policy.max_lifetime_seconds,
        };
        for vector in document.vectors {
            assert_eq!(
                price_work(&vector.pressure, &policy, document.now).unwrap(),
                vector.quote,
                "{}",
                vector.name
            );
        }
    }

    #[test]
    fn rsw_trapdoor_validation_matches_language_neutral_vectors() {
        let document: RswKeyValidationDocument = serde_json::from_str(include_str!(
            "../../../protocol/rsw-key-validation-vectors.json"
        ))
        .unwrap();
        for vector in document.vectors {
            let key = TimeLockKey {
                id: vector.name.clone(),
                modulus: BigUint::parse_bytes(vector.modulus.as_bytes(), 10).unwrap(),
                lambda: BigUint::parse_bytes(vector.lambda.as_bytes(), 10).unwrap(),
            };
            assert_eq!(
                validate_time_lock_key(&key),
                vector.valid,
                "{}",
                vector.name
            );
        }
    }
    fn engine() -> Engine {
        let p = BigUint::from(1_000_003_u64);
        let q = BigUint::from(1_000_033_u64);
        let lambda = BigUint::from(166_672_333_344_u64);
        Engine::new(
            SigningMaterial {
                key_id: vec![9, 9, 9, 1],
                seed: [7; 32],
            },
            TimeLockKey {
                id: "test-rsw".into(),
                modulus: &p * &q,
                lambda,
            },
            policy(),
        )
    }

    struct UnavailableNonceStore;
    impl NonceStore for UnavailableNonceStore {
        fn health(&self) -> Result<(), StoreError> {
            Err(StoreError)
        }

        fn consume(
            &self,
            _namespace: &str,
            _nonce: &[u8],
            _expires_at: u64,
        ) -> Result<bool, StoreError> {
            Ok(true)
        }
    }

    #[derive(Default)]
    struct MutationCounters {
        nonce: std::sync::atomic::AtomicUsize,
        pressure: std::sync::atomic::AtomicUsize,
        audit: std::sync::atomic::AtomicUsize,
    }

    struct CountingNonceStore(Arc<MutationCounters>);
    impl NonceStore for CountingNonceStore {
        fn consume(
            &self,
            _namespace: &str,
            _nonce: &[u8],
            _expires_at: u64,
        ) -> Result<bool, StoreError> {
            self.0
                .nonce
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(true)
        }
    }

    struct CountingPressureStore(Arc<MutationCounters>);
    impl PressureStore for CountingPressureStore {
        fn read(
            &self,
            _input: &ChallengeRequest,
            _now: u64,
            _quiet_window_seconds: u64,
        ) -> Result<PressureInput, StoreError> {
            self.0
                .pressure
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(pressure())
        }

        fn price_and_record(
            &self,
            input: &ChallengeRequest,
            policy: &WorkPolicy,
            now: u64,
        ) -> Result<WorkQuote, StoreError> {
            self.0
                .pressure
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut input_pressure = pressure();
            if let Some(assurance_tier) = input.assurance_tier {
                input_pressure.assurance_debt = input_pressure.assurance_debt.max(assurance_tier);
            }
            price_work(&input_pressure, policy, now).map_err(|_| StoreError)
        }

        fn record_issued(
            &self,
            _input: &ChallengeRequest,
            _expires_at: u64,
            _now: u64,
        ) -> Result<(), StoreError> {
            self.0
                .pressure
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }

        fn record_success(
            &self,
            _input: &ChallengeRequest,
            _expires_at: u64,
            _now: u64,
        ) -> Result<(), StoreError> {
            self.0
                .pressure
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }

        fn record_failure(
            &self,
            _input: &ChallengeRequest,
            _kind: FailureKind,
            _expires_at: u64,
            _now: u64,
        ) -> Result<(), StoreError> {
            self.0
                .pressure
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    struct CountingAuditStore(Arc<MutationCounters>);
    impl AuditStore for CountingAuditStore {
        fn record(&self, _event: &AuditEvent) -> Result<(), StoreError> {
            self.0
                .audit
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn readiness_checks_required_stores_without_mutating_work_state() {
        assert!(engine().ready().is_ok());
        let p = BigUint::from(1_000_003_u64);
        let q = BigUint::from(1_000_033_u64);
        let unavailable = Engine::with_nonce_store(
            SigningMaterial {
                key_id: vec![9, 9, 9, 1],
                seed: [7; 32],
            },
            TimeLockKey {
                id: "test-rsw".into(),
                modulus: &p * &q,
                lambda: BigUint::from(166_672_333_344_u64),
            },
            policy(),
            Arc::new(UnavailableNonceStore),
        );
        let error = unavailable.ready().unwrap_err();
        assert_eq!(error.status, 503);
        assert_eq!(error.code, "readiness_unavailable");
        assert!(error.retryable);
        assert_eq!(error.next_action, "retry");
        assert_eq!(error.retry_after, Some(1));
    }
    #[test]
    fn canonical_cbor_vector() {
        let value = Cbor::Map(vec![(t("b"), u(2)), (u(1), t("one")), (t("a"), u(1))]);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(encode_cbor(&value).unwrap()),
            "owFjb25lYWEBYWIC"
        );
        assert_eq!(decode_cbor(&[0x18, 1]), Err("noncanonical integer"));
    }

    #[test]
    fn bounded_hostile_cbor_corpus_rejects_without_state_mutation() {
        let document: MalformedCborDocument = serde_json::from_str(include_str!(
            "../../../protocol/malformed-cbor-vectors.json"
        ))
        .unwrap();
        assert_eq!(document.limits.maximum_depth, MAX_CBOR_DEPTH);
        assert_eq!(document.limits.maximum_items, MAX_CBOR_ITEMS);

        let p = BigUint::from(1_000_003_u64);
        let q = BigUint::from(1_000_033_u64);
        let counters = Arc::new(MutationCounters::default());
        let engine = Engine::with_stores_and_rotation_and_audit(
            SigningMaterial {
                key_id: vec![9, 9, 9, 1],
                seed: [7; 32],
            },
            TimeLockKey {
                id: "test-rsw".into(),
                modulus: &p * &q,
                lambda: BigUint::from(166_672_333_344_u64),
            },
            policy(),
            Arc::new(CountingNonceStore(counters.clone())),
            Arc::new(CountingPressureStore(counters.clone())),
            Arc::new(StaticConfigStore(policy())),
            Vec::new(),
            Vec::new(),
            Some(Arc::new(CountingAuditStore(counters.clone()))),
        );
        for vector in document.vectors {
            let bytes = malformed_bytes(&vector);
            let decoded = decode_cbor(&bytes);
            if vector.outcome == "accept" {
                assert!(decoded.is_ok(), "{}", vector.name);
            } else {
                assert!(decoded.is_err(), "{}", vector.name);
            }
            let token = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
            assert!(cose_verify(&token, &engine.verification_keys()).is_err());
            let error = engine
                .redeem(
                    &RedeemRequest {
                        token,
                        time_lock: TimeLockProof {
                            output: "AA".into(),
                        },
                        rendering: RenderingProof {
                            digest: "AA".into(),
                            backend: "css".into(),
                            css_commitment: None,
                        },
                        trust_blinded: None,
                    },
                    1_800_000_000,
                    [0; 16],
                )
                .unwrap_err();
            assert_eq!(error.code, "invalid_challenge", "{}", vector.name);
        }
        assert_eq!(counters.nonce.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(
            counters.pressure.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(counters.audit.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
    #[test]
    fn crypto_vector() {
        assert_eq!(
            conformance_values()["ed25519_public"],
            "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"
        );
        let s = SigningMaterial {
            key_id: vec![1, 2, 3, 4],
            seed: [7; 32],
        };
        let token = cose_sign(&[1, 2, 3], &s).unwrap();
        assert_eq!(
            cose_verify(
                &token,
                &[VerificationMaterial {
                    key_id: s.key_id,
                    public_key: public_from_seed(&s.seed)
                }]
            )
            .unwrap(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn direct_cose_signing_matches_generic_canonical_cbor_at_length_boundaries() {
        fn reference(payload: &[u8], material: &SigningMaterial) -> String {
            let protected = encode_cbor(&Cbor::Map(vec![
                (Cbor::Unsigned(1), Cbor::Negative(-8)),
                (Cbor::Unsigned(4), Cbor::Bytes(material.key_id.clone())),
            ]))
            .unwrap();
            let structure = encode_cbor(&Cbor::Array(vec![
                Cbor::Text("Signature1".into()),
                Cbor::Bytes(protected.clone()),
                Cbor::Bytes(vec![]),
                Cbor::Bytes(payload.to_vec()),
            ]))
            .unwrap();
            let signature = SigningKey::from_bytes(&material.seed)
                .sign(&structure)
                .to_bytes()
                .to_vec();
            let sign1 = encode_cbor(&Cbor::Array(vec![
                Cbor::Bytes(protected),
                Cbor::Map(vec![]),
                Cbor::Bytes(payload.to_vec()),
                Cbor::Bytes(signature),
            ]))
            .unwrap();
            format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(sign1))
        }

        for key_id_length in [0, 23, 24, 255, 256] {
            let material = SigningMaterial {
                key_id: vec![7; key_id_length],
                seed: [11; 32],
            };
            let signer = CoseSigner::new(&material).unwrap();
            for payload_length in [0, 23, 24, 255, 256, 4096] {
                let payload = vec![13; payload_length];
                assert_eq!(
                    signer.sign(&payload).unwrap(),
                    reference(&payload, &material)
                );
            }
        }
    }

    #[test]
    fn direct_challenge_encoding_matches_generic_canonical_map() {
        fn reference(c: &ChallengeClaims) -> Vec<u8> {
            let mut entries = vec![
                (0, t("challenge")),
                (1, t("shar-v1")),
                (2, t(&c.tenant)),
                (3, t(&c.site)),
                (4, t(&c.action)),
                (5, t(&c.origin)),
                (6, u(c.iat)),
                (7, u(c.exp)),
                (8, t(&c.policy)),
                (9, u(c.tier.into())),
                (10, u(c.iterations)),
                (11, u(c.rounds.into())),
                (12, Cbor::Bytes(c.nonce.to_vec())),
                (13, Cbor::Bytes(c.seed.to_vec())),
                (14, t(&c.modulus)),
                (16, u(c.triangles.into())),
                (17, u(c.samples.into())),
            ];
            if let Some(session) = &c.session {
                entries.push((15, t(session)));
            }
            if let Some(network) = &c.network_pseudonym {
                entries.push((19, t(network)));
            }
            if let Some(region) = &c.region {
                entries.push((20, t(region)));
            }
            if let Some(key_id) = &c.trust_key_id {
                entries.push((21, Cbor::Bytes(key_id.clone())));
            }
            encode_cbor(&Cbor::Map(
                entries
                    .into_iter()
                    .map(|(key, value)| (u(key), value))
                    .collect(),
            ))
            .unwrap()
        }

        let baseline = ChallengeClaims {
            tenant: "tenant".into(),
            site: "site".into(),
            action: "submit".into(),
            origin: "https://app.example".into(),
            region: None,
            iat: 1_900_000_000,
            exp: 1_900_000_120,
            policy: "policy-v1".into(),
            tier: 0,
            iterations: 1_024,
            rounds: 1,
            nonce: [3; 16],
            seed: [5; 32],
            modulus: "rsw-production-v1".into(),
            session: None,
            network_pseudonym: None,
            triangles: DEFAULT_RENDER_TRIANGLES,
            samples: DEFAULT_RENDER_SAMPLES,
            trust_key_id: None,
        };
        assert_eq!(encode_challenge(&baseline).unwrap(), reference(&baseline));

        let mut complete = baseline;
        complete.tenant = "t".repeat(24);
        complete.site = "s".repeat(256);
        complete.action = "a".repeat(23);
        complete.origin = format!("https://{}.example", "o".repeat(240));
        complete.region = Some("region-a".into());
        complete.session = Some("binding".repeat(32));
        complete.network_pseudonym = Some("network".repeat(16));
        complete.trust_key_id = Some(vec![9; 24]);
        complete.tier = 32;
        complete.iterations = u64::MAX;
        complete.rounds = u32::MAX;
        assert_eq!(encode_challenge(&complete).unwrap(), reference(&complete));
    }
    #[test]
    fn daily_network_pseudonym_vector() {
        assert_eq!(
            URL_SAFE_NO_PAD
                .encode(daily_network_pseudonym(&[5; 32], b"203.0.113.9", 1_800_000_000).unwrap()),
            "Ef3J3xx8_qDuqQkHDW3A_w"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(
                daily_network_pseudonym(
                    &[5; 32],
                    b"tenant-a\0site-a\x00203.0.113.9",
                    1_800_000_000
                )
                .unwrap()
            ),
            "HTtNSqJ2qefLMc6XeJXWgQ"
        );
    }
    #[test]
    fn site_verify_secret_vector_and_tamper_rejection() {
        let secret = derive_site_verify_secret(&[13; 32], "tenant-a", "site-a").unwrap();
        assert_eq!(
            secret,
            "shrs1_AQAIdGVuYW50LWEABnNpdGUtYcmPEinTIUA9EfB7rzqbMNpqjSG59aMCVJECR59QLoJX"
        );
        assert_eq!(
            verify_site_verify_secret(&[13; 32], &secret).unwrap(),
            Some(("tenant-a".into(), "site-a".into()))
        );
        let mut altered = secret;
        altered.pop();
        altered.push('A');
        assert_eq!(
            verify_site_verify_secret(&[13; 32], &altered).unwrap(),
            None
        );
    }
    #[test]
    fn timelock_input_vector_is_coprime() {
        let modulus = BigUint::from(1_000_036_000_099_u64);
        let input = derive_timelock_input(&[0; 16], &modulus);
        assert_eq!(input, BigUint::from(817_057_293_964_u64));
        assert!(coprime_timelock_candidate(&input, &modulus));
    }
    #[test]
    fn optimized_timelock_input_matches_reference_reduction_and_gcd() {
        fn reference(nonce: &[u8], modulus: &BigUint) -> BigUint {
            for counter in 0..=u32::MAX {
                let candidate = BigUint::from_bytes_be(&hash(&[
                    b"shar/rsw-v1/input\0",
                    nonce,
                    &counter.to_be_bytes(),
                ])) % modulus;
                if candidate > BigUint::from(1_u8) {
                    let mut a = candidate.clone();
                    let mut b = modulus.clone();
                    while b.bits() != 0 {
                        let next = &a % &b;
                        a = b;
                        b = next;
                    }
                    if a == BigUint::from(1_u8) {
                        return candidate;
                    }
                }
            }
            unreachable!("u32 counter space exhausted")
        }

        let moduli = [
            BigUint::from(5_u8),
            BigUint::from(6_u8),
            BigUint::from(17_u8),
            BigUint::from(1_000_u16),
            BigUint::from(1_000_036_000_099_u64),
            (BigUint::from(1_u8) << 2048_usize) - BigUint::from(159_u8),
        ];
        for modulus in moduli {
            for nonce in [[0_u8; 16], [7_u8; 16], [255_u8; 16]] {
                assert_eq!(
                    derive_timelock_input(&nonce, &modulus),
                    reference(&nonce, &modulus)
                );
            }
        }
    }
    #[test]
    fn pricing_caps_network() {
        let mut p = pressure();
        p.network_tier = 32;
        p.trust_credits = 32;
        let q = price_work(&p, &policy(), 100).unwrap();
        assert_eq!(q.tier, 4);
        assert_eq!(q.time_lock_iterations, "256");
    }
    #[test]
    fn default_policy_starts_at_exactly_two_minutes_and_does_not_cap_tier_32() {
        let now = 1_800_000_000;
        let baseline = price_work(&PressureInput::default(), &default_work_policy(), now).unwrap();
        assert_eq!(baseline.expires_at, now + 120);
        let maximum = price_work(
            &PressureInput {
                base_tier: 32,
                ..PressureInput::default()
            },
            &default_work_policy(),
            now,
        )
        .unwrap();
        assert_eq!(maximum.expires_at - now, 43_984_411);
        assert!(maximum.expires_at - now < default_work_policy().max_lifetime_seconds);
    }
    #[test]
    fn logarithmic_pressure_tiers_use_exact_integer_boundaries() {
        let cases = [
            (0, 0),
            (1, 0),
            (2, 1),
            (3, 2),
            (4, 2),
            (5, 3),
            (8, 3),
            (9, 4),
            (u64::MAX, 32),
        ];
        for (count, expected) in cases {
            assert_eq!(logarithmic_tier(count), expected, "count={count}");
        }
    }
    #[test]
    fn memory_pricing_atomically_reserves_concurrent_quotes() {
        let store = Arc::new(MemoryPressureStore::new(60).unwrap());
        let request = ChallengeRequest {
            tenant: "tenant-a".into(),
            site_key: "site-a".into(),
            action: "atomic".into(),
            origin: "https://app.example".into(),
            region: None,
            session_binding: None,
            network_pseudonym: None,
            assurance_tier: None,
            trust_token: None,
        };
        let mut work_policy = policy();
        work_policy.base_iterations = 1;
        work_policy.iteration_allowance = 1_000_000;
        work_policy.round_allowance_seconds = 0;
        let mut handles = Vec::new();
        for _ in 0..64 {
            let store = store.clone();
            let request = request.clone();
            let work_policy = work_policy.clone();
            handles.push(std::thread::spawn(move || {
                store
                    .price_and_record(&request, &work_policy, 1_800_000_000)
                    .unwrap()
                    .tier
            }));
        }
        let mut tiers: Vec<u8> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        tiers.sort_unstable();
        let expected: Vec<u8> = (1_u64..=64)
            .map(|count| logarithmic_tier(count) * 2)
            .collect();
        assert_eq!(tiers, expected);
    }
    #[test]
    fn pricing_keeps_render_rounds_inside_protocol_ceiling() {
        let mut work_policy = policy();
        work_policy.base_render_rounds = 257;
        let mut p = pressure();
        p.base_tier = 32;
        assert_eq!(price_work(&p, &work_policy, 100), Err("work overflow"));
    }
    #[test]
    fn pricing_rejects_overflow_instead_of_wrapping() {
        let mut p = pressure();
        p.base_tier = 1;
        let mut work_policy = policy();
        work_policy.base_iterations = 1_u64 << 63;
        assert_eq!(price_work(&p, &work_policy, 100), Err("work overflow"));
        assert_eq!(
            price_work(&pressure(), &policy(), u64::MAX),
            Err("time overflow")
        );
    }
    #[test]
    fn pricing_rejects_zero_base_lifetime() {
        let mut work_policy = policy();
        work_policy.base_lifetime_seconds = 0;
        assert_eq!(
            price_work(&pressure(), &work_policy, 100),
            Err("invalid policy")
        );
    }
    #[test]
    fn request_rejects_empty_optional_pressure_scopes() {
        let e = engine();
        let mut request = ChallengeRequest {
            tenant: "tenant-a".into(),
            site_key: "site-a".into(),
            action: "signup".into(),
            origin: "https://app.example".into(),
            region: None,
            session_binding: Some(String::new()),
            network_pseudonym: None,
            assurance_tier: None,
            trust_token: None,
        };
        assert_eq!(
            e.issue(&request, 100, [0; 16], [1; 32]).unwrap_err().code,
            "invalid_session_binding"
        );
        request.session_binding = None;
        request.network_pseudonym = Some(String::new());
        assert_eq!(
            e.issue(&request, 100, [0; 16], [1; 32]).unwrap_err().code,
            "invalid_network_pseudonym"
        );
    }
    #[test]
    fn request_text_bounds_match_language_neutral_utf8_vectors() {
        let document: BoundedTextDocument =
            serde_json::from_str(include_str!("../../../protocol/bounded-text-vectors.json"))
                .unwrap();
        assert_eq!(document.version, "bounded-text-v1");
        for vector in document.vectors {
            let mut request = ChallengeRequest {
                tenant: "tenant-a".into(),
                site_key: "site-a".into(),
                action: "signup".into(),
                origin: "https://app.example".into(),
                region: None,
                session_binding: None,
                network_pseudonym: None,
                assurance_tier: None,
                trust_token: None,
            };
            let value = vector.unit.repeat(vector.repetitions);
            match vector.field.as_str() {
                "tenant" => request.tenant = value,
                "action" => request.action = value,
                "region" => request.region = Some(value),
                "session_binding" => request.session_binding = Some(value),
                "network_pseudonym" => request.network_pseudonym = Some(value),
                field => panic!("unknown bounded text field {field}"),
            }
            let result = engine().issue(&request, 100, [0; 16], [1; 32]);
            if vector.valid {
                assert!(result.is_ok(), "{}", vector.name);
            } else {
                assert_eq!(
                    result.unwrap_err().code,
                    vector.error.as_deref().unwrap(),
                    "{}",
                    vector.name
                );
            }
        }
    }
    #[test]
    fn issue_applies_assurance_tier_before_pricing() {
        let e = engine();
        let request = ChallengeRequest {
            tenant: "tenant-a".into(),
            site_key: "site-a".into(),
            action: "signup".into(),
            origin: "https://app.example".into(),
            region: Some("au-mel-1".into()),
            session_binding: None,
            network_pseudonym: None,
            assurance_tier: Some(5),
            trust_token: None,
        };
        let challenge = e.issue(&request, 1_800_000_000, [0; 16], [1; 32]).unwrap();
        assert_eq!(challenge.quote.tier, 5);
        assert_eq!(challenge.quote.time_lock_iterations, "512");
    }

    #[test]
    fn trust_credit_flow_is_scoped_and_single_use() {
        let issuer = TrustKeyPair::from_seed(&[17; 32], &[7, 7, 7, 1]).unwrap();
        let e = engine().with_trust_keys(vec![issuer], 86_400).unwrap();
        let request = ChallengeRequest {
            tenant: "tenant-a".into(),
            site_key: "site-a".into(),
            action: "signup".into(),
            origin: "https://app.example".into(),
            region: None,
            session_binding: None,
            network_pseudonym: None,
            assurance_tier: None,
            trust_token: None,
        };
        let now = 1_800_000_000;
        let challenge = e.issue(&request, now, [0; 16], [1; 32]).unwrap();
        let TrustTokenPlan::Voprf {
            challenge_digest,
            key_id,
            public_key,
            issued_at,
            expires_at,
            ..
        } = challenge.trust.clone().expect("trust plan")
        else {
            panic!("trust plan disabled")
        };
        assert_eq!(issued_at, now);
        assert_eq!(expires_at, now + 86_400);
        let credit_nonce = [13; 32];
        let input = trust::trust_input_for_scope(
            "credit",
            &credit_nonce,
            &URL_SAFE_NO_PAD.decode(&challenge_digest).unwrap(),
            &URL_SAFE_NO_PAD.decode(&key_id).unwrap(),
            &TrustScope {
                tenant: &request.tenant,
                site_key: &request.site_key,
                action: &request.action,
                origin: &request.origin,
            },
        )
        .unwrap();
        let mut blind_rng = TrustRng::from_seed(&[9; 32]);
        let blind = TrustBlindState::blind(&input, &mut blind_rng).unwrap();
        let time_lock_input =
            BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&challenge.time_lock.input).unwrap());
        let iterations = challenge.time_lock.iterations.parse::<u64>().unwrap();
        let time_lock_output = solve_timelock(&time_lock_input, iterations, &e.time_lock.modulus);
        let rendering_digest = URL_SAFE_NO_PAD.encode(
            solve_rendering(
                &[1; 32],
                challenge.render.rounds,
                challenge.render.triangles,
                challenge.render.samples,
            )
            .unwrap(),
        );
        let verification_nonce = [2; 16];
        let redeemed = e
            .redeem(
                &RedeemRequest {
                    token: challenge.token,
                    time_lock: TimeLockProof {
                        output: URL_SAFE_NO_PAD.encode(time_lock_output.to_bytes_be()),
                    },
                    rendering: RenderingProof {
                        digest: rendering_digest,
                        backend: "css".into(),
                        css_commitment: None,
                    },
                    trust_blinded: Some(URL_SAFE_NO_PAD.encode(&blind.blinded)),
                },
                now + 1,
                verification_nonce,
            )
            .unwrap();
        let evaluation = redeemed.trust_evaluation.expect("trust evaluation");
        assert_eq!(evaluation.issued_at, issued_at);
        assert_eq!(evaluation.expires_at, expires_at);
        let output = blind
            .finalize(
                &input,
                &TrustEvaluation {
                    evaluated: URL_SAFE_NO_PAD.decode(evaluation.evaluated).unwrap(),
                    proof: URL_SAFE_NO_PAD.decode(evaluation.proof).unwrap(),
                },
                &URL_SAFE_NO_PAD.decode(public_key).unwrap(),
            )
            .unwrap();
        let credit = trust::encode_trust_credit_token(&trust::TrustCreditToken {
            key_id: URL_SAFE_NO_PAD.decode(key_id).unwrap(),
            challenge_nonce: credit_nonce.to_vec(),
            challenge_digest: URL_SAFE_NO_PAD.decode(challenge_digest).unwrap(),
            tenant: request.tenant.clone(),
            site_key: request.site_key.clone(),
            action: request.action.clone(),
            origin: request.origin.clone(),
            issued_at: evaluation.issued_at,
            expires_at: evaluation.expires_at,
            output,
        })
        .unwrap();
        let follow_up = e
            .issue(
                &ChallengeRequest {
                    trust_token: Some(credit.clone()),
                    ..request.clone()
                },
                now + 2,
                [3; 16],
                [4; 32],
            )
            .unwrap();
        assert!(follow_up.token.starts_with("shr1_"));
        assert_eq!(
            e.issue(
                &ChallengeRequest {
                    trust_token: Some(credit.clone()),
                    ..request.clone()
                },
                now + 3,
                [5; 16],
                [6; 32],
            )
            .unwrap_err()
            .code,
            "replayed_trust_token"
        );
        let mut rewrapped = trust::decode_trust_credit_token(&credit).unwrap();
        rewrapped.issued_at += 1;
        rewrapped.expires_at += 1;
        let rewrapped = trust::encode_trust_credit_token(&rewrapped).unwrap();
        assert_eq!(
            e.issue(
                &ChallengeRequest {
                    trust_token: Some(rewrapped),
                    ..request.clone()
                },
                now + 3,
                [7; 16],
                [8; 32],
            )
            .unwrap_err()
            .code,
            "invalid_trust_token"
        );
        let mut altered = request;
        altered.action = "other".into();
        altered.trust_token = Some(credit);
        assert_eq!(
            e.issue(&altered, now + 3, [9; 16], [10; 32])
                .unwrap_err()
                .code,
            "trust_binding_mismatch"
        );
        let optional = e
            .issue(
                &ChallengeRequest {
                    trust_token: None,
                    ..altered
                },
                now + 4,
                [11; 16],
                [12; 32],
            )
            .unwrap();
        let optional_input =
            BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&optional.time_lock.input).unwrap());
        let optional_iterations = optional.time_lock.iterations.parse::<u64>().unwrap();
        let optional_output =
            solve_timelock(&optional_input, optional_iterations, &e.time_lock.modulus);
        let optional_digest = URL_SAFE_NO_PAD.encode(
            solve_rendering(
                &[12; 32],
                optional.render.rounds,
                optional.render.triangles,
                optional.render.samples,
            )
            .unwrap(),
        );
        let honored = e
            .redeem(
                &RedeemRequest {
                    token: optional.token,
                    time_lock: TimeLockProof {
                        output: URL_SAFE_NO_PAD.encode(optional_output.to_bytes_be()),
                    },
                    rendering: RenderingProof {
                        digest: optional_digest,
                        backend: "css".into(),
                        css_commitment: None,
                    },
                    trust_blinded: Some(URL_SAFE_NO_PAD.encode([0xff; 32])),
                },
                now + 5,
                [13; 16],
            )
            .unwrap();
        assert!(honored.token.starts_with("shr1_"));
        assert!(honored.trust_evaluation.is_none());
    }
    #[test]
    fn memory_pressure_keeps_network_failures_out_of_session_debt() {
        let store = MemoryPressureStore::new(10).unwrap();
        let mut request = ChallengeRequest {
            tenant: "tenant".into(),
            site_key: "site".into(),
            action: "submit".into(),
            origin: "https://app.example".into(),
            region: None,
            session_binding: None,
            network_pseudonym: Some("daily-network-a".into()),
            assurance_tier: None,
            trust_token: None,
        };
        store.read(&request, 100, 10).unwrap();
        for _ in 0..32 {
            store
                .record_failure(&request, FailureKind::Invalid, 200, 101)
                .unwrap();
        }
        let pressured = store.read(&request, 102, 10).unwrap();
        assert_eq!(pressured.failure_debt, 0);
        assert_eq!(pressured.network_tier, 32);
        let mut outstanding_request = request.clone();
        outstanding_request.network_pseudonym = None;
        store.record_issued(&outstanding_request, 200, 102).unwrap();
        assert_eq!(
            store
                .read(&outstanding_request, 200, 10)
                .unwrap()
                .outstanding_tier,
            1
        );
        assert_eq!(
            store
                .read(&outstanding_request, 201, 10)
                .unwrap()
                .outstanding_tier,
            0
        );
        store.record_trust(&request, 103).unwrap();
        assert_eq!(store.read(&request, 103, 10).unwrap().network_tier, 32);
        request.network_pseudonym = Some("daily-network-b".into());
        assert_eq!(store.read(&request, 103, 10).unwrap().network_tier, 0);
        request.network_pseudonym = Some("daily-network-a".into());
        request.session_binding = Some("host-session".into());
        store
            .record_failure(&request, FailureKind::Invalid, 200, 103)
            .unwrap();
        assert_eq!(store.read(&request, 104, 10).unwrap().failure_debt, 1);
    }
    #[test]
    fn memory_pressure_removes_the_completed_quotes_exact_expiry() {
        let store = MemoryPressureStore::new(60).unwrap();
        let request = ChallengeRequest {
            tenant: "tenant".into(),
            site_key: "site".into(),
            action: "submit".into(),
            origin: "https://app.example".into(),
            region: None,
            session_binding: Some("session".into()),
            network_pseudonym: None,
            assurance_tier: None,
            trust_token: None,
        };
        store.record_issued(&request, 150, 100).unwrap();
        store.record_issued(&request, 300, 101).unwrap();
        store.record_success(&request, 300, 110).unwrap();
        assert_eq!(store.read(&request, 151, 60).unwrap().outstanding_tier, 0);

        store.record_issued(&request, 300, 200).unwrap();
        store.record_issued(&request, 250, 201).unwrap();
        store
            .record_failure(&request, FailureKind::Expired, 250, 251)
            .unwrap();
        assert_eq!(store.read(&request, 251, 60).unwrap().outstanding_tier, 1);
    }
    #[test]
    fn render_vector_stable() {
        assert_eq!(
            conformance_values()["render_digest"],
            "XBnikgSO8AzOfMrpg1EDZH46vjjovkkGRA9MmiQv7_A"
        );
        assert_eq!(
            css_transcript_commitment(&RenderingProofPlan {
                version: "render-v1".into(),
                seed: URL_SAFE_NO_PAD.encode([0; 32]),
                rounds: 2,
                triangles: 8,
                samples: 16,
            })
            .unwrap(),
            "amIKy6SKVrc5Vi4HgSJBTCZCpLF_B6Z9ahgvpTRVDoA"
        );
        let program = create_triangle_program(&[3; 32], 8, 16).unwrap();
        let selections = select_triangles(&program);
        assert_eq!(
            reduce_triangle_selections(&selections).unwrap(),
            evaluate_triangle_program(&program)
        );
        assert_eq!(reduce_triangle_selections(&[]), Err("render bounds"));
    }
    #[test]
    fn default_rendering_work_is_bounded_and_million_scale() {
        assert_eq!(DEFAULT_RENDER_PREDICATES, 1_048_576);
        let challenge = engine()
            .challenge(
                &ChallengeRequest {
                    tenant: "tenant".into(),
                    site_key: "site".into(),
                    action: "submit".into(),
                    origin: "https://app.example".into(),
                    region: None,
                    session_binding: None,
                    network_pseudonym: None,
                    assurance_tier: None,
                    trust_token: None,
                },
                &pressure(),
                1_800_000_000,
                [0; 16],
                [0; 32],
            )
            .unwrap();
        assert_eq!(challenge.render.triangles, DEFAULT_RENDER_TRIANGLES);
        assert_eq!(challenge.render.samples, DEFAULT_RENDER_SAMPLES);
    }
    #[test]
    fn render_vectors_match_the_language_neutral_css_transcript() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../protocol/render-v1-vectors.json")).unwrap();
        for vector in vectors["cases"].as_array().unwrap() {
            let seed = URL_SAFE_NO_PAD
                .decode(vector["seed"].as_str().unwrap())
                .unwrap();
            let expected_words: Vec<u32> = vector["transcript_words"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_u64().unwrap() as u32)
                .collect();
            assert_eq!(
                derive_canonical_css_transcript(&seed)
                    .unwrap()
                    .words()
                    .as_slice(),
                expected_words,
                "{}",
                vector["name"].as_str().unwrap()
            );
            let plan = RenderingProofPlan {
                version: "render-v1".into(),
                seed: vector["seed"].as_str().unwrap().into(),
                rounds: vector["rounds"].as_u64().unwrap() as u32,
                triangles: vector["triangles"].as_u64().unwrap() as u32,
                samples: vector["samples"].as_u64().unwrap() as u32,
            };
            assert_eq!(
                URL_SAFE_NO_PAD.encode(
                    solve_rendering(&seed, plan.rounds, plan.triangles, plan.samples).unwrap()
                ),
                vector["digest"].as_str().unwrap()
            );
            assert_eq!(
                css_transcript_commitment(&plan).unwrap(),
                vector["css_commitment"].as_str().unwrap()
            );
        }
    }
    #[test]
    fn immutable_quote_and_replay() {
        let e = engine();
        let req = ChallengeRequest {
            tenant: "tenant-a".into(),
            site_key: "site-a".into(),
            action: "signup".into(),
            origin: "https://app.example".into(),
            region: Some("au-mel-1".into()),
            session_binding: None,
            network_pseudonym: None,
            assurance_tier: None,
            trust_token: None,
        };
        let c = e
            .challenge(&req, &pressure(), 1_800_000_000, [0; 16], [1; 32])
            .unwrap();
        assert_eq!(c.region.as_deref(), Some("au-mel-1"));
        let input = BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&c.time_lock.input).unwrap());
        let iterations = c.time_lock.iterations.parse().unwrap();
        let tl = solve_timelock(&input, iterations, &e.time_lock.modulus);
        let rr = URL_SAFE_NO_PAD.encode(
            solve_rendering(
                &[1; 32],
                c.render.rounds,
                c.render.triangles,
                c.render.samples,
            )
            .unwrap(),
        );
        let mut request = RedeemRequest {
            token: c.token,
            time_lock: TimeLockProof {
                output: URL_SAFE_NO_PAD.encode(tl.to_bytes_be()),
            },
            rendering: RenderingProof {
                digest: rr,
                backend: "css".into(),
                css_commitment: None,
            },
            trust_blinded: None,
        };
        let mut malformed_commitment = request.clone();
        malformed_commitment.rendering.css_commitment = Some(CssTranscriptCommitment {
            version: "css-transcript-v1".into(),
            digest: "malformed".into(),
        });
        assert_eq!(
            e.redeem(&malformed_commitment, c.quote.expires_at, [9; 16])
                .unwrap_err()
                .code,
            "invalid_work"
        );
        request.rendering.css_commitment = Some(CssTranscriptCommitment {
            version: "css-transcript-v1".into(),
            digest: URL_SAFE_NO_PAD.encode([0; 32]),
        });
        assert_eq!(
            e.redeem(&request, c.quote.expires_at, [9; 16])
                .unwrap_err()
                .code,
            "invalid_work"
        );
        request.rendering.css_commitment = Some(CssTranscriptCommitment {
            version: "css-transcript-v1".into(),
            digest: css_transcript_commitment(&c.render).unwrap(),
        });
        // The signed expiry is inclusive; the exact boundary remains valid.
        let redeemed = e.redeem(&request, c.quote.expires_at, [2; 16]).unwrap();
        assert_eq!(redeemed.receipt.tier, 0);
        assert_eq!(
            e.redeem(&request, 1_800_000_001, [3; 16]).unwrap_err().code,
            "replayed_challenge"
        );
        let v = SiteVerifyRequest {
            token: redeemed.token,
            tenant: None,
            site_key: None,
            action: Some("signup".into()),
            origin: None,
            region: Some("au-mel-1".into()),
            session_binding: None,
        };
        let verified = e.siteverify(&v, 1_800_000_002).unwrap();
        assert!(verified.success);
        assert_eq!(verified.region.as_deref(), Some("au-mel-1"));
        assert_eq!(
            e.siteverify(&v, 1_800_000_002).unwrap_err().code,
            "replayed_verification"
        );
    }
    #[test]
    fn complete_challenge_envelope_vector() {
        let e = engine().with_render_work(24, 64).unwrap();
        let request = ChallengeRequest {
            tenant: "tenant-a".into(),
            site_key: "site-a".into(),
            action: "signup".into(),
            origin: "https://app.example".into(),
            region: None,
            session_binding: None,
            network_pseudonym: None,
            assurance_tier: None,
            trust_token: None,
        };
        let challenge = e
            .challenge(&request, &pressure(), 1_800_000_000, [0; 16], [1; 32])
            .unwrap();
        assert_eq!(
            challenge.token,
            "shr1_hEmiAScERAkJCQGgWKuxAGljaGFsbGVuZ2UBZ3NoYXItdjECaHRlbmFudC1hA2ZzaXRlLWEEZnNpZ251cAVzaHR0cHM6Ly9hcHAuZXhhbXBsZQYaa0nSAAcaa0nSeAhucG9saWN5LXRlc3QtdjEJAAoQCwEMUAAAAAAAAAAAAAAAAAAAAAANWCABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ5odGVzdC1yc3cQGBgRGEBYQPDsYCzP1bKKSa_GLMn2Y2EhJpJfpVEllXqdjPgS8WFs1DqUyi3KTpt6oxEBNMfC_pO85_lY3KUY8kwxHdFP6gA"
        );
    }
    #[test]
    fn overlapping_keys_honor_pre_rotation_challenges() {
        let old = engine();
        let request = ChallengeRequest {
            tenant: "tenant-a".into(),
            site_key: "site-a".into(),
            action: "signup".into(),
            origin: "https://app.example".into(),
            region: None,
            session_binding: None,
            network_pseudonym: None,
            assurance_tier: None,
            trust_token: None,
        };
        let challenge = old
            .challenge(&request, &pressure(), 1_800_000_000, [0; 16], [1; 32])
            .unwrap();
        let input =
            BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&challenge.time_lock.input).unwrap());
        let output = solve_timelock(&input, 16, &old.time_lock.modulus);
        let digest = URL_SAFE_NO_PAD.encode(
            solve_rendering(
                &[1; 32],
                challenge.render.rounds,
                challenge.render.triangles,
                challenge.render.samples,
            )
            .unwrap(),
        );
        let p = policy();
        let pressure_store = Arc::new(MemoryPressureStore::new(p.quiet_window_seconds).unwrap());
        let old_time_lock = old.time_lock.clone();
        let rotated = Engine::with_stores_and_rotation(
            SigningMaterial {
                key_id: vec![2],
                seed: [8; 32],
            },
            TimeLockKey {
                id: "new-rsw".into(),
                modulus: BigUint::from(1_000_037_u64) * BigUint::from(1_000_039_u64),
                lambda: BigUint::from(500_037_000_684_u64),
            },
            p.clone(),
            Arc::new(MemoryNonceStore::default()),
            pressure_store,
            Arc::new(StaticConfigStore(p)),
            vec![VerificationMaterial {
                key_id: vec![9, 9, 9, 1],
                public_key: public_from_seed(&[7; 32]),
            }],
            vec![old_time_lock],
        );
        let redeemed = rotated
            .redeem(
                &RedeemRequest {
                    token: challenge.token,
                    time_lock: TimeLockProof {
                        output: URL_SAFE_NO_PAD.encode(output.to_bytes_be()),
                    },
                    rendering: RenderingProof {
                        digest,
                        backend: "css".into(),
                        css_commitment: None,
                    },
                    trust_blinded: None,
                },
                1_800_000_001,
                [2; 16],
            )
            .unwrap();
        assert_eq!(redeemed.receipt.tier, 0);
        assert_eq!(rotated.verification_keys().len(), 2);
        assert_eq!(rotated.time_lock_ids(), vec!["new-rsw", "test-rsw"]);
    }

    #[test]
    fn public_plan_and_provider_contracts_match_the_language_neutral_api() {
        assert_eq!(
            serde_json::to_value(RenderingProofPlan {
                version: "render-v1".into(),
                seed: "seed".into(),
                rounds: 2,
                triangles: 24,
                samples: 64,
            })
            .unwrap(),
            serde_json::json!({"version":"render-v1","seed":"seed","rounds":2,"triangles":24,"samples":64})
        );
        assert_eq!(
            serde_json::to_value(RenderingProof {
                digest: "digest".into(),
                backend: "css".into(),
                css_commitment: Some(CssTranscriptCommitment {
                    version: "css-transcript-v1".into(),
                    digest: "transcript".into(),
                }),
            })
            .unwrap(),
            serde_json::json!({"digest":"digest","backend":"css","css_commitment":{"version":"css-transcript-v1","digest":"transcript"}})
        );
        assert_eq!(
            serde_json::to_value(derive_canonical_css_transcript(&[0; 32]).unwrap()).unwrap(),
            serde_json::json!({
                "version":"css-transcript-v1",
                "chainWidth":64,
                "layoutHeight":48,
                "gridFirstWidth":16,
                "gridSecondWidth":48,
                "flexFirstWidth":4,
                "flexSecondWidth":12,
                "intrinsicWidth":8,
                "queryBranch":12,
                "styleBranch":12,
                "nestedBranch":1,
                "transformX":4,
                "transformY":4,
                "verticalWriting":0,
                "hitId":1,
                "topologyDepth":3
            })
        );
        assert_eq!(
            serde_json::to_value(PresencePlan::Host).unwrap(),
            serde_json::json!({"mode":"host"})
        );
        assert_eq!(
            serde_json::to_value(RenderingBackend::Webgl2).unwrap(),
            serde_json::json!("webgl2")
        );
        assert_eq!(
            serde_json::to_value(FallbackPlan {
                available: true,
                methods: vec!["passkey".into(), "email".into()],
            })
            .unwrap(),
            serde_json::json!({"available":true,"methods":["passkey","email"]})
        );
        assert_eq!(
            create_triangle_program(&[1; 32], 1, 1).unwrap().version,
            "render-v1"
        );
        assert!(engine().with_render_work(512, 4_096).is_ok());
        assert!(engine().with_render_work(513, 4_096).is_err());
        assert!(engine().with_render_work(512, 4_097).is_err());
        assert!(
            engine()
                .with_browser_plans(
                    PresencePlan::Host,
                    FallbackPlan {
                        available: true,
                        methods: vec!["email".into(), "email".into()],
                    },
                )
                .is_err()
        );
        let planned = engine()
            .with_browser_plans(
                PresencePlan::Host,
                FallbackPlan {
                    available: true,
                    methods: vec!["passkey".into(), "support".into()],
                },
            )
            .unwrap();
        let challenge = planned
            .challenge(
                &ChallengeRequest {
                    tenant: "tenant".into(),
                    site_key: "site".into(),
                    action: "submit".into(),
                    origin: "https://example.test".into(),
                    region: None,
                    session_binding: None,
                    network_pseudonym: None,
                    assurance_tier: None,
                    trust_token: None,
                },
                &pressure(),
                1_800_000_000,
                [1; 16],
                [2; 32],
            )
            .unwrap();
        assert_eq!(challenge.presence, PresencePlan::Host);
        assert_eq!(
            challenge.fallback,
            FallbackPlan {
                available: true,
                methods: vec!["passkey".into(), "support".into()],
            }
        );
    }

    #[test]
    fn host_providers_price_only_new_quotes_and_verify_fallback_before_nonce_use() {
        use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

        struct Signals {
            mode: AtomicU8,
            calls: AtomicUsize,
        }
        impl SignalProvider for Signals {
            fn health(&self) -> Result<(), StoreError> {
                if self.mode.load(Ordering::Relaxed) == u8::MAX {
                    Err(StoreError)
                } else {
                    Ok(())
                }
            }

            fn assurance_tier(&self, _request: &ChallengeRequest) -> Result<u8, StoreError> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                match self.mode.load(Ordering::Relaxed) {
                    u8::MAX => Err(StoreError),
                    tier => Ok(tier),
                }
            }
        }
        struct Fallback {
            // 0 rejects, 1 accepts, and 2 represents an unavailable host.
            mode: AtomicU8,
        }
        impl FallbackVerifier for Fallback {
            fn health(&self) -> Result<(), StoreError> {
                if self.mode.load(Ordering::Relaxed) == 2 {
                    Err(StoreError)
                } else {
                    Ok(())
                }
            }

            fn verify(
                &self,
                method: &str,
                payload: &serde_json::Value,
            ) -> Result<bool, StoreError> {
                assert_eq!(method, "passkey");
                assert!(
                    payload["assertion_id"]
                        .as_str()
                        .is_some_and(|value| value.starts_with("host-assertion-"))
                );
                match self.mode.load(Ordering::Relaxed) {
                    0 => Ok(false),
                    1 => Ok(true),
                    _ => Err(StoreError),
                }
            }
        }

        let signals = Arc::new(Signals {
            mode: AtomicU8::new(7),
            calls: AtomicUsize::new(0),
        });
        let fallback = Arc::new(Fallback {
            mode: AtomicU8::new(0),
        });
        let e = engine()
            .with_render_work(8, 16)
            .unwrap()
            .with_browser_plans(
                PresencePlan::Host,
                FallbackPlan {
                    available: true,
                    methods: vec!["passkey".into()],
                },
            )
            .unwrap()
            .with_signal_provider(signals.clone())
            .with_fallback_verifier(fallback.clone());
        let request = ChallengeRequest {
            tenant: "tenant".into(),
            site_key: "site".into(),
            action: "submit".into(),
            origin: "https://app.example".into(),
            region: None,
            session_binding: None,
            network_pseudonym: None,
            assurance_tier: None,
            trust_token: None,
        };
        let disabled = FallbackCompletionRequest {
            tenant: request.tenant.clone(),
            site_key: request.site_key.clone(),
            action: request.action.clone(),
            origin: request.origin.clone(),
            region: None,
            method: "passkey".into(),
            assertion_id: "host-assertion-disabled-0001".into(),
            session_binding: None,
        };
        let disabled_error = engine()
            .complete_fallback(&disabled, 1_800_000_000)
            .unwrap_err();
        assert_eq!(disabled_error.status, 501);
        assert_eq!(disabled_error.code, "fallback_not_configured");
        assert!(!disabled_error.retryable);
        assert_eq!(disabled_error.next_action, "fallback");
        let challenge = e.issue(&request, 1_800_000_000, [1; 16], [2; 32]).unwrap();
        assert_eq!(challenge.quote.tier, 7);
        assert_eq!(signals.calls.load(Ordering::Relaxed), 1);

        // Provider failure after issuance cannot alter the signed quote or a
        // correct proof's validity.
        signals.mode.store(u8::MAX, Ordering::Relaxed);
        assert_eq!(e.ready().unwrap_err().code, "readiness_unavailable");
        let time_lock_input =
            BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&challenge.time_lock.input).unwrap());
        let time_lock_output = solve_timelock(
            &time_lock_input,
            challenge.time_lock.iterations.parse().unwrap(),
            &e.time_lock.modulus,
        );
        let rendering_digest = URL_SAFE_NO_PAD.encode(
            solve_rendering(
                &[2; 32],
                challenge.render.rounds,
                challenge.render.triangles,
                challenge.render.samples,
            )
            .unwrap(),
        );
        let redeemed = e
            .redeem(
                &RedeemRequest {
                    token: challenge.token,
                    time_lock: TimeLockProof {
                        output: URL_SAFE_NO_PAD.encode(time_lock_output.to_bytes_be()),
                    },
                    rendering: RenderingProof {
                        digest: rendering_digest,
                        backend: "css".into(),
                        css_commitment: None,
                    },
                    trust_blinded: None,
                },
                1_800_000_001,
                [3; 16],
            )
            .unwrap();
        assert_eq!(redeemed.receipt.tier, 7);
        assert_eq!(signals.calls.load(Ordering::Relaxed), 1);
        signals.mode.store(7, Ordering::Relaxed);
        assert!(e.ready().is_ok());

        let completion = FallbackCompletionRequest {
            tenant: request.tenant.clone(),
            site_key: request.site_key.clone(),
            action: request.action.clone(),
            origin: request.origin.clone(),
            region: None,
            method: "passkey".into(),
            assertion_id: "host-assertion-provider-0001".into(),
            session_binding: None,
        };
        let rejected = e.complete_fallback(&completion, 1_800_000_002).unwrap_err();
        assert_eq!(rejected.code, "fallback_not_verified");
        assert_eq!(rejected.next_action, "fallback");
        fallback.mode.store(1, Ordering::Relaxed);
        assert!(
            e.complete_fallback(&completion, 1_800_000_002)
                .unwrap()
                .success
        );
        assert_eq!(
            e.complete_fallback(&completion, 1_800_000_002)
                .unwrap_err()
                .code,
            "replayed_fallback_assertion"
        );

        let mut retryable = completion.clone();
        retryable.assertion_id = "host-assertion-provider-0002".into();
        fallback.mode.store(2, Ordering::Relaxed);
        assert_eq!(e.ready().unwrap_err().code, "readiness_unavailable");
        let unavailable = e.complete_fallback(&retryable, 1_800_000_003).unwrap_err();
        assert_eq!(unavailable.code, "fallback_unavailable");
        assert!(unavailable.retryable);
        assert_eq!(unavailable.retry_after, Some(1));
        fallback.mode.store(1, Ordering::Relaxed);
        assert!(
            e.complete_fallback(&retryable, 1_800_000_003)
                .unwrap()
                .success
        );
        assert!(e.ready().is_ok());
    }

    #[test]
    fn host_provider_behavior_matches_language_neutral_vectors() {
        use std::sync::atomic::{AtomicU8, Ordering};

        let document: serde_json::Value =
            serde_json::from_str(include_str!("../../../protocol/host-provider-vectors.json"))
                .unwrap();
        assert_eq!(document["schema"], "shar-host-provider-vectors-v1");

        struct Signals(u8);
        impl SignalProvider for Signals {
            fn assurance_tier(&self, _request: &ChallengeRequest) -> Result<u8, StoreError> {
                if self.0 == u8::MAX {
                    Err(StoreError)
                } else {
                    Ok(self.0)
                }
            }
        }
        for vector in document["signals"].as_array().unwrap() {
            let p = policy();
            let counters = Arc::new(MutationCounters::default());
            let provider_outcome = vector["provider"]["outcome"].as_str().unwrap();
            let provider_tier = if provider_outcome == "unavailable" {
                u8::MAX
            } else {
                vector["provider"]["tier"].as_u64().unwrap() as u8
            };
            let e = Engine::with_stores(
                SigningMaterial {
                    key_id: vec![9, 9, 9, 1],
                    seed: [7; 32],
                },
                TimeLockKey {
                    id: "test-rsw".into(),
                    modulus: BigUint::from(1_000_003_u64) * BigUint::from(1_000_033_u64),
                    lambda: BigUint::from(166_672_333_344_u64),
                },
                p.clone(),
                Arc::new(MemoryNonceStore::default()),
                Arc::new(CountingPressureStore(counters.clone())),
                Arc::new(StaticConfigStore(p)),
            )
            .with_signal_provider(Arc::new(Signals(provider_tier)));
            let request = ChallengeRequest {
                tenant: "tenant".into(),
                site_key: "site".into(),
                action: "submit".into(),
                origin: "https://app.example".into(),
                region: None,
                session_binding: None,
                network_pseudonym: None,
                assurance_tier: vector["request_assurance_tier"]
                    .as_u64()
                    .map(|tier| tier as u8),
                trust_token: None,
            };
            if vector["result"]["outcome"] == "quote" {
                let quote = e
                    .issue(&request, 1_800_000_000, [1; 16], [2; 32])
                    .unwrap()
                    .quote;
                assert_eq!(quote.tier, vector["result"]["tier"].as_u64().unwrap() as u8);
                assert_eq!(counters.pressure.load(Ordering::Relaxed), 1);
            } else {
                let error = e
                    .issue(&request, 1_800_000_000, [1; 16], [2; 32])
                    .unwrap_err();
                assert_eq!(error.code, vector["result"]["code"].as_str().unwrap());
                assert_eq!(error.retryable, vector["result"]["retryable"]);
                assert_eq!(
                    error.next_action,
                    vector["result"]["next_action"].as_str().unwrap()
                );
                assert_eq!(error.retry_after, vector["result"]["retry_after"].as_u64());
                assert_eq!(
                    counters.pressure.load(Ordering::Relaxed),
                    vector["result"]["pricing_mutations"].as_u64().unwrap() as usize
                );
            }
        }

        struct Fallback(AtomicU8);
        impl FallbackVerifier for Fallback {
            fn verify(
                &self,
                _method: &str,
                _payload: &serde_json::Value,
            ) -> Result<bool, StoreError> {
                match self.0.load(Ordering::Relaxed) {
                    0 => Ok(false),
                    1 => Ok(true),
                    _ => Err(StoreError),
                }
            }
        }
        for (index, vector) in document["fallback"].as_array().unwrap().iter().enumerate() {
            let mode = match vector["provider"]["outcome"].as_str().unwrap() {
                "accepted" => 1,
                "rejected" => 0,
                _ => 2,
            };
            let verifier = Arc::new(Fallback(AtomicU8::new(mode)));
            let e = engine()
                .with_browser_plans(
                    PresencePlan::Host,
                    FallbackPlan {
                        available: true,
                        methods: vec!["passkey".into()],
                    },
                )
                .unwrap()
                .with_fallback_verifier(verifier.clone());
            let request = FallbackCompletionRequest {
                tenant: "tenant".into(),
                site_key: "site".into(),
                action: "submit".into(),
                origin: "https://app.example".into(),
                region: None,
                method: "passkey".into(),
                assertion_id: format!("host-assertion-vector-{index:04}"),
                session_binding: None,
            };
            if vector["result"]["outcome"] == "success" {
                assert!(
                    e.complete_fallback(&request, 1_800_000_000)
                        .unwrap()
                        .success
                );
                assert_eq!(
                    e.complete_fallback(&request, 1_800_000_000)
                        .unwrap_err()
                        .code,
                    "replayed_fallback_assertion"
                );
            } else {
                let error = e.complete_fallback(&request, 1_800_000_000).unwrap_err();
                assert_eq!(error.code, vector["result"]["code"].as_str().unwrap());
                assert_eq!(error.retryable, vector["result"]["retryable"]);
                assert_eq!(
                    error.next_action,
                    vector["result"]["next_action"].as_str().unwrap()
                );
                assert_eq!(error.retry_after, vector["result"]["retry_after"].as_u64());
                verifier.0.store(1, Ordering::Relaxed);
                assert!(
                    e.complete_fallback(&request, 1_800_000_000)
                        .unwrap()
                        .success
                );
            }
        }
    }

    #[test]
    fn stored_fallback_assertions_match_language_neutral_vectors() {
        struct Assertions(Option<StoredFallbackAssertion>);
        impl FallbackAssertionStore for Assertions {
            fn find(
                &self,
                assertion_id: &str,
            ) -> Result<Option<StoredFallbackAssertion>, StoreError> {
                assert_eq!(assertion_id, "host-assertion-stored-0001");
                Ok(self.0.clone())
            }
        }

        let document: serde_json::Value = serde_json::from_str(include_str!(
            "../../../protocol/fallback-assertion-vectors.json"
        ))
        .unwrap();
        assert_eq!(document["schema"], "shar-fallback-assertion-vectors-v1");
        let now = document["now"].as_u64().unwrap();
        let request: FallbackCompletionRequest =
            serde_json::from_value(document["request"].clone()).unwrap();
        let payload = serde_json::to_value(&request).unwrap();
        for vector in document["vectors"].as_array().unwrap() {
            let record = if vector["missing"].as_bool() == Some(true) {
                None
            } else {
                let mut value = document["assertion"].clone();
                if let Some(overrides) = vector["overrides"].as_object() {
                    let target = value.as_object_mut().unwrap();
                    for (key, override_value) in overrides {
                        target.insert(key.clone(), override_value.clone());
                    }
                }
                Some(serde_json::from_value(value).unwrap())
            };
            let verifier =
                StoredFallbackVerifier::with_clock(Arc::new(Assertions(record)), move || Ok(now));
            let result = verifier.verify(&request.method, &payload);
            match vector["result"].as_str().unwrap() {
                "accepted" => assert!(result.unwrap(), "{}", vector["name"]),
                "rejected" => assert!(!result.unwrap(), "{}", vector["name"]),
                "unavailable" => assert!(result.is_err(), "{}", vector["name"]),
                _ => panic!("unknown vector result"),
            }
        }

        let assertion: StoredFallbackAssertion =
            serde_json::from_value(document["assertion"].clone()).unwrap();
        let verifier = Arc::new(StoredFallbackVerifier::with_clock(
            Arc::new(Assertions(Some(assertion))),
            move || Ok(now),
        ));
        let engine = engine()
            .with_browser_plans(
                PresencePlan::Host,
                FallbackPlan {
                    available: true,
                    methods: vec![request.method.clone()],
                },
            )
            .unwrap()
            .with_fallback_verifier(verifier);
        assert!(engine.complete_fallback(&request, now).unwrap().success);
        assert_eq!(
            engine.complete_fallback(&request, now).unwrap_err().code,
            "replayed_fallback_assertion"
        );
    }
}
