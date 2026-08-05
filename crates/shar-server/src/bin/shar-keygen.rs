#![forbid(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use rand::{RngCore, rngs::OsRng};
use serde_json::json;
use sha2::{Digest, Sha256};
use shar_core::{derive_site_verify_secret, public_from_seed};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{collections::HashMap, env, ffi::OsString, fs::OpenOptions, io::Write, path::PathBuf};

fn main() {
    if let Err(message) = run() {
        eprintln!("{message}");
        std::process::exit(64)
    }
}
fn run() -> Result<(), String> {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    if arguments.first().and_then(|value| value.to_str()) == Some("site-secret") {
        return site_secret(&arguments[1..]);
    }
    if arguments.first().and_then(|value| value.to_str()) == Some("rotate") {
        return rotate(&arguments[1..]);
    }
    let mut args = arguments.into_iter();
    let flag = args.next().ok_or("usage: shar-keygen --output PATH")?;
    if flag != "--output" {
        return Err("usage: shar-keygen --output PATH".into());
    }
    let path = PathBuf::from(args.next().ok_or("usage: shar-keygen --output PATH")?);
    if args.next().is_some() {
        return Err("usage: shar-keygen --output PATH".into());
    }
    eprintln!("generating a 2048-bit RSW modulus; this can take a while");
    let mut rng = OsRng;
    let p = generate_prime(1024, &mut rng);
    let (mut q, mut modulus);
    loop {
        q = generate_prime(1024, &mut rng);
        modulus = &p * &q;
        if q != p && modulus.bits() == 2048 {
            break;
        }
    }
    let lambda = (p - BigUint::from(1_u8)).lcm(&(q - BigUint::from(1_u8)));
    let mut signing_seed = [0; 32];
    let mut key_id = [0; 8];
    let mut network_secret = [0; 32];
    let mut fallback_secret = [0; 32];
    let mut admin_secret = [0; 32];
    let mut siteverify_master_secret = [0; 32];
    let mut trust_seed = [0; 32];
    let mut trust_key_id = [0; 8];
    rng.fill_bytes(&mut signing_seed);
    rng.fill_bytes(&mut key_id);
    rng.fill_bytes(&mut network_secret);
    rng.fill_bytes(&mut fallback_secret);
    rng.fill_bytes(&mut admin_secret);
    rng.fill_bytes(&mut siteverify_master_secret);
    rng.fill_bytes(&mut trust_seed);
    rng.fill_bytes(&mut trust_key_id);
    let modulus_bytes = modulus.to_bytes_be();
    let digest = Sha256::digest(&modulus_bytes);
    let document = json!({"SHAR_SIGNING_SEED":URL_SAFE_NO_PAD.encode(signing_seed),"SHAR_KEY_ID":URL_SAFE_NO_PAD.encode(key_id),"SHAR_RSW_MODULUS":URL_SAFE_NO_PAD.encode(&modulus_bytes),"SHAR_RSW_LAMBDA":URL_SAFE_NO_PAD.encode(lambda.to_bytes_be()),"SHAR_RSW_ID":format!("rsw-{}",URL_SAFE_NO_PAD.encode(&digest[..12])),"SHAR_NETWORK_SECRET":URL_SAFE_NO_PAD.encode(network_secret),"SHAR_FALLBACK_SECRET":URL_SAFE_NO_PAD.encode(fallback_secret),"SHAR_ADMIN_SECRET":URL_SAFE_NO_PAD.encode(admin_secret),"SHAR_SITEVERIFY_MASTER_SECRET":URL_SAFE_NO_PAD.encode(siteverify_master_secret),"SHAR_TRUST_SEED":URL_SAFE_NO_PAD.encode(trust_seed),"SHAR_TRUST_KEY_ID":URL_SAFE_NO_PAD.encode(trust_key_id)});
    write_document(&path, &document)?;
    eprintln!("wrote new protected key material to {}", path.display());
    Ok(())
}

fn rotate(arguments: &[OsString]) -> Result<(), String> {
    const USAGE: &str = "usage: shar-keygen rotate --input OLD_PATH --output NEW_PATH";
    let values = parse_flags(arguments, &["--input", "--output"], USAGE)?;
    let input = PathBuf::from(values.get("--input").ok_or(USAGE)?);
    let output = PathBuf::from(values.get("--output").ok_or(USAGE)?);
    let old = read_document(&input)?;
    let old_seed = decode_exact::<32>(required(&old, "SHAR_SIGNING_SEED")?, "SHAR_SIGNING_SEED")?;
    let old_key_id = required(&old, "SHAR_KEY_ID")?.to_owned();
    let old_key_id_bytes = decode_bytes(&old_key_id, "SHAR_KEY_ID")?;
    let old_public = public_from_seed(&old_seed);
    let old_modulus = decode_bytes(required(&old, "SHAR_RSW_MODULUS")?, "SHAR_RSW_MODULUS")?;
    let old_lambda = decode_bytes(required(&old, "SHAR_RSW_LAMBDA")?, "SHAR_RSW_LAMBDA")?;
    let old_modulus_value = BigUint::from_bytes_be(&old_modulus);
    let old_lambda_value = BigUint::from_bytes_be(&old_lambda);
    let old_rsw_id = required(&old, "SHAR_RSW_ID")?.to_owned();
    let old_trust_seed = old.get("SHAR_TRUST_SEED").cloned();
    let old_trust_key_id = old.get("SHAR_TRUST_KEY_ID").cloned();
    if old_trust_seed.is_some() != old_trust_key_id.is_some() {
        return Err("old key file must contain both SHAR_TRUST_SEED and SHAR_TRUST_KEY_ID".into());
    }
    if let (Some(seed), Some(key_id)) = (&old_trust_seed, &old_trust_key_id) {
        decode_exact::<32>(seed, "SHAR_TRUST_SEED")?;
        let key_id = decode_bytes(key_id, "SHAR_TRUST_KEY_ID")?;
        if key_id.is_empty() || key_id.len() > 32 {
            return Err("SHAR_TRUST_KEY_ID must decode to 1..32 bytes".into());
        }
    }
    if old_key_id_bytes.is_empty() || old_key_id_bytes.len() > 32 {
        return Err("SHAR_KEY_ID must decode to 1..32 bytes".into());
    }
    if old_modulus.len() != 256
        || old_modulus.first().is_none_or(|byte| byte & 0x80 == 0)
        || old_modulus.last().is_some_and(|byte| byte & 1 == 0)
    {
        return Err("SHAR_RSW_MODULUS must decode to an odd 2048-bit value".into());
    }
    if old_lambda.is_empty()
        || old_lambda_value <= BigUint::from(1_u8)
        || old_lambda_value >= old_modulus_value
    {
        return Err("SHAR_RSW_LAMBDA must satisfy 1 < lambda < modulus".into());
    }
    for name in [
        "SHAR_NETWORK_SECRET",
        "SHAR_FALLBACK_SECRET",
        "SHAR_ADMIN_SECRET",
        "SHAR_SITEVERIFY_MASTER_SECRET",
    ] {
        let _ = required(&old, name)?;
    }
    eprintln!("generating a new 2048-bit RSW modulus; this can take a while");
    let mut rng = OsRng;
    let p = generate_prime(1024, &mut rng);
    let (q, modulus) = loop {
        let q = generate_prime(1024, &mut rng);
        let modulus = &p * &q;
        if q != p && modulus.bits() == 2048 {
            break (q, modulus);
        }
    };
    let lambda = (p - BigUint::from(1_u8)).lcm(&(q - BigUint::from(1_u8)));
    let mut signing_seed = [0; 32];
    let mut key_id = [0; 8];
    let mut trust_seed = [0; 32];
    let mut trust_key_id = [0; 8];
    rng.fill_bytes(&mut signing_seed);
    rng.fill_bytes(&mut key_id);
    rng.fill_bytes(&mut trust_seed);
    rng.fill_bytes(&mut trust_key_id);
    let modulus_bytes = modulus.to_bytes_be();
    let digest = Sha256::digest(&modulus_bytes);
    let previous_verify = append_json_array(
        &old,
        "SHAR_PREVIOUS_VERIFY_KEYS",
        json!({"kid": old_key_id, "x": URL_SAFE_NO_PAD.encode(old_public)}),
    )?;
    let previous_rsw = append_json_array(
        &old,
        "SHAR_PREVIOUS_RSW_KEYS",
        json!({
            "id": old_rsw_id,
            "modulus": URL_SAFE_NO_PAD.encode(old_modulus),
            "lambda": URL_SAFE_NO_PAD.encode(old_lambda),
        }),
    )?;
    let previous_trust = match (old_trust_seed, old_trust_key_id) {
        (Some(seed), Some(key_id)) => append_json_array(
            &old,
            "SHAR_PREVIOUS_TRUST_KEYS",
            json!({"seed": seed, "key_id": key_id}),
        )?,
        _ => old
            .get("SHAR_PREVIOUS_TRUST_KEYS")
            .map(|encoded| serde_json::from_str(encoded))
            .transpose()
            .map_err(|_| "SHAR_PREVIOUS_TRUST_KEYS must be a JSON array")?
            .unwrap_or_default(),
    };
    let document = json!({
        "SHAR_SIGNING_SEED": URL_SAFE_NO_PAD.encode(signing_seed),
        "SHAR_KEY_ID": URL_SAFE_NO_PAD.encode(key_id),
        "SHAR_RSW_MODULUS": URL_SAFE_NO_PAD.encode(&modulus_bytes),
        "SHAR_RSW_LAMBDA": URL_SAFE_NO_PAD.encode(lambda.to_bytes_be()),
        "SHAR_RSW_ID": format!("rsw-{}", URL_SAFE_NO_PAD.encode(&digest[..12])),
        "SHAR_NETWORK_SECRET": required(&old, "SHAR_NETWORK_SECRET")?,
        "SHAR_FALLBACK_SECRET": required(&old, "SHAR_FALLBACK_SECRET")?,
        "SHAR_ADMIN_SECRET": required(&old, "SHAR_ADMIN_SECRET")?,
        "SHAR_SITEVERIFY_MASTER_SECRET": required(&old, "SHAR_SITEVERIFY_MASTER_SECRET")?,
        "SHAR_TRUST_SEED": URL_SAFE_NO_PAD.encode(trust_seed),
        "SHAR_TRUST_KEY_ID": URL_SAFE_NO_PAD.encode(trust_key_id),
        "SHAR_PREVIOUS_VERIFY_KEYS": serde_json::to_string(&previous_verify).map_err(|_| "cannot encode previous verification keys")?,
        "SHAR_PREVIOUS_RSW_KEYS": serde_json::to_string(&previous_rsw).map_err(|_| "cannot encode previous RSW keys")?,
        "SHAR_PREVIOUS_TRUST_KEYS": serde_json::to_string(&previous_trust).map_err(|_| "cannot encode previous trust keys")?,
    });
    write_document(&output, &document)?;
    eprintln!(
        "wrote rotated protected key material to {}",
        output.display()
    );
    Ok(())
}

fn parse_flags(
    arguments: &[OsString],
    allowed: &[&str],
    usage: &str,
) -> Result<HashMap<String, OsString>, String> {
    let mut values = HashMap::new();
    let mut chunks = arguments.chunks_exact(2);
    for pair in &mut chunks {
        let flag = pair[0].to_str().ok_or(usage)?;
        if !allowed.contains(&flag) || values.insert(flag.to_owned(), pair[1].clone()).is_some() {
            return Err(usage.into());
        }
    }
    if !chunks.remainder().is_empty() {
        return Err(usage.into());
    }
    Ok(values)
}

fn read_document(path: &PathBuf) -> Result<HashMap<String, String>, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("key file must not be accessible by group or other users".into());
    }
    serde_json::from_slice(
        &std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?,
    )
    .map_err(|_| "key file must contain a JSON object of string values".into())
}

fn required<'a>(document: &'a HashMap<String, String>, name: &str) -> Result<&'a str, String> {
    document
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("key file does not contain {name}"))
}

fn decode_bytes(value: &str, name: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| format!("{name} must be base64url"))
}

fn decode_exact<const N: usize>(value: &str, name: &str) -> Result<[u8; N], String> {
    decode_bytes(value, name)?
        .try_into()
        .map_err(|_| format!("{name} must decode to {N} bytes"))
}

fn append_json_array(
    document: &HashMap<String, String>,
    name: &str,
    entry: serde_json::Value,
) -> Result<Vec<serde_json::Value>, String> {
    let mut values = document
        .get(name)
        .map(|encoded| serde_json::from_str::<Vec<serde_json::Value>>(encoded))
        .transpose()
        .map_err(|_| format!("{name} must be a JSON array"))?
        .unwrap_or_default();
    values.retain(|value| value != &entry);
    values.insert(0, entry);
    Ok(values)
}

fn write_document(path: &PathBuf, document: &serde_json::Value) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, document)
        .map_err(|error| format!("cannot write key file: {error}"))?;
    file.write_all(b"\n")
        .map_err(|error| format!("cannot finish key file: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync key file: {error}"))?;
    Ok(())
}

fn site_secret(arguments: &[OsString]) -> Result<(), String> {
    const USAGE: &str =
        "usage: shar-keygen site-secret --key-file PATH --tenant TENANT --site-key SITE";
    let mut values = HashMap::new();
    let mut chunks = arguments.chunks_exact(2);
    for pair in &mut chunks {
        let flag = pair[0].to_str().ok_or(USAGE)?;
        if !["--key-file", "--tenant", "--site-key"].contains(&flag) {
            return Err(USAGE.into());
        }
        if values.insert(flag, pair[1].clone()).is_some() {
            return Err(USAGE.into());
        }
    }
    if !chunks.remainder().is_empty() {
        return Err(USAGE.into());
    }
    let path = PathBuf::from(values.get("--key-file").ok_or(USAGE)?);
    let metadata =
        std::fs::metadata(&path).map_err(|error| format!("cannot inspect key file: {error}"))?;
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("key file must not be accessible by group or other users".into());
    }
    let document: HashMap<String, String> = serde_json::from_slice(
        &std::fs::read(&path).map_err(|error| format!("cannot read key file: {error}"))?,
    )
    .map_err(|_| "key file must contain a JSON object of string values")?;
    let encoded = document
        .get("SHAR_SITEVERIFY_MASTER_SECRET")
        .ok_or("key file does not contain SHAR_SITEVERIFY_MASTER_SECRET")?;
    let master: [u8; 32] = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "SHAR_SITEVERIFY_MASTER_SECRET must be base64url")?
        .try_into()
        .map_err(|_| "SHAR_SITEVERIFY_MASTER_SECRET must decode to 32 bytes")?;
    let tenant = values
        .get("--tenant")
        .and_then(|value| value.to_str())
        .ok_or(USAGE)?;
    let site_key = values
        .get("--site-key")
        .and_then(|value| value.to_str())
        .ok_or(USAGE)?;
    println!(
        "{}",
        derive_site_verify_secret(&master, tenant, site_key)
            .map_err(|_| "tenant or site key is invalid")?
    );
    Ok(())
}

fn generate_prime(bits: u64, rng: &mut OsRng) -> BigUint {
    loop {
        let mut candidate = rng.gen_biguint(bits);
        candidate.set_bit(bits - 1, true);
        candidate.set_bit(1, true);
        candidate.set_bit(0, true);
        if probable_prime(&candidate, 64, rng) {
            return candidate;
        }
    }
}
fn probable_prime(n: &BigUint, rounds: u32, rng: &mut OsRng) -> bool {
    let two = BigUint::from(2_u8);
    let three = BigUint::from(3_u8);
    if n == &two || n == &three {
        return true;
    }
    if n < &two || n.is_even() {
        return false;
    }
    for prime in [3_u32, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47] {
        let p = BigUint::from(prime);
        if n == &p {
            return true;
        }
        if (n % &p) == BigUint::from(0_u8) {
            return false;
        }
    }
    let one = BigUint::from(1_u8);
    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut s = 0;
    while d.is_even() {
        d >>= 1;
        s += 1
    }
    let upper = n - &two;
    'witness: for _ in 0..rounds {
        let a = rng.gen_biguint_range(&two, &upper);
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_one {
            continue;
        }
        for _ in 1..s {
            x = (&x * &x) % n;
            if x == n_minus_one {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn primality_rejects_composites_and_generates_requested_size() {
        let mut rng = OsRng;
        for value in [0_u64, 1, 4, 9, 15, 21, 341, 561, 1105] {
            assert!(!probable_prime(&BigUint::from(value), 16, &mut rng))
        }
        for value in [2_u64, 3, 5, 17, 97, 65537] {
            assert!(probable_prime(&BigUint::from(value), 16, &mut rng))
        }
        let prime = generate_prime(64, &mut rng);
        assert_eq!(prime.bits(), 64);
        assert!(probable_prime(&prime, 32, &mut rng));
    }
}
