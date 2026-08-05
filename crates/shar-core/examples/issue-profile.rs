use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use num_bigint::BigUint;
use serde_json::Value;
use sha2::{Digest, Sha256};
use shar_core::{
    ChallengeRequest, Engine, PressureInput, SigningMaterial, TimeLockKey, cose_sign,
    default_work_policy, derive_timelock_input, trust::TrustKeyPair,
};
use std::{env, fs, hint::black_box, time::Instant};

const ITERATIONS: u64 = 20_000;

fn main() {
    let path = env::args()
        .nth(1)
        .expect("usage: cargo run -p shar-core --release --example issue-profile -- KEY_FILE");
    let document: Value =
        serde_json::from_slice(&fs::read(path).expect("read key file")).expect("parse key file");
    let signing = SigningMaterial {
        key_id: decode(&document, "SHAR_KEY_ID"),
        seed: decode(&document, "SHAR_SIGNING_SEED")
            .try_into()
            .expect("32-byte signing seed"),
    };
    let time_lock = TimeLockKey {
        id: text(&document, "SHAR_RSW_ID").to_owned(),
        modulus: BigUint::from_bytes_be(&decode(&document, "SHAR_RSW_MODULUS")),
        lambda: BigUint::from_bytes_be(&decode(&document, "SHAR_RSW_LAMBDA")),
    };
    let trust = TrustKeyPair::from_seed(
        &decode(&document, "SHAR_TRUST_SEED"),
        &decode(&document, "SHAR_TRUST_KEY_ID"),
    )
    .expect("trust key");
    let signing_profile = signing.clone();
    let without_trust = Engine::new(signing.clone(), time_lock.clone(), default_work_policy());
    let with_trust = Engine::new(signing, time_lock.clone(), default_work_policy())
        .with_trust_keys(vec![trust], 86_400)
        .expect("trust configuration");
    let request = ChallengeRequest {
        tenant: "benchmark".into(),
        site_key: "benchmark".into(),
        action: "issue".into(),
        origin: "http://localhost:3000".into(),
        region: None,
        session_binding: None,
        network_pseudonym: Some("daily-network".into()),
        assurance_tier: None,
        trust_token: None,
    };
    let pressure = PressureInput::default();
    for index in 0..100 {
        black_box(issue(&without_trust, &request, &pressure, index));
        black_box(issue(&with_trust, &request, &pressure, index));
    }
    let without = measure(|| {
        for index in 0..ITERATIONS {
            black_box(issue(&without_trust, &request, &pressure, index));
        }
    });
    let with = measure(|| {
        for index in 0..ITERATIONS {
            black_box(issue(&with_trust, &request, &pressure, index));
        }
    });
    let derive = measure(|| {
        for index in 0..ITERATIONS {
            let mut nonce = [0_u8; 16];
            nonce[8..].copy_from_slice(&index.to_be_bytes());
            black_box(derive_timelock_input(&nonce, &time_lock.modulus));
        }
    });
    let euclidean_derive = measure(|| {
        for index in 0..ITERATIONS {
            let mut nonce = [0_u8; 16];
            nonce[8..].copy_from_slice(&index.to_be_bytes());
            black_box(euclidean_timelock_input(&nonce, &time_lock.modulus));
        }
    });
    let representative = issue(&with_trust, &request, &pressure, ITERATIONS + 1);
    let serialized = serde_json::to_vec(&representative).expect("serialize response");
    let serialize = measure(|| {
        for _ in 0..ITERATIONS {
            black_box(serde_json::to_vec(&representative).expect("serialize response"));
        }
    });
    let signing_payload = vec![0_u8; 220];
    let signing = measure(|| {
        for _ in 0..ITERATIONS {
            black_box(cose_sign(&signing_payload, &signing_profile).expect("COSE sign"));
        }
    });
    println!(
        "{{\"schema\":\"shar-rust-core-issue-profile-v1\",\"iterations\":{ITERATIONS},\"without_trust_ops_per_second\":{},\"with_trust_ops_per_second\":{},\"timelock_input_derivations_per_second\":{},\"euclidean_timelock_input_derivations_per_second\":{},\"cose_signing_per_second\":{},\"serialization_ops_per_second\":{},\"response_bytes\":{},\"token_characters\":{},\"quote_bytes\":{},\"render_bytes\":{},\"time_lock_bytes\":{},\"trust_bytes\":{}}}",
        rate(without),
        rate(with),
        rate(derive),
        rate(euclidean_derive),
        rate(signing),
        rate(serialize),
        serialized.len(),
        representative.token.len(),
        json_size(&representative.quote),
        json_size(&representative.render),
        json_size(&representative.time_lock),
        json_size(&representative.trust),
    );
}

fn euclidean_timelock_input(nonce: &[u8], modulus: &BigUint) -> BigUint {
    for counter in 0..=u32::MAX {
        let mut hash = Sha256::new();
        hash.update(b"shar/rsw-v1/input\0");
        hash.update(nonce);
        hash.update(counter.to_be_bytes());
        let digest = BigUint::from_bytes_be(&hash.finalize());
        let candidate = if &digest >= modulus {
            digest % modulus
        } else {
            digest
        };
        if candidate.bits() <= 1 {
            continue;
        }
        let mut a = candidate.clone();
        let mut b = modulus % &candidate;
        while b.bits() != 0 {
            let next = &a % &b;
            a = b;
            b = next;
        }
        if a.bits() == 1 {
            return candidate;
        }
    }
    unreachable!("u32 counter space exhausted")
}

fn issue(
    engine: &Engine,
    request: &ChallengeRequest,
    pressure: &PressureInput,
    index: u64,
) -> shar_core::ChallengeResponse {
    let mut nonce = [0_u8; 16];
    nonce[8..].copy_from_slice(&index.to_be_bytes());
    let mut seed = [0_u8; 32];
    seed[24..].copy_from_slice(&index.to_be_bytes());
    engine
        .challenge(request, pressure, 1_800_000_000, nonce, seed)
        .expect("issue challenge")
}

fn measure(operation: impl FnOnce()) -> std::time::Duration {
    let started = Instant::now();
    operation();
    started.elapsed()
}

fn rate(duration: std::time::Duration) -> f64 {
    ITERATIONS as f64 / duration.as_secs_f64()
}

fn text<'a>(document: &'a Value, name: &str) -> &'a str {
    document[name]
        .as_str()
        .unwrap_or_else(|| panic!("missing {name}"))
}

fn decode(document: &Value, name: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(text(document, name))
        .unwrap_or_else(|_| panic!("invalid {name}"))
}

fn json_size(value: &impl serde::Serialize) -> usize {
    serde_json::to_vec(value).expect("serialize field").len()
}
