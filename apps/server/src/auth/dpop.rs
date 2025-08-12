use base64::Engine;
use parking_lot::Mutex;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use josekit::{jwk::Jwk, jws::alg::{ecdsa::EcdsaJwsAlgorithm, eddsa::EddsaJwsAlgorithm}, jws::JwsVerifier};

#[derive(Clone, Debug)]
pub struct ReplayCache {
    inner: Arc<Mutex<HashMap<String, i64>>>, // jti -> exp_ts
    window_sec: i64,
}

impl ReplayCache {
    pub fn new(window_sec: i64) -> Self {
        Self { inner: Arc::new(Mutex::new(HashMap::new())), window_sec }
    }
    pub fn check_and_store(&self, jti: &str, now: i64) -> bool {
        let mut m = self.inner.lock();
        // cleanup expired
        m.retain(|_, exp| *exp > now);
        if m.contains_key(jti) { return false; }
        m.insert(jti.to_string(), now + self.window_sec);
        true
    }
}

#[derive(Debug, Deserialize)]
struct DPoPHeader { alg: String, typ: Option<String>, jwk: serde_json::Value }
#[derive(Debug, Deserialize)]
struct DPoPPayload { htm: String, htu: String, iat: i64, jti: String }

fn b64u_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| "bad_b64")
}

fn compute_ec_thumbprint_b64u(jwk: &serde_json::Value) -> Result<String, &'static str> {
    // RFC7638: only accepted members and lex order
    let crv = jwk.get("crv").and_then(|v| v.as_str()).ok_or("bad_jwk")?;
    let kty = jwk.get("kty").and_then(|v| v.as_str()).ok_or("bad_jwk")?;
    let x = jwk.get("x").and_then(|v| v.as_str()).ok_or("bad_jwk")?;
    let y = jwk.get("y").and_then(|v| v.as_str()).ok_or("bad_jwk")?;
    let obj = serde_json::json!({
        "crv": crv,
        "kty": kty,
        "x": x,
        "y": y,
    });
    let data = serde_json::to_vec(&obj).map_err(|_| "bad_jwk")?;
    let digest = Sha256::digest(&data);
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
}

fn build_htu(origin: &str, path_and_query: &str) -> String {
    if origin.ends_with('/') {
        format!("{}{}", origin.trim_end_matches('/'), path_and_query)
    } else {
        format!("{}{}", origin, path_and_query)
    }
}

pub fn validate_dpop(
    method: &str,
    host: Option<&str>,
    path_and_query: &str,
    dpop_header: &str,
    expected_jkt: &str,
    public_origin: Option<&str>,
    replay: &ReplayCache,
    now_ts: i64,
) -> Result<(), &'static str> {
    // Split compact JWS
    let parts: Vec<&str> = dpop_header.split('.').collect();
    if parts.len() != 3 { return Err("bad_dpop"); }
    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let sig_b64 = parts[2];
    let header_raw = b64u_decode(header_b64)?;
    let payload_raw = b64u_decode(payload_b64)?;

    let header: DPoPHeader = serde_json::from_slice(&header_raw).map_err(|_| "bad_dpop")?;
    if header.typ.as_deref() != Some("dpop+jwt") { return Err("bad_dpop_typ"); }
    if header.alg != "ES256" && header.alg != "EdDSA" { return Err("bad_dpop_alg"); }

    let payload: DPoPPayload = serde_json::from_slice(&payload_raw).map_err(|_| "bad_dpop")?;

    // htm
    if payload.htm.to_uppercase() != method.to_uppercase() { return Err("bad_htm"); }

    // htu
    let origin = if let Some(orig) = public_origin { orig.to_string() } else {
        let host = host.ok_or("no_host")?;
        format!("http://{}", host)
    };
    let expected_htu = build_htu(&origin, path_and_query);
    if payload.htu != expected_htu { return Err("bad_htu"); }

    // iat window 5 min
    if (now_ts - payload.iat).abs() > 300 { return Err("iat_window"); }

    // jti anti-replay
    if !replay.check_and_store(&payload.jti, now_ts) { return Err("replay"); }

    // jkt from header.jwk
    let jkt = compute_ec_thumbprint_b64u(&header.jwk)?;
    if jkt != expected_jkt { return Err("jkt_mismatch"); }

    // signature verification
    let sig = b64u_decode(sig_b64)?;
    let signing_input = [header_b64.as_bytes(), b".", payload_b64.as_bytes()].concat();

    let jwk_json = header.jwk.to_string();
    let jwk = Jwk::from_bytes(jwk_json.as_bytes()).map_err(|_| "bad_jwk")?;
    let verified = match header.alg.as_str() {
        "ES256" => EcdsaJwsAlgorithm::Es256
            .verifier_from_jwk(&jwk)
            .ok()
            .and_then(|v| v.verify(&signing_input, &sig).ok())
            .is_some(),
        "EdDSA" => EddsaJwsAlgorithm::Eddsa
            .verifier_from_jwk(&jwk)
            .ok()
            .and_then(|v| v.verify(&signing_input, &sig).ok())
            .is_some(),
        _ => false,
    };
    if !verified { return Err("bad_sig"); }

    Ok(())
}

pub fn validate_dpop_and_get_jkt(
    method: &str,
    host: Option<&str>,
    path_and_query: &str,
    dpop_header: &str,
    public_origin: Option<&str>,
    replay: &ReplayCache,
    now_ts: i64,
) -> Result<String, &'static str> {
    // Split compact JWS
    let parts: Vec<&str> = dpop_header.split('.').collect();
    if parts.len() != 3 { return Err("bad_dpop"); }
    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let sig_b64 = parts[2];
    let header_raw = b64u_decode(header_b64)?;
    let payload_raw = b64u_decode(payload_b64)?;

    let header: DPoPHeader = serde_json::from_slice(&header_raw).map_err(|_| "bad_dpop")?;
    if header.typ.as_deref() != Some("dpop+jwt") { return Err("bad_dpop_typ"); }
    if header.alg != "ES256" && header.alg != "EdDSA" { return Err("bad_dpop_alg"); }

    let payload: DPoPPayload = serde_json::from_slice(&payload_raw).map_err(|_| "bad_dpop")?;

    // htm
    if payload.htm.to_uppercase() != method.to_uppercase() { return Err("bad_htm"); }

    // htu
    let origin = if let Some(orig) = public_origin { orig.to_string() } else {
        let host = host.ok_or("no_host")?;
        format!("http://{}", host)
    };
    let expected_htu = build_htu(&origin, path_and_query);
    if payload.htu != expected_htu { return Err("bad_htu"); }

    // iat window 5 min
    if (now_ts - payload.iat).abs() > 300 { return Err("iat_window"); }

    // jti anti-replay
    if !replay.check_and_store(&payload.jti, now_ts) { return Err("replay"); }

    // compute jkt from header.jwk
    let jkt = compute_ec_thumbprint_b64u(&header.jwk)?;

    // signature verification
    let sig = b64u_decode(sig_b64)?;
    let signing_input = [header_b64.as_bytes(), b".", payload_b64.as_bytes()].concat();

    let jwk_json = header.jwk.to_string();
    let jwk = Jwk::from_bytes(jwk_json.as_bytes()).map_err(|_| "bad_jwk")?;
    let verified = match header.alg.as_str() {
        "ES256" => EcdsaJwsAlgorithm::Es256
            .verifier_from_jwk(&jwk)
            .ok()
            .and_then(|v| v.verify(&signing_input, &sig).ok())
            .is_some(),
        "EdDSA" => EddsaJwsAlgorithm::Eddsa
            .verifier_from_jwk(&jwk)
            .ok()
            .and_then(|v| v.verify(&signing_input, &sig).ok())
            .is_some(),
        _ => false,
    };
    if !verified { return Err("bad_sig"); }

    Ok(jkt)
}
