//! HTTP Digest auth helpers (RFC 7616 SHA-256 + RFC 2617 MD5 fallback).
//!
//! The C gateway's `datum_api.c` validates `Authorization: Digest ...` headers
//! using SHA-256 by default and falls back to MD5 when the client (Safari)
//! doesn't advertise SHA-256. This module ports the verification primitives —
//! HA1, HA2, response hash — and exposes a `verify_digest_response` helper
//! plus a `build_www_authenticate` helper for issuing challenges.
//!
//! Wiring into the axum router is left to the binary so the API state can
//! hold the admin password and CSRF token.

use md5::Md5;
use sha2::{Digest, Sha256};

/// Digest hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Sha256,
    Md5,
}

impl DigestAlgorithm {
    pub fn header_token(self) -> &'static str {
        match self {
            DigestAlgorithm::Sha256 => "SHA-256",
            DigestAlgorithm::Md5 => "MD5",
        }
    }

    fn hash_hex(self, parts: &[&[u8]]) -> String {
        match self {
            DigestAlgorithm::Sha256 => {
                let mut h = Sha256::new();
                for p in parts {
                    h.update(p);
                }
                hex_lower(&h.finalize())
            }
            DigestAlgorithm::Md5 => {
                let mut h = Md5::new();
                for p in parts {
                    h.update(p);
                }
                hex_lower(&h.finalize())
            }
        }
    }
}

/// `HA1 = H(username:realm:password)`. Matches RFC 7616 § 3.4.2 (basic form).
pub fn ha1(algo: DigestAlgorithm, username: &str, realm: &str, password: &str) -> String {
    algo.hash_hex(&[
        username.as_bytes(),
        b":",
        realm.as_bytes(),
        b":",
        password.as_bytes(),
    ])
}

/// `HA2 = H(method:uri)` for `qop=auth`. Matches RFC 7616 § 3.4.3.
pub fn ha2(algo: DigestAlgorithm, method: &str, uri: &str) -> String {
    algo.hash_hex(&[method.as_bytes(), b":", uri.as_bytes()])
}

/// `response = H(HA1:nonce:nc:cnonce:qop:HA2)`. RFC 7616 § 3.4.1 with `qop=auth`.
pub fn response_hash(
    algo: DigestAlgorithm,
    ha1: &str,
    nonce: &str,
    nc: &str,
    cnonce: &str,
    qop: &str,
    ha2: &str,
) -> String {
    algo.hash_hex(&[
        ha1.as_bytes(),
        b":",
        nonce.as_bytes(),
        b":",
        nc.as_bytes(),
        b":",
        cnonce.as_bytes(),
        b":",
        qop.as_bytes(),
        b":",
        ha2.as_bytes(),
    ])
}

/// Verify a client's `response` token. Returns `true` if it matches what the
/// server computes from `password` and the request's nonce/method/uri/qop/nc/
/// cnonce. Constant-time equality on the hex digest.
#[allow(clippy::too_many_arguments)]
pub fn verify_digest_response(
    algo: DigestAlgorithm,
    expected_response: &str,
    username: &str,
    realm: &str,
    password: &str,
    method: &str,
    uri: &str,
    nonce: &str,
    nc: &str,
    cnonce: &str,
    qop: &str,
) -> bool {
    let h1 = ha1(algo, username, realm, password);
    let h2 = ha2(algo, method, uri);
    let computed = response_hash(algo, &h1, nonce, nc, cnonce, qop, &h2);
    constant_time_eq(computed.as_bytes(), expected_response.as_bytes())
}

/// Build a `WWW-Authenticate` challenge header value for the given algorithm.
pub fn build_www_authenticate(algo: DigestAlgorithm, realm: &str, nonce: &str) -> String {
    format!(
        "Digest realm=\"{realm}\", qop=\"auth\", algorithm={algo}, nonce=\"{nonce}\"",
        algo = algo.header_token(),
    )
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(hex_nib(b >> 4));
        s.push(hex_nib(b & 0x0F));
    }
    s
}

fn hex_nib(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + n - 10) as char,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ha1_sha256_is_64_hex() {
        let h = ha1(
            DigestAlgorithm::Sha256,
            "Mufasa",
            "http-auth@example.org",
            "Circle of Life",
        );
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        // Stability pin: same inputs always produce the same hash.
        assert_eq!(
            h,
            ha1(
                DigestAlgorithm::Sha256,
                "Mufasa",
                "http-auth@example.org",
                "Circle of Life"
            )
        );
    }

    #[test]
    fn ha2_sha256() {
        let h = ha2(DigestAlgorithm::Sha256, "GET", "/dir/index.html");
        assert!(!h.is_empty());
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn ha1_md5() {
        let h = ha1(DigestAlgorithm::Md5, "user", "realm", "pw");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn verify_digest_round_trip_sha256() {
        let realm = "datum_gateway";
        let nonce = "abcd1234";
        let nc = "00000001";
        let cnonce = "0a4f113b";
        let qop = "auth";
        let method = "POST";
        let uri = "/cmd";
        let username = "admin";
        let password = "hunter2";

        let h1 = ha1(DigestAlgorithm::Sha256, username, realm, password);
        let h2 = ha2(DigestAlgorithm::Sha256, method, uri);
        let resp = response_hash(DigestAlgorithm::Sha256, &h1, nonce, nc, cnonce, qop, &h2);

        assert!(verify_digest_response(
            DigestAlgorithm::Sha256,
            &resp,
            username,
            realm,
            password,
            method,
            uri,
            nonce,
            nc,
            cnonce,
            qop
        ));
    }

    #[test]
    fn verify_digest_round_trip_md5() {
        let h1 = ha1(DigestAlgorithm::Md5, "u", "r", "p");
        let h2 = ha2(DigestAlgorithm::Md5, "GET", "/");
        let resp = response_hash(DigestAlgorithm::Md5, &h1, "n", "1", "c", "auth", &h2);
        assert!(verify_digest_response(
            DigestAlgorithm::Md5,
            &resp,
            "u",
            "r",
            "p",
            "GET",
            "/",
            "n",
            "1",
            "c",
            "auth"
        ));
    }

    #[test]
    fn verify_digest_rejects_bad_password() {
        let h1 = ha1(DigestAlgorithm::Sha256, "u", "r", "right");
        let h2 = ha2(DigestAlgorithm::Sha256, "GET", "/");
        let resp = response_hash(DigestAlgorithm::Sha256, &h1, "n", "1", "c", "auth", &h2);
        assert!(!verify_digest_response(
            DigestAlgorithm::Sha256,
            &resp,
            "u",
            "r",
            "wrong",
            "GET",
            "/",
            "n",
            "1",
            "c",
            "auth"
        ));
    }

    #[test]
    fn build_challenge_includes_algorithm() {
        let c = build_www_authenticate(DigestAlgorithm::Sha256, "datum_gateway", "abc");
        assert!(c.contains("algorithm=SHA-256"));
        assert!(c.contains("realm=\"datum_gateway\""));
        assert!(c.contains("nonce=\"abc\""));
    }
}
