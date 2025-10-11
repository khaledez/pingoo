use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TestClaims {
    pub sub: String,
    pub name: String,
    pub admin: bool,
    pub exp: i64,
}

#[test]
fn test_sign_and_verify_eddsa_jwt() {
    let key = Key::generate_ed25519("test-key-1".to_string()).expect("failed to generate key");

    let header = Header {
        typ: TokenType::JWT,
        alg: Algorithm::EdDSA,
        cty: None,
        jku: None,
        kid: Some("test-key-1".to_string()),
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    };

    let expiration_timestamp = Utc::now().timestamp() + 3600;
    let claims = TestClaims {
        sub: "user123".to_string(),
        name: "John Doe".to_string(),
        admin: true,
        exp: expiration_timestamp,
    };

    let jwt_token = sign(&key, &header, &claims).expect("failed to sign JWT");

    println!("Generated JWT token: {}", jwt_token);
    assert!(jwt_token.len() > 0);
    assert_eq!(jwt_token.split('.').count(), 3);

    let validate_options = ValidateOptions {
        allowed_time_drift: Duration::from_secs(10),
        nbf: false,
        exp: true,
        aud: &[],
        iss: &[],
    };

    let parsed_jwt: ParsedJwt<TestClaims> =
        parse_and_verify(&key, &jwt_token, &validate_options).expect("failed to verify JWT");

    assert_eq!(parsed_jwt.header.alg, Algorithm::EdDSA);
    assert_eq!(parsed_jwt.header.typ, TokenType::JWT);
    assert_eq!(parsed_jwt.claims, claims);
}

#[test]
fn test_verify_jwt_with_expired_token() {
    let key = Key::generate_ed25519("test-key-2".to_string()).expect("failed to generate key");

    let header = Header {
        typ: TokenType::JWT,
        alg: Algorithm::EdDSA,
        cty: None,
        jku: None,
        kid: Some("test-key-2".to_string()),
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    };

    let expired_timestamp = Utc::now().timestamp() - 3600;
    let claims = TestClaims {
        sub: "user456".to_string(),
        name: "Jane Smith".to_string(),
        admin: false,
        exp: expired_timestamp,
    };

    let jwt_token = sign(&key, &header, &claims).expect("failed to sign JWT");

    let validate_options = ValidateOptions {
        allowed_time_drift: Duration::from_secs(10),
        nbf: false,
        exp: true,
        aud: &[],
        iss: &[],
    };

    let result = parse_and_verify::<TestClaims>(&key, &jwt_token, &validate_options);
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::InvalidToken)));
}

#[test]
fn test_verify_jwt_with_wrong_key() {
    let signing_key = Key::generate_ed25519("signing-key".to_string()).expect("failed to generate key");
    let verification_key = Key::generate_ed25519("different-key".to_string()).expect("failed to generate key");

    let header = Header {
        typ: TokenType::JWT,
        alg: Algorithm::EdDSA,
        cty: None,
        jku: None,
        kid: Some("signing-key".to_string()),
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    };

    let claims = TestClaims {
        sub: "user789".to_string(),
        name: "Bob Wilson".to_string(),
        admin: false,
        exp: Utc::now().timestamp() + 3600,
    };

    let jwt_token = sign(&signing_key, &header, &claims).expect("failed to sign JWT");

    let validate_options = ValidateOptions {
        allowed_time_drift: Duration::from_secs(10),
        nbf: false,
        exp: true,
        aud: &[],
        iss: &[],
    };

    let result = parse_and_verify::<TestClaims>(&verification_key, &jwt_token, &validate_options);
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::InvalidSignature)));
}

#[test]
fn test_verify_jwt_with_registered_claims() {
    let key = Key::generate_ed25519("test-key-3".to_string()).expect("failed to generate key");

    let header = Header {
        typ: TokenType::JWT,
        alg: Algorithm::EdDSA,
        cty: None,
        jku: None,
        kid: Some("test-key-3".to_string()),
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    };

    let claims = RegisteredClaims {
        iss: Some("https://auth.example.com".to_string()),
        sub: Some("user123".to_string()),
        aud: Some("https://api.example.com".to_string()),
        exp: Some(Utc::now().timestamp() + 3600),
        nbf: Some(Utc::now().timestamp() - 60),
        iat: Some(Utc::now().timestamp()),
        jti: Some("unique-token-id".to_string()),
    };

    let jwt_token = sign(&key, &header, &claims).expect("failed to sign JWT");

    let validate_options = ValidateOptions {
        allowed_time_drift: Duration::from_secs(10),
        nbf: true,
        exp: true,
        aud: &["https://api.example.com"],
        iss: &["https://auth.example.com"],
    };

    let parsed_jwt: ParsedJwt<RegisteredClaims> =
        parse_and_verify(&key, &jwt_token, &validate_options).expect("failed to verify JWT");

    assert_eq!(
        parsed_jwt.claims.iss,
        Some("https://auth.example.com".to_string())
    );
    assert_eq!(parsed_jwt.claims.sub, Some("user123".to_string()));
    assert_eq!(
        parsed_jwt.claims.aud,
        Some("https://api.example.com".to_string())
    );
}

#[test]
fn test_verify_jwt_with_nbf_claim() {
    let key = Key::generate_ed25519("test-key-4".to_string()).expect("failed to generate key");

    let header = Header {
        typ: TokenType::JWT,
        alg: Algorithm::EdDSA,
        cty: None,
        jku: None,
        kid: Some("test-key-4".to_string()),
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    };

    let future_nbf = Utc::now().timestamp() + 3600;
    let claims = RegisteredClaims {
        iss: None,
        sub: Some("user999".to_string()),
        aud: None,
        exp: Some(Utc::now().timestamp() + 7200),
        nbf: Some(future_nbf),
        iat: Some(Utc::now().timestamp()),
        jti: None,
    };

    let jwt_token = sign(&key, &header, &claims).expect("failed to sign JWT");

    let validate_options = ValidateOptions {
        allowed_time_drift: Duration::from_secs(10),
        nbf: true,
        exp: true,
        aud: &[],
        iss: &[],
    };

    let result = parse_and_verify::<RegisteredClaims>(&key, &jwt_token, &validate_options);
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::InvalidToken)));
}

#[test]
fn test_verify_jwt_with_invalid_audience() {
    let key = Key::generate_ed25519("test-key-5".to_string()).expect("failed to generate key");

    let header = Header {
        typ: TokenType::JWT,
        alg: Algorithm::EdDSA,
        cty: None,
        jku: None,
        kid: Some("test-key-5".to_string()),
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    };

    let claims = RegisteredClaims {
        iss: None,
        sub: Some("user456".to_string()),
        aud: Some("https://wrong-api.example.com".to_string()),
        exp: Some(Utc::now().timestamp() + 3600),
        nbf: None,
        iat: Some(Utc::now().timestamp()),
        jti: None,
    };

    let jwt_token = sign(&key, &header, &claims).expect("failed to sign JWT");

    let validate_options = ValidateOptions {
        allowed_time_drift: Duration::from_secs(10),
        nbf: false,
        exp: true,
        aud: &["https://api.example.com"],
        iss: &[],
    };

    let result = parse_and_verify::<RegisteredClaims>(&key, &jwt_token, &validate_options);
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::InvalidToken)));
}

#[test]
fn test_verify_jwt_with_invalid_issuer() {
    let key = Key::generate_ed25519("test-key-6".to_string()).expect("failed to generate key");

    let header = Header {
        typ: TokenType::JWT,
        alg: Algorithm::EdDSA,
        cty: None,
        jku: None,
        kid: Some("test-key-6".to_string()),
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    };

    let claims = RegisteredClaims {
        iss: Some("https://untrusted.example.com".to_string()),
        sub: Some("user789".to_string()),
        aud: None,
        exp: Some(Utc::now().timestamp() + 3600),
        nbf: None,
        iat: Some(Utc::now().timestamp()),
        jti: None,
    };

    let jwt_token = sign(&key, &header, &claims).expect("failed to sign JWT");

    let validate_options = ValidateOptions {
        allowed_time_drift: Duration::from_secs(10),
        nbf: false,
        exp: true,
        aud: &[],
        iss: &["https://auth.example.com"],
    };

    let result = parse_and_verify::<RegisteredClaims>(&key, &jwt_token, &validate_options);
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::InvalidToken)));
}

#[test]
fn test_parse_header_from_token() {
    let key = Key::generate_ed25519("test-key-7".to_string()).expect("failed to generate key");

    let header = Header {
        typ: TokenType::JWT,
        alg: Algorithm::EdDSA,
        cty: None,
        jku: None,
        kid: Some("test-key-7".to_string()),
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    };

    let claims = TestClaims {
        sub: "user000".to_string(),
        name: "Test User".to_string(),
        admin: false,
        exp: Utc::now().timestamp() + 3600,
    };

    let jwt_token = sign(&key, &header, &claims).expect("failed to sign JWT");

    let parsed_header = parse_header(&jwt_token).expect("failed to parse header");

    assert_eq!(parsed_header.alg, Algorithm::EdDSA);
    assert_eq!(parsed_header.typ, TokenType::JWT);
    assert_eq!(parsed_header.kid, Some("test-key-7".to_string()));
}

#[test]
fn test_parse_header_invalid_token() {
    let result = parse_header("invalid.token");
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::InvalidToken)));
}

#[test]
fn test_jwk_roundtrip_conversion() {
    let original_key = Key::generate_ed25519("test-key-8".to_string()).expect("failed to generate key");

    let jwk: Jwk = (&original_key).into();

    assert_eq!(jwk.kid, "test-key-8");
    assert_eq!(jwk.algorithm, Algorithm::EdDSA);
    assert_eq!(jwk.r#use, KeyUse::Sign);

    let reconstructed_key: Key = jwk.try_into().expect("failed to convert JWK to Key");

    assert_eq!(reconstructed_key.id, "test-key-8");
    assert_eq!(reconstructed_key.algorithm(), Algorithm::EdDSA);

    let header = Header {
        typ: TokenType::JWT,
        alg: Algorithm::EdDSA,
        cty: None,
        jku: None,
        kid: Some("test-key-8".to_string()),
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    };

    let claims = TestClaims {
        sub: "roundtrip-test".to_string(),
        name: "Roundtrip User".to_string(),
        admin: true,
        exp: Utc::now().timestamp() + 3600,
    };

    let jwt_token = sign(&original_key, &header, &claims).expect("failed to sign JWT");

    let validate_options = ValidateOptions {
        allowed_time_drift: Duration::from_secs(10),
        nbf: false,
        exp: true,
        aud: &[],
        iss: &[],
    };

    let parsed_jwt: ParsedJwt<TestClaims> =
        parse_and_verify(&reconstructed_key, &jwt_token, &validate_options)
            .expect("failed to verify JWT with reconstructed key");

    assert_eq!(parsed_jwt.claims, claims);
}

// RS256 tests - Note: RS256 key generation needs to be implemented first
// Once RS256 support is added to the Key module, uncomment and implement these tests:
//
// #[test]
// fn test_sign_and_verify_rs256_jwt() {
//     let key = Key::generate_rsa("test-rsa-key".to_string()).expect("failed to generate RSA key");
//
//     let header = Header {
//         typ: TokenType::JWT,
//         alg: Algorithm::RS256,
//         cty: None,
//         jku: None,
//         kid: Some("test-rsa-key".to_string()),
//         x5u: None,
//         x5c: None,
//         x5t: None,
//         x5t_s256: None,
//     };
//
//     let claims = TestClaims {
//         sub: "rsa-user".to_string(),
//         name: "RSA Test User".to_string(),
//         admin: true,
//         exp: Utc::now().timestamp() + 3600,
//     };
//
//     let jwt_token = sign(&key, &header, &claims).expect("failed to sign JWT with RS256");
//
//     let validate_options = ValidateOptions {
//         allowed_time_drift: Duration::from_secs(10),
//         nbf: false,
//         exp: true,
//         aud: &[],
//         iss: &[],
//     };
//
//     let parsed_jwt: ParsedJwt<TestClaims> =
//         parse_and_verify(&key, &jwt_token, &validate_options)
//             .expect("failed to verify RS256 JWT");
//
//     assert_eq!(parsed_jwt.header.alg, Algorithm::RS256);
//     assert_eq!(parsed_jwt.claims, claims);
// }
