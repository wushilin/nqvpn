//! Bytes that must not change across dependency upgrades. Every value
//! here was produced by an earlier release and is checked by peers or
//! read back from disk, so a crate bump that alters one of them would
//! split a mixed-version fleet. Deterministic inputs only.

use ed25519_dalek::SigningKey;
use nqvpn_proto::control::Heartbeat;
use nqvpn_proto::credential::{self, Claims};
use nqvpn_proto::envelope::{encode_msg, Kind};
use nqvpn_proto::identity::fingerprint_der;
use nqvpn_proto::seal::StaticKeys;
use nqvpn_proto::token::Token;
use nqvpn_proto::types::Role;

fn claims() -> Claims {
    Claims {
        iss: "nqvpn-coord".into(),
        aud: "nqvpn".into(),
        network_id: "lab".into(),
        network_uuid: "c4efe2e0-bb43-4ad5-b15e-97ecc1740818".into(),
        node_id: 7,
        sub: "laptop".into(),
        role: Role::Client,
        pubkey: "AAAA".into(),
        cert_fp: "sha256:00".into(),
        prefixes: vec!["10.99.0.7/32".into()],
        login_gen: 3,
        iat: 1_790_000_000,
        exp: 1_790_003_600,
    }
}

#[test]
fn ed25519_keys_and_credentials_are_byte_identical() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    assert_eq!(hex::encode(sk.verifying_key().to_bytes()), "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c");
    // Ed25519 signatures are deterministic: a whole credential is pinned.
    assert_eq!(
        credential::sign(&claims(), "k1", &sk),
        "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImsxIn0.eyJpc3MiOiJucXZwbi1jb29yZCIsImF1ZCI6Im5xdnBuIiwibmV0d29ya19pZCI6ImxhYiIsIm5ldHdvcmtfdXVpZCI6ImM0ZWZlMmUwLWJiNDMtNGFkNS1iMTVlLTk3ZWNjMTc0MDgxOCIsIm5vZGVfaWQiOjcsInN1YiI6ImxhcHRvcCIsInJvbGUiOiJjbGllbnQiLCJwdWJrZXkiOiJBQUFBIiwiY2VydF9mcCI6InNoYTI1NjowMCIsInByZWZpeGVzIjpbIjEwLjk5LjAuNy8zMiJdLCJsb2dpbl9nZW4iOjMsImlhdCI6MTc5MDAwMDAwMCwiZXhwIjoxNzkwMDAzNjAwfQ.BGE7P0HeM0XXw9aXxayy4W3XiJ5EFa4mZA5Dj9HqpikdVA7HhZn5M0vjqX65R64wg58WpS1t7hjKni4hitH9BQ"
    );
}

#[test]
fn x25519_public_key_from_a_stored_private_key_is_unchanged() {
    assert_eq!(StaticKeys::from_private(vec![9u8; 32]).unwrap().public_b64(), "V9tLNZ8jrl4Ubk4lEgVnBHIlBjSMFQwUdT0Mkz0E1CE=");
}

#[test]
fn certificate_fingerprints_are_unchanged() {
    assert_eq!(fingerprint_der(b"nqvpn golden certificate"), "sha256:e68f2b1ba1d9e458193d6849b12a4181dc8fc563ff1ac72814c5c22969d638a7");
}

#[test]
fn member_tokens_encode_and_parse_as_before() {
    let t = Token { coordinator: "https://gate.example:9443".into(), secret: "s3cr3t".into(), fp: Some("sha256:ab".into()) };
    let s = "nqv1.ZW5kcG9pbnQ9aHR0cHM6Ly9nYXRlLmV4YW1wbGU6OTQ0MztzZWNyZXQ9czNjcjN0O2ZwPXNoYTI1NjphYg";
    assert_eq!(t.encode(), s);
    assert_eq!(Token::parse(s).unwrap(), t);
}

#[test]
fn control_payloads_keep_their_bincode_layout() {
    // The control wire is bincode, not self-describing: this layout is
    // what every deployed peer decodes.
    let hb = Heartbeat { gen: 42, digest: 0xdead_beef, attached: vec![], mesh_up: vec![1, 2], attached_to: Some(2), usable_mtu: 1350, traffic: None };
    assert_eq!(hex::encode(encode_msg(Kind::Heartbeat, &hb).unwrap()), "01010005000000102afcefbeadde000201020102fb460500");
}
