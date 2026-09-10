use aigc_core::storage::crypto::{
    decrypt_bytes, encrypt_bytes, generate_dek_32, EncryptedBlob, EncryptionAlgorithm,
};

#[test]
fn xchacha20_poly1305_roundtrip() {
    let key = generate_dek_32();
    let pt = b"secret payload";
    let enc = encrypt_bytes(EncryptionAlgorithm::XCHACHA20_POLY1305, &key, pt).unwrap();
    let dec = decrypt_bytes(&enc, &key).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn aes_256_gcm_roundtrip() {
    let key = generate_dek_32();
    let pt = b"secret payload";
    let enc = encrypt_bytes(EncryptionAlgorithm::AES_256_GCM, &key, pt).unwrap();
    let dec = decrypt_bytes(&enc, &key).unwrap();
    assert_eq!(dec, pt);
}

// --- non-happy-path coverage for the chacha20poly1305 0.11 / rand 0.10 migration ---
//
// Before this, the whole file was the two round trips above: zero assertions on tampering,
// foreign keys, malformed input, or the RNG. AGENTS.md makes at least two non-happy-path
// assertions a blocking requirement for any production change, and a crypto path is the last
// place a green suite should be allowed to mean "the happy case still works".

fn tamper(mut blob: EncryptedBlob) -> EncryptedBlob {
    let last = blob.ciphertext.len() - 1;
    blob.ciphertext[last] ^= 0x01;
    blob
}

#[test]
fn tampered_ciphertext_is_rejected_for_both_algorithms() {
    for algo in [
        EncryptionAlgorithm::XCHACHA20_POLY1305,
        EncryptionAlgorithm::AES_256_GCM,
    ] {
        let key = generate_dek_32();
        let enc = encrypt_bytes(algo, &key, b"secret payload").unwrap();
        let err = decrypt_bytes(&tamper(enc), &key).unwrap_err();
        assert!(
            err.to_string().contains("decryption failed"),
            "AEAD tag must reject tampered ciphertext, got: {err}"
        );
    }
}

#[test]
fn wrong_key_is_rejected_for_both_algorithms() {
    for algo in [
        EncryptionAlgorithm::XCHACHA20_POLY1305,
        EncryptionAlgorithm::AES_256_GCM,
    ] {
        let enc = encrypt_bytes(algo, &generate_dek_32(), b"secret payload").unwrap();
        let err = decrypt_bytes(&enc, &generate_dek_32()).unwrap_err();
        assert!(
            err.to_string().contains("decryption failed"),
            "decryption under a foreign key must fail, got: {err}"
        );
    }
}

#[test]
fn malformed_nonce_length_is_rejected_not_panicking() {
    // Guards the exact path the migration rewrote (from_slice -> try_from). blob.nonce is
    // deserialized, so its length is untrusted; a wrong length must be an error, not a panic.
    for (algo, expected, bad_len) in [
        (
            EncryptionAlgorithm::XCHACHA20_POLY1305,
            "XChaCha20 nonce must be 24 bytes",
            12usize,
        ),
        (
            EncryptionAlgorithm::AES_256_GCM,
            "AES-GCM nonce must be 12 bytes",
            24usize,
        ),
    ] {
        let key = generate_dek_32();
        let mut enc = encrypt_bytes(algo, &key, b"secret payload").unwrap();
        enc.nonce = vec![0u8; bad_len];
        let err = decrypt_bytes(&enc, &key).unwrap_err();
        assert!(
            err.to_string().contains(expected),
            "expected a length rejection, got: {err}"
        );
    }
}

#[test]
fn empty_nonce_is_rejected() {
    let key = generate_dek_32();
    let mut enc = encrypt_bytes(EncryptionAlgorithm::XCHACHA20_POLY1305, &key, b"x").unwrap();
    enc.nonce.clear();
    assert!(decrypt_bytes(&enc, &key).is_err());
}

#[test]
fn algorithm_field_mismatch_is_rejected() {
    // A blob whose algorithm tag is flipped must not decrypt: the 24-byte XChaCha nonce
    // fails the AES branch's 12-byte guard.
    let key = generate_dek_32();
    let mut enc = encrypt_bytes(EncryptionAlgorithm::XCHACHA20_POLY1305, &key, b"x").unwrap();
    enc.algorithm = EncryptionAlgorithm::AES_256_GCM;
    assert!(decrypt_bytes(&enc, &key).is_err());
}

#[test]
fn nonces_and_keys_are_not_reused() {
    // The only assertion here covering the rand 0.9 -> 0.10 lane (RngCore -> Rng,
    // rand::rng().fill_bytes). Nonce reuse under a fixed key is catastrophic for both AEADs,
    // so a silent RNG regression is severe rather than merely wrong.
    assert_ne!(generate_dek_32(), generate_dek_32(), "DEKs must not repeat");

    let key = generate_dek_32();
    let a = encrypt_bytes(EncryptionAlgorithm::XCHACHA20_POLY1305, &key, b"same").unwrap();
    let b = encrypt_bytes(EncryptionAlgorithm::XCHACHA20_POLY1305, &key, b"same").unwrap();
    assert_ne!(a.nonce, b.nonce, "nonces must not repeat under a fixed key");
    assert_ne!(
        a.ciphertext, b.ciphertext,
        "identical plaintext must not yield identical ciphertext"
    );
    assert_eq!(a.nonce.len(), 24);
    assert_eq!(b.nonce.len(), 24);
}
