use aigc_core::storage::crypto::EncryptionAlgorithm;
use aigc_core::storage::key_management::KeyStorage;
use aigc_core::storage::vault::{VaultConfig, VaultStorage};

fn create_vault(
    root: &std::path::Path,
    cfg: VaultConfig,
) -> aigc_core::error::CoreResult<VaultStorage> {
    VaultStorage::create_with_key_storage(root, cfg, KeyStorage::FILE_FALLBACK)
}

#[test]
fn vault_blob_and_sqlite_are_encrypted_at_rest() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = VaultConfig {
        vault_id: "v_test".to_string(),
        encryption_algorithm: EncryptionAlgorithm::XCHACHA20_POLY1305,
        encryption_at_rest: true,
    };
    let vault = create_vault(dir.path(), cfg).unwrap();

    let blob_pt = b"top-secret-blob";
    let db_pt = b"sqlite-raw-bytes";
    vault.write_blob("b1", blob_pt).unwrap();
    vault.write_sqlite_bytes(db_pt).unwrap();

    let generation = dir.path().join("generations/generation-0");
    let blob_ct_disk = std::fs::read(generation.join("blobs/b1.bin")).unwrap();
    let db_ct_disk = std::fs::read(generation.join("sqlite/vault.db.enc")).unwrap();
    assert!(!String::from_utf8_lossy(&blob_ct_disk).contains("top-secret-blob"));
    assert!(!String::from_utf8_lossy(&db_ct_disk).contains("sqlite-raw-bytes"));

    let opened = VaultStorage::open(dir.path()).unwrap();
    assert_eq!(opened.read_blob("b1").unwrap(), blob_pt);
    assert_eq!(opened.read_sqlite_bytes().unwrap(), db_pt);
}

#[test]
fn vault_dek_rotation_reencrypts_and_preserves_readability() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = VaultConfig {
        vault_id: "v_rotate".to_string(),
        encryption_algorithm: EncryptionAlgorithm::AES_256_GCM,
        encryption_at_rest: true,
    };
    let mut vault = create_vault(dir.path(), cfg).unwrap();
    vault.write_blob("b1", b"alpha").unwrap();
    vault.write_sqlite_bytes(b"db-bytes").unwrap();

    let ev = vault.rotate_dek("kek_v2").unwrap();
    assert_eq!(
        ev.get("old_key_id").and_then(|x| x.as_str()).unwrap(),
        "kek_v1"
    );
    assert_eq!(
        ev.get("new_key_id").and_then(|x| x.as_str()).unwrap(),
        "kek_v2"
    );

    assert_eq!(vault.read_blob("b1").unwrap(), b"alpha");
    assert_eq!(vault.read_sqlite_bytes().unwrap(), b"db-bytes");

    let reopened = VaultStorage::open(dir.path()).unwrap();
    assert_eq!(reopened.read_blob("b1").unwrap(), b"alpha");
    assert_eq!(reopened.read_sqlite_bytes().unwrap(), b"db-bytes");
}

#[test]
fn create_refuses_existing_vault_and_preserves_original_key_state() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = VaultConfig {
        vault_id: "v_existing".to_string(),
        encryption_algorithm: EncryptionAlgorithm::AES_256_GCM,
        encryption_at_rest: true,
    };
    let vault = create_vault(dir.path(), cfg.clone()).unwrap();
    vault.write_blob("keep", b"original").unwrap();
    let key_state = std::fs::read(
        dir.path()
            .join("generations/generation-0/meta/key_state.json"),
    )
    .unwrap();
    assert!(create_vault(dir.path(), cfg).is_err());
    assert_eq!(
        std::fs::read(
            dir.path()
                .join("generations/generation-0/meta/key_state.json")
        )
        .unwrap(),
        key_state
    );
    assert_eq!(
        VaultStorage::open(dir.path())
            .unwrap()
            .read_blob("keep")
            .unwrap(),
        b"original"
    );
}

#[test]
fn first_generation_remains_openable_if_initial_pointer_publish_was_interrupted() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = VaultConfig {
        vault_id: "v_initial_publish".to_string(),
        encryption_algorithm: EncryptionAlgorithm::AES_256_GCM,
        encryption_at_rest: true,
    };
    let vault = create_vault(dir.path(), cfg).unwrap();
    vault.write_blob("kept", b"readable").unwrap();
    std::fs::remove_file(dir.path().join("meta/active_generation")).unwrap();
    let reopened = VaultStorage::open(dir.path()).unwrap();
    assert_eq!(reopened.read_blob("kept").unwrap(), b"readable");
}

#[test]
fn blob_ids_reject_traversal_absolute_and_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = VaultConfig {
        vault_id: "v_paths".to_string(),
        encryption_algorithm: EncryptionAlgorithm::AES_256_GCM,
        encryption_at_rest: false,
    };
    let vault = create_vault(dir.path(), cfg).unwrap();
    for invalid in ["../escape", "/absolute", "", "with.dot"] {
        assert!(vault.write_blob(invalid, b"x").is_err());
    }
    vault.write_blob("safe", b"one").unwrap();
    assert!(vault.write_blob("safe", b"two").is_err());
    assert_eq!(vault.read_blob("safe").unwrap(), b"one");
    assert!(!dir.path().parent().unwrap().join("escape.bin").exists());
}

#[test]
fn open_with_missing_recorded_file_key_fails_without_creating_a_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = VaultConfig {
        vault_id: "v_missing_key".to_string(),
        encryption_algorithm: EncryptionAlgorithm::AES_256_GCM,
        encryption_at_rest: true,
    };
    let _vault = create_vault(dir.path(), cfg).unwrap();
    let key_path = dir.path().join("meta/kek_fallback.bin");
    std::fs::remove_file(&key_path).unwrap();
    let error = VaultStorage::open(dir.path()).err().unwrap().to_string();
    assert!(error.contains("KEY_PROVIDER_MISSING"), "{error}");
    assert!(!key_path.exists());
}

#[test]
fn open_with_denied_recorded_file_key_reports_access_failure_without_replacing_it() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = VaultConfig {
        vault_id: "v_denied_key".to_string(),
        encryption_algorithm: EncryptionAlgorithm::AES_256_GCM,
        encryption_at_rest: true,
    };
    let _vault = create_vault(dir.path(), cfg).unwrap();
    let key_path = dir.path().join("meta/kek_fallback.bin");
    std::fs::remove_file(&key_path).unwrap();
    std::fs::create_dir(&key_path).unwrap();
    let error = VaultStorage::open(dir.path()).err().unwrap().to_string();
    assert!(error.contains("KEY_PROVIDER_ACCESS_FAILED"), "{error}");
    assert!(key_path.is_dir());
}

#[test]
fn plaintext_sqlite_remains_plaintext_after_rotation_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = VaultConfig {
        vault_id: "v_plain_rotate".to_string(),
        encryption_algorithm: EncryptionAlgorithm::AES_256_GCM,
        encryption_at_rest: false,
    };
    let mut vault = create_vault(dir.path(), cfg).unwrap();
    vault.write_blob("plain", b"blob").unwrap();
    vault.write_sqlite_bytes(b"plain sqlite").unwrap();
    vault.rotate_dek("kek_v2").unwrap();
    let active = std::fs::read_to_string(dir.path().join("meta/active_generation")).unwrap();
    let active = dir.path().join("generations").join(active.trim());
    assert_eq!(
        std::fs::read(active.join("sqlite/vault.db.enc")).unwrap(),
        b"plain sqlite"
    );
    let reopened = VaultStorage::open(dir.path()).unwrap();
    assert_eq!(reopened.read_blob("plain").unwrap(), b"blob");
    assert_eq!(reopened.read_sqlite_bytes().unwrap(), b"plain sqlite");
}

#[test]
fn failed_staged_rotation_keeps_previous_generation_readable() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = VaultConfig {
        vault_id: "v_failed_rotate".to_string(),
        encryption_algorithm: EncryptionAlgorithm::AES_256_GCM,
        encryption_at_rest: true,
    };
    let mut vault = create_vault(dir.path(), cfg).unwrap();
    vault.write_blob("good", b"preserved").unwrap();
    vault.write_blob("corrupt", b"do not rotate").unwrap();
    std::fs::write(
        dir.path()
            .join("generations/generation-0/blobs/corrupt.bin"),
        b"not encrypted json",
    )
    .unwrap();
    assert!(vault.rotate_dek("kek_v2").is_err());
    assert_eq!(vault.read_blob("good").unwrap(), b"preserved");
    let reopened = VaultStorage::open(dir.path()).unwrap();
    assert_eq!(reopened.read_blob("good").unwrap(), b"preserved");
}

#[cfg(unix)]
#[test]
fn blob_writes_reject_a_symlinked_blob_directory() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let cfg = VaultConfig {
        vault_id: "v_symlink_blob".to_string(),
        encryption_algorithm: EncryptionAlgorithm::AES_256_GCM,
        encryption_at_rest: false,
    };
    let vault = create_vault(dir.path(), cfg).unwrap();
    let blob_dir = dir.path().join("generations/generation-0/blobs");
    std::fs::remove_dir(&blob_dir).unwrap();
    symlink(external.path(), &blob_dir).unwrap();
    assert!(vault.write_blob("escape", b"outside").is_err());
    assert!(!external.path().join("escape.bin").exists());
}

#[cfg(unix)]
#[test]
fn blob_reads_reject_symlinked_files() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let external = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(external.path(), b"outside secret").unwrap();
    let cfg = VaultConfig {
        vault_id: "v_symlink_file".to_string(),
        encryption_algorithm: EncryptionAlgorithm::AES_256_GCM,
        encryption_at_rest: false,
    };
    let vault = create_vault(dir.path(), cfg).unwrap();
    let target = dir.path().join("generations/generation-0/blobs/secret.bin");
    symlink(external.path(), &target).unwrap();
    assert!(vault
        .read_blob("secret")
        .unwrap_err()
        .to_string()
        .contains("SYMLINKED_BLOB_FILE"));
    assert!(vault.write_blob("secret", b"replace").is_err());
    assert_eq!(std::fs::read(external.path()).unwrap(), b"outside secret");
}

#[test]
fn encryption_status_payload_contains_required_fields() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = VaultConfig {
        vault_id: "v_status".to_string(),
        encryption_algorithm: EncryptionAlgorithm::XCHACHA20_POLY1305,
        encryption_at_rest: true,
    };
    let vault = create_vault(dir.path(), cfg).unwrap();
    let d = vault.encryption_status_audit_details();
    assert_eq!(
        d.get("encryption_at_rest").and_then(|x| x.as_bool()),
        Some(true)
    );
    assert_eq!(
        d.get("algorithm").and_then(|x| x.as_str()),
        Some("XCHACHA20_POLY1305")
    );
    assert!(d.get("key_storage").is_some());
}
