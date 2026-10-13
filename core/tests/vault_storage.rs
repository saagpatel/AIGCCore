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

fn encrypted_cfg(id: &str) -> VaultConfig {
    VaultConfig {
        vault_id: id.to_string(),
        encryption_algorithm: EncryptionAlgorithm::AES_256_GCM,
        encryption_at_rest: true,
    }
}

/// Rebuild the pre-generations flat layout from a fresh vault: data and key
/// state directly under the vault root, no `generations/` and no pointer.
fn convert_to_flat_layout(root: &std::path::Path) {
    let generation = root.join("generations/generation-0");
    for name in ["sqlite", "blobs", "caches"] {
        std::fs::rename(generation.join(name), root.join(name)).unwrap();
    }
    std::fs::rename(
        generation.join("meta/key_state.json"),
        root.join("meta/key_state.json"),
    )
    .unwrap();
    std::fs::remove_dir_all(root.join("generations")).unwrap();
    std::fs::remove_file(root.join("meta/active_generation")).unwrap();
}

#[test]
fn rotating_a_flat_layout_vault_migrates_it_and_retires_the_old_data() {
    let dir = tempfile::tempdir().unwrap();
    {
        let vault = create_vault(dir.path(), encrypted_cfg("v_flat")).unwrap();
        vault.write_blob("one", b"first").unwrap();
        vault.write_blob("two", b"second").unwrap();
        vault.write_sqlite_bytes(b"database").unwrap();
    }
    convert_to_flat_layout(dir.path());

    let mut vault = VaultStorage::open(dir.path()).expect("flat layout still opens");
    assert_eq!(vault.read_blob("one").unwrap(), b"first");
    vault.rotate_dek("kek_v2").expect("flat layout rotates");

    let reopened = VaultStorage::open(dir.path()).unwrap();
    assert_eq!(reopened.read_blob("one").unwrap(), b"first");
    assert_eq!(reopened.read_blob("two").unwrap(), b"second");
    assert_eq!(reopened.read_sqlite_bytes().unwrap(), b"database");
    assert!(dir.path().join("meta/active_generation").is_file());
    // The old DEK's data and its wrapping key state are gone from the root.
    for retired in ["blobs", "sqlite", "caches", "meta/key_state.json"] {
        assert!(!dir.path().join(retired).exists(), "{retired}");
    }
    // The fallback KEK and config were never copied into a data generation.
    let generations: Vec<_> = std::fs::read_dir(dir.path().join("generations"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(generations.len(), 1, "{generations:?}");
    assert!(!generations[0].join("meta/kek_fallback.bin").exists());
    assert!(!generations[0].join("vault_config.json").exists());
}

#[test]
fn create_succeeds_after_a_crash_left_lock_files_behind() {
    let dir = tempfile::tempdir().unwrap();
    let meta = dir.path().join("meta");
    std::fs::create_dir_all(&meta).unwrap();
    // Leftovers a process killed mid-create would have left: the old marker
    // file and an unlocked lock file. Neither may block a later create.
    std::fs::write(meta.join(".vault_create.lock"), b"").unwrap();
    std::fs::write(meta.join(".lock"), b"").unwrap();

    let vault = create_vault(dir.path(), encrypted_cfg("v_after_crash")).unwrap();
    vault.write_blob("fresh", b"ok").unwrap();
}

#[test]
fn rotation_requires_sole_ownership_and_other_instances_keep_working_afterwards() {
    let dir = tempfile::tempdir().unwrap();
    let mut first = create_vault(dir.path(), encrypted_cfg("v_lock")).unwrap();
    first.write_blob("before", b"one").unwrap();
    let second = VaultStorage::open(dir.path()).unwrap();

    let error = first.rotate_dek("kek_v2").unwrap_err().to_string();
    assert!(error.contains("VAULT_IN_USE"), "{error}");
    // The refused rotation changed nothing and the first instance still works.
    first.write_blob("after", b"two").unwrap();
    assert_eq!(second.read_blob("after").unwrap(), b"two");

    drop(second);
    first.rotate_dek("kek_v2").unwrap();
    // After rotating, the first instance holds the lock shared again.
    let third = VaultStorage::open(dir.path()).unwrap();
    assert_eq!(third.read_blob("before").unwrap(), b"one");
    assert_eq!(third.read_blob("after").unwrap(), b"two");
}

#[test]
fn concurrent_create_attempts_cannot_both_succeed() {
    let dir = tempfile::tempdir().unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let root = dir.path().to_path_buf();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                create_vault(&root, encrypted_cfg("v_race")).map(|vault| {
                    // Keep the winner alive so it keeps holding its lock.
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    drop(vault);
                })
            })
        })
        .collect();
    let successes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .filter(Result::is_ok)
        .count();
    assert_eq!(successes, 1);
}

#[test]
fn vault_io_errors_name_the_operation_and_path() {
    let dir = tempfile::tempdir().unwrap();
    let error = VaultStorage::open(dir.path().join("missing"))
        .err()
        .unwrap();
    let message = error.to_string();
    assert!(message.contains("vault lock"), "{message}");
    assert!(message.contains("missing"), "{message}");
}
