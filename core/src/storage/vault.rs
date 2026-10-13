use crate::error::{CoreError, CoreResult};
use crate::storage::crypto::{
    decrypt_bytes, encrypt_bytes, generate_dek_32, EncryptedBlob, EncryptionAlgorithm,
};
use crate::storage::key_management::{create_kek, load_kek, KeyStorage};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const LOG_TARGET: &str = "aigc_core::vault";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    pub vault_id: String,
    pub encryption_algorithm: EncryptionAlgorithm,
    pub encryption_at_rest: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultKeyState {
    key_id: String,
    kek_storage: KeyStorage,
    wrapped_dek: EncryptedBlob,
}

/// A vault on disk.
///
/// Concurrency contract: every open instance holds a shared OS lock on
/// `meta/.lock` for its lifetime. Creation and key rotation need the lock
/// exclusively, so rotation only proceeds when this is the sole open instance
/// and can never lose a blob another instance is writing. The OS releases the
/// lock if the process dies, so a crash never leaves a stale lock behind.
pub struct VaultStorage {
    root: PathBuf,
    generation_root: PathBuf,
    dek: [u8; 32],
    cfg: VaultConfig,
    key_state: VaultKeyState,
    lock: fs::File,
}

trait IoContext<T> {
    fn ctx(self, operation: &'static str, path: &Path) -> CoreResult<T>;
}

impl<T> IoContext<T> for std::io::Result<T> {
    fn ctx(self, operation: &'static str, path: &Path) -> CoreResult<T> {
        self.map_err(|error| CoreError::io(operation, path, error))
    }
}

fn vault_state_exists(root: &Path) -> bool {
    let meta = root.join("meta");
    meta.join("vault_config.json").exists()
        || meta.join("key_state.json").exists()
        || meta.join("active_generation").exists()
        || root
            .join("generations/generation-0/meta/key_state.json")
            .exists()
}

fn open_lock_file(meta: &Path) -> CoreResult<fs::File> {
    let path = meta.join(".lock");
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(&path).ctx("open vault lock", &path)
}

impl VaultStorage {
    pub fn create(root: impl AsRef<Path>, cfg: VaultConfig) -> CoreResult<Self> {
        #[cfg(target_os = "macos")]
        let storage = KeyStorage::MACOS_KEYCHAIN;
        #[cfg(target_os = "windows")]
        let storage = KeyStorage::WINDOWS_DPAPI;
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let storage = KeyStorage::FILE_FALLBACK;
        Self::create_with_key_storage(root, cfg, storage)
    }

    #[doc(hidden)]
    pub fn create_with_key_storage(
        root: impl AsRef<Path>,
        cfg: VaultConfig,
        storage: KeyStorage,
    ) -> CoreResult<Self> {
        let root = root.as_ref().to_path_buf();
        reject_symlink_if_present(&root, "VAULT_ROOT_SYMLINK")?;
        let meta = root.join("meta");
        reject_symlink_if_present(&meta, "VAULT_META_SYMLINK")?;
        fs::create_dir_all(&meta).ctx("create vault metadata directory", &meta)?;
        let lock = open_lock_file(&meta)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(if vault_state_exists(&root) {
                    already_exists()
                } else {
                    CoreError::InvalidInput(
                        "VAULT_CREATE_IN_PROGRESS: another operation holds the vault lock".into(),
                    )
                });
            }
            Err(fs::TryLockError::Error(error)) => {
                return Err(CoreError::io("lock vault", meta.join(".lock"), error));
            }
        }
        if vault_state_exists(&root) {
            return Err(already_exists());
        }
        let generation_root = root.join("generations").join("generation-0");
        for directory in ["sqlite", "blobs", "caches", "meta"] {
            let path = generation_root.join(directory);
            fs::create_dir_all(&path).ctx("create vault generation directory", &path)?;
        }

        let dek = generate_dek_32();
        let kek_material = create_kek(
            &cfg.vault_id,
            storage,
            &root.join("meta").join("kek_fallback.bin"),
        )?;
        let wrapped_dek = encrypt_bytes(EncryptionAlgorithm::AES_256_GCM, &kek_material.kek, &dek)?;
        let key_state = VaultKeyState {
            key_id: "kek_v1".to_string(),
            kek_storage: kek_material.storage,
            wrapped_dek,
        };
        let key_state_path = generation_root.join("meta").join("key_state.json");
        fs::write(&key_state_path, serde_json::to_vec_pretty(&key_state)?)
            .ctx("write vault key state", &key_state_path)?;
        sync_tree(&generation_root)?;
        write_synced_replace(
            &root.join("meta").join("vault_config.json"),
            &serde_json::to_vec_pretty(&cfg)?,
        )?;
        publish_generation(&root, "generation-0")?;
        // Created: keep the lock, but shared so other instances may open.
        hold_shared(&lock, &meta)?;
        Ok(Self {
            root,
            generation_root,
            dek,
            cfg,
            key_state,
            lock,
        })
    }

    pub fn open(root: impl AsRef<Path>) -> CoreResult<Self> {
        let root = root.as_ref().to_path_buf();
        reject_symlink_if_present(&root, "VAULT_ROOT_SYMLINK")?;
        let meta = root.join("meta");
        reject_symlink_if_present(&meta, "VAULT_META_SYMLINK")?;
        // Lock before reading any state so a rotation in flight finishes first.
        let lock = open_lock_file(&meta)?;
        lock.lock_shared().ctx("lock vault", &meta.join(".lock"))?;
        let pointer_path = meta.join("active_generation");
        reject_symlink_if_present(&pointer_path, "ACTIVE_GENERATION_SYMLINK")?;
        let config_path = meta.join("vault_config.json");
        let cfg_bytes = fs::read(&config_path).ctx("read vault config", &config_path)?;
        let cfg: VaultConfig = serde_json::from_slice(&cfg_bytes)?;
        let generation_pointer = pointer_path;
        let generation_name = match fs::read_to_string(&generation_pointer) {
            Ok(value) => Some(value),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(CoreError::io(
                    "read active generation",
                    &generation_pointer,
                    error,
                ))
            }
        };
        if generation_name.as_deref().is_some_and(|name| {
            let name = name.trim();
            name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }) {
            return Err(CoreError::InvalidInput(
                "INVALID_ACTIVE_GENERATION: malformed generation pointer".into(),
            ));
        }
        let generation_name = generation_name.or_else(|| {
            root.join("generations/generation-0")
                .is_dir()
                .then(|| "generation-0".to_string())
        });
        let generation_root = generation_name
            .as_deref()
            .map(|name| root.join("generations").join(name.trim()))
            .unwrap_or_else(|| root.clone());
        if generation_name.is_some() {
            let metadata = fs::symlink_metadata(&generation_root)
                .ctx("inspect active generation", &generation_root)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(CoreError::InvalidInput(
                    "INVALID_ACTIVE_GENERATION: active generation must be a real directory".into(),
                ));
            }
        }
        let key_state_path = generation_root.join("meta").join("key_state.json");
        let key_state_bytes =
            fs::read(&key_state_path).ctx("read vault key state", &key_state_path)?;
        let key_state: VaultKeyState = serde_json::from_slice(&key_state_bytes)?;
        let kek_material = load_kek(
            &cfg.vault_id,
            key_state.kek_storage,
            &root.join("meta").join("kek_fallback.bin"),
        )?;
        let dek_bytes = decrypt_bytes(&key_state.wrapped_dek, &kek_material.kek)?;
        if dek_bytes.len() != 32 {
            return Err(CoreError::InvalidInput(
                "wrapped DEK did not unwrap to 32 bytes".to_string(),
            ));
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&dek_bytes);
        Ok(Self {
            root,
            generation_root,
            dek,
            cfg,
            key_state,
            lock,
        })
    }

    /// Write a new blob. The bytes go to a temporary file that is synced and
    /// then published under the final name only if that name is free, so a
    /// failed or interrupted write never leaves a partial blob behind.
    pub fn write_blob(&self, blob_id: &str, plaintext: &[u8]) -> CoreResult<()> {
        use std::io::Write;
        let blob_id = BlobId::try_from(blob_id)?;
        let blobs_dir = self.generation_root.join("blobs");
        let path = blobs_dir.join(format!("{}.bin", blob_id.0));
        if fs::symlink_metadata(&blobs_dir)
            .ctx("inspect blob directory", &blobs_dir)?
            .file_type()
            .is_symlink()
        {
            return Err(CoreError::InvalidInput(
                "SYMLINKED_BLOB_DIRECTORY: symlinked blob directory rejected".into(),
            ));
        }
        let bytes = if self.cfg.encryption_at_rest {
            let enc = encrypt_bytes(self.cfg.encryption_algorithm, &self.dek, plaintext)?;
            serde_json::to_vec(&enc)?
        } else {
            plaintext.to_vec()
        };
        let temporary = blobs_dir.join(format!(".{}.{}.partial", blob_id.0, unique_suffix()?));
        let _temporary_guard = RemoveOnDrop(temporary.clone());
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&temporary).ctx("create blob", &temporary)?;
        file.write_all(&bytes).ctx("write blob", &temporary)?;
        file.sync_all().ctx("sync blob", &temporary)?;
        drop(file);
        #[cfg(test)]
        test_hooks::fail_if_requested(test_hooks::Fault::BlobBeforePublish)?;
        // A hard link fails if the final name exists, so this never replaces a blob.
        fs::hard_link(&temporary, &path).ctx("publish blob", &path)?;
        if let Err(error) = sync_directory(&blobs_dir) {
            log_cleanup_failure("sync blob directory", &error);
        }
        Ok(())
    }

    pub fn read_blob(&self, blob_id: &str) -> CoreResult<Vec<u8>> {
        let blob_id = BlobId::try_from(blob_id)?;
        let blobs_dir = self.generation_root.join("blobs");
        let path = blobs_dir.join(format!("{}.bin", blob_id.0));
        if fs::symlink_metadata(&blobs_dir)
            .ctx("inspect blob directory", &blobs_dir)?
            .file_type()
            .is_symlink()
        {
            return Err(CoreError::InvalidInput(
                "SYMLINKED_BLOB_DIRECTORY: symlinked blob directory rejected".into(),
            ));
        }
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if metadata.file_type().is_symlink() {
                return Err(CoreError::InvalidInput(
                    "SYMLINKED_BLOB_FILE: symlinked blob file rejected".into(),
                ));
            }
        }
        let mut read_options = fs::OpenOptions::new();
        read_options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            read_options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = read_options.open(&path).ctx("open blob", &path)?;
        let mut bytes = Vec::new();
        use std::io::Read;
        file.read_to_end(&mut bytes).ctx("read blob", &path)?;
        if self.cfg.encryption_at_rest {
            let enc: EncryptedBlob = serde_json::from_slice(&bytes)?;
            decrypt_bytes(&enc, &self.dek)
        } else {
            Ok(bytes)
        }
    }

    pub fn write_sqlite_bytes(&self, db_bytes: &[u8]) -> CoreResult<()> {
        let path = self.generation_root.join("sqlite").join("vault.db.enc");
        if self.cfg.encryption_at_rest {
            let enc = encrypt_bytes(self.cfg.encryption_algorithm, &self.dek, db_bytes)?;
            fs::write(&path, serde_json::to_vec(&enc)?).ctx("write vault database", &path)?;
        } else {
            fs::write(&path, db_bytes).ctx("write vault database", &path)?;
        }
        Ok(())
    }

    pub fn read_sqlite_bytes(&self) -> CoreResult<Vec<u8>> {
        let path = self.generation_root.join("sqlite").join("vault.db.enc");
        let bytes = fs::read(&path).ctx("read vault database", &path)?;
        if self.cfg.encryption_at_rest {
            let enc: EncryptedBlob = serde_json::from_slice(&bytes)?;
            decrypt_bytes(&enc, &self.dek)
        } else {
            Ok(bytes)
        }
    }

    /// Rotate the data key. Requires that no other instance has the vault
    /// open (`VAULT_IN_USE` otherwise); see the type-level concurrency contract.
    pub fn rotate_dek(&mut self, new_key_id: &str) -> CoreResult<serde_json::Value> {
        self.rotate_dek_with_checkpoint(new_key_id, |_| Ok(()))
    }

    fn rotate_dek_with_checkpoint<F>(
        &mut self,
        new_key_id: &str,
        checkpoint: F,
    ) -> CoreResult<serde_json::Value>
    where
        F: FnMut(RotationCheckpoint) -> CoreResult<()>,
    {
        self.lock_exclusive_for_rotation()?;
        let result = self.rotate_locked(new_key_id, checkpoint);
        if let Err(error) = hold_shared(&self.lock, &self.root.join("meta")) {
            log_cleanup_failure("restore shared vault lock", &error);
        }
        result
    }

    fn lock_exclusive_for_rotation(&self) -> CoreResult<()> {
        let lock_path = self.root.join("meta").join(".lock");
        // Convert shared -> exclusive. Not atomic on every platform, so on any
        // failure the shared lock is retaken before reporting.
        self.lock.unlock().ctx("unlock vault", &lock_path)?;
        match self.lock.try_lock() {
            Ok(()) => Ok(()),
            Err(fs::TryLockError::WouldBlock) => {
                self.lock.lock_shared().ctx("lock vault", &lock_path)?;
                Err(CoreError::InvalidInput(
                    "VAULT_IN_USE: key rotation requires that no other instance has the vault open"
                        .into(),
                ))
            }
            Err(fs::TryLockError::Error(error)) => {
                self.lock.lock_shared().ctx("lock vault", &lock_path)?;
                Err(CoreError::io("lock vault exclusively", &lock_path, error))
            }
        }
    }

    fn rotate_locked<F>(
        &mut self,
        new_key_id: &str,
        mut checkpoint: F,
    ) -> CoreResult<serde_json::Value>
    where
        F: FnMut(RotationCheckpoint) -> CoreResult<()>,
    {
        let old_key_id = self.key_state.key_id.clone();
        let old_dek = self.dek;
        let new_dek = generate_dek_32();
        let generation_name = format!("generation-{}", unique_suffix()?);
        let legacy_layout = self.generation_root == self.root;
        let generations = self.root.join("generations");
        fs::create_dir_all(&generations).ctx("create generations directory", &generations)?;
        let stage = generations.join(format!(".staging-{generation_name}"));
        let _stage_guard = VaultStageGuard(stage.clone());
        copy_generation(&self.generation_root, &stage, legacy_layout)?;

        let sqlite_path = stage.join("sqlite/vault.db.enc");
        if sqlite_path.exists() {
            let current_db = self.read_sqlite_bytes()?;
            if self.cfg.encryption_at_rest {
                let encrypted =
                    encrypt_bytes(self.cfg.encryption_algorithm, &new_dek, &current_db)?;
                fs::write(&sqlite_path, serde_json::to_vec(&encrypted)?)
                    .ctx("write staged vault database", &sqlite_path)?;
            } else {
                fs::write(&sqlite_path, current_db)
                    .ctx("write staged vault database", &sqlite_path)?;
            }
        }

        let blobs_dir = stage.join("blobs");
        for entry in fs::read_dir(&blobs_dir).ctx("list staged blobs", &blobs_dir)? {
            let path = entry.ctx("list staged blobs", &blobs_dir)?.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("bin") {
                continue;
            }
            if self.cfg.encryption_at_rest {
                let source = self.generation_root.join("blobs").join(
                    path.file_name()
                        .ok_or_else(|| CoreError::InvalidInput("invalid blob filename".into()))?,
                );
                let bytes = fs::read(&source).ctx("read blob for rotation", &source)?;
                let encrypted: EncryptedBlob = serde_json::from_slice(&bytes)?;
                let plaintext = decrypt_bytes(&encrypted, &old_dek)?;
                let replacement =
                    encrypt_bytes(self.cfg.encryption_algorithm, &new_dek, &plaintext)?;
                fs::write(&path, serde_json::to_vec(&replacement)?)
                    .ctx("write rotated blob", &path)?;
            }
        }

        // Wrap new DEK with KEK from configured storage.
        let kek_material = load_kek(
            &self.cfg.vault_id,
            self.key_state.kek_storage,
            &self.root.join("meta").join("kek_fallback.bin"),
        )?;
        let wrapped_dek = encrypt_bytes(
            EncryptionAlgorithm::AES_256_GCM,
            &kek_material.kek,
            &new_dek,
        )?;
        let new_key_state = VaultKeyState {
            key_id: new_key_id.to_string(),
            kek_storage: kek_material.storage,
            wrapped_dek,
        };
        let staged_key_state = stage.join("meta/key_state.json");
        fs::write(
            &staged_key_state,
            serde_json::to_vec_pretty(&new_key_state)?,
        )
        .ctx("write staged key state", &staged_key_state)?;
        checkpoint(RotationCheckpoint::FilesWritten)?;
        sync_tree(&stage)?;
        checkpoint(RotationCheckpoint::GenerationSynced)?;
        let final_path = generations.join(&generation_name);
        fs::rename(&stage, &final_path).ctx("publish staged generation", &final_path)?;
        sync_directory(&generations)?;
        if let Err(error) = checkpoint(RotationCheckpoint::GenerationRenamed) {
            remove_unpublished_generation(&final_path);
            return Err(error);
        }
        if let Err(error) = publish_generation(&self.root, &generation_name) {
            remove_unpublished_generation(&final_path);
            return Err(error);
        }
        let old_generation = std::mem::replace(&mut self.generation_root, final_path);
        self.key_state = new_key_state;
        self.dek = new_dek;
        checkpoint(RotationCheckpoint::PointerPublished)?;
        if legacy_layout {
            remove_legacy_layout(&self.root);
        } else if let Err(error) = fs::remove_dir_all(&old_generation) {
            log_cleanup_failure("remove retired vault generation", &error);
        }
        Ok(serde_json::json!({
            "old_key_id": old_key_id,
            "new_key_id": new_key_id
        }))
    }

    pub fn encryption_status_audit_details(&self) -> serde_json::Value {
        serde_json::json!({
            "encryption_at_rest": self.cfg.encryption_at_rest,
            "algorithm": match self.cfg.encryption_algorithm {
                EncryptionAlgorithm::XCHACHA20_POLY1305 => "XCHACHA20_POLY1305",
                EncryptionAlgorithm::AES_256_GCM => "AES_256_GCM",
            },
            "key_storage": match self.key_state.kek_storage {
                KeyStorage::MACOS_KEYCHAIN => "MACOS_KEYCHAIN",
                KeyStorage::WINDOWS_DPAPI => "WINDOWS_DPAPI",
                KeyStorage::FILE_FALLBACK => "FILE_FALLBACK",
            }
        })
    }
}

impl Drop for VaultStorage {
    fn drop(&mut self) {
        // Closing the handle releases the lock; the explicit unlock is best effort.
        let _ = self.lock.unlock();
    }
}

fn already_exists() -> CoreError {
    CoreError::InvalidInput("VAULT_ALREADY_EXISTS: refusing to overwrite vault state".into())
}

fn hold_shared(lock: &fs::File, meta: &Path) -> CoreResult<()> {
    lock.lock_shared().ctx("lock vault", &meta.join(".lock"))
}

fn unique_suffix() -> CoreResult<u128> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| CoreError::InvalidInput(error.to_string()))?
        .as_nanos();
    Ok(nanos * 1_000 + u128::from(SEQUENCE.fetch_add(1, Ordering::Relaxed) % 1_000))
}

/// Log a cleanup failure without paths: the operation and the error kind only.
fn log_cleanup_failure(operation: &str, error: &(impl CleanupError + ?Sized)) {
    log::warn!(target: LOG_TARGET, "{operation} failed: {:?}", error.kind());
}

trait CleanupError {
    fn kind(&self) -> Option<std::io::ErrorKind>;
}

impl CleanupError for std::io::Error {
    fn kind(&self) -> Option<std::io::ErrorKind> {
        Some(std::io::Error::kind(self))
    }
}

impl CleanupError for CoreError {
    fn kind(&self) -> Option<std::io::ErrorKind> {
        self.io_kind()
    }
}

fn remove_unpublished_generation(path: &Path) {
    if let Err(error) = fs::remove_dir_all(path) {
        log_cleanup_failure("remove unpublished vault generation", &error);
    }
}

/// After a rotation out of the old flat layout, drop the retired data and the
/// key state that wraps the old DEK. `meta/` (config, fallback KEK, pointer,
/// lock) and `generations/` belong to the new layout and stay.
fn remove_legacy_layout(root: &Path) {
    for name in LEGACY_DATA_DIRECTORIES {
        let path = root.join(name);
        if let Err(error) = fs::remove_dir_all(&path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                log_cleanup_failure("remove retired legacy vault data", &error);
            }
        }
    }
    if let Err(error) = fs::remove_file(root.join("meta").join("key_state.json")) {
        if error.kind() != std::io::ErrorKind::NotFound {
            log_cleanup_failure("remove retired legacy key state", &error);
        }
    }
}

const LEGACY_DATA_DIRECTORIES: [&str; 3] = ["sqlite", "blobs", "caches"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RotationCheckpoint {
    FilesWritten,
    GenerationSynced,
    GenerationRenamed,
    PointerPublished,
}

struct VaultStageGuard(PathBuf);

/// Removes a temporary file when dropped; a missing file is fine because the
/// success path may already have consumed it.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.0) {
            if error.kind() != std::io::ErrorKind::NotFound {
                log_cleanup_failure("remove temporary vault file", &error);
            }
        }
    }
}

impl Drop for VaultStageGuard {
    fn drop(&mut self) {
        if self.0.exists() {
            if let Err(error) = fs::remove_dir_all(&self.0) {
                log_cleanup_failure("remove staged vault generation", &error);
            }
        }
    }
}

struct BlobId<'a>(&'a str);

impl<'a> TryFrom<&'a str> for BlobId<'a> {
    type Error = CoreError;

    fn try_from(blob_id: &'a str) -> Result<Self, Self::Error> {
        if blob_id.is_empty()
            || !blob_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(CoreError::InvalidInput(
                "INVALID_BLOB_ID: expected non-empty ASCII letters, digits, underscore, or hyphen"
                    .into(),
            ));
        }
        Ok(Self(blob_id))
    }
}

fn reject_symlink_if_present(path: &Path, code: &str) -> CoreResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(CoreError::InvalidInput(format!(
            "{code}: symlinked vault path rejected"
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CoreError::io("inspect vault path", path, error)),
    }
}

/// Atomically point `meta/active_generation` at `name`. Once the rename
/// succeeds the publish is committed: a failed directory sync afterwards only
/// weakens durability, so it is logged and never reported as a failed publish
/// (the caller would otherwise delete the generation the pointer now names).
fn publish_generation(root: &Path, name: &str) -> CoreResult<()> {
    use std::io::Write;
    let meta = root.join("meta");
    let temporary = meta.join(format!(".active_generation-{}.tmp", unique_suffix()?));
    let _temporary_guard = RemoveOnDrop(temporary.clone());
    let mut pointer = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .ctx("create generation pointer", &temporary)?;
    pointer
        .write_all(name.as_bytes())
        .ctx("write generation pointer", &temporary)?;
    pointer
        .write_all(b"\n")
        .ctx("write generation pointer", &temporary)?;
    pointer
        .sync_all()
        .ctx("sync generation pointer", &temporary)?;
    atomic_replace(&temporary, &meta.join("active_generation"))?;
    #[cfg(test)]
    let synced = test_hooks::fail_if_requested(test_hooks::Fault::DirectorySyncAfterPublish)
        .map_err(|_| std::io::Error::other("injected directory sync failure"))
        .and_then(|()| {
            sync_directory(&meta).map_err(|error| std::io::Error::other(error.to_string()))
        });
    #[cfg(not(test))]
    let synced = sync_directory(&meta);
    if let Err(error) = synced {
        log_cleanup_failure("sync vault metadata after publish", &error);
    }
    Ok(())
}

fn write_synced_replace(path: &Path, bytes: &[u8]) -> CoreResult<()> {
    use std::io::Write;
    let parent = path.parent().ok_or_else(|| {
        CoreError::InvalidInput("INVALID_VAULT_PATH: config path has no parent".into())
    })?;
    let temporary = parent.join(format!(".vault-config-{}.tmp", unique_suffix()?));
    let _temporary_guard = RemoveOnDrop(temporary.clone());
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .ctx("create vault config", &temporary)?;
    file.write_all(bytes)
        .ctx("write vault config", &temporary)?;
    file.sync_all().ctx("sync vault config", &temporary)?;
    atomic_replace(&temporary, path)?;
    sync_directory(parent)?;
    Ok(())
}
fn atomic_replace(source: &Path, destination: &Path) -> CoreResult<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let destination_wide: Vec<u16> = destination
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        // SAFETY: both pointers reference nul-terminated UTF-16 buffers for this call.
        let result = unsafe {
            windows_sys::Win32::Storage::FileSystem::MoveFileExW(
                source_wide.as_ptr(),
                destination_wide.as_ptr(),
                windows_sys::Win32::Storage::FileSystem::MOVEFILE_REPLACE_EXISTING
                    | windows_sys::Win32::Storage::FileSystem::MOVEFILE_WRITE_THROUGH,
            )
        };
        if result == 0 {
            return Err(CoreError::io(
                "replace file",
                destination,
                std::io::Error::last_os_error(),
            ));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        fs::rename(source, destination).ctx("replace file", destination)
    }
}

fn copy_generation(source: &Path, destination: &Path, legacy_layout: bool) -> CoreResult<()> {
    fs::create_dir(destination).ctx("create staged generation", destination)?;
    if !legacy_layout {
        return copy_tree(source, destination);
    }
    // The old flat layout used the vault root as its generation. Copy only the
    // data directories and the key state: the root also holds `generations/`
    // (which would recurse into the staging directory), `vault_config.json`
    // and the fallback KEK, none of which belong in a data generation.
    for name in LEGACY_DATA_DIRECTORIES {
        let from = source.join(name);
        if fs::symlink_metadata(&from).is_ok() {
            let to = destination.join(name);
            fs::create_dir(&to).ctx("create staged directory", &to)?;
            copy_tree(&from, &to)?;
        }
    }
    let meta = destination.join("meta");
    fs::create_dir(&meta).ctx("create staged directory", &meta)?;
    let from = source.join("meta").join("key_state.json");
    let to = meta.join("key_state.json");
    fs::copy(&from, &to).ctx("copy vault key state", &from)?;
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> CoreResult<()> {
    for entry in fs::read_dir(source).ctx("list vault generation", source)? {
        let entry = entry.ctx("list vault generation", source)?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .ctx("inspect vault generation entry", &source_path)?;
        if metadata.file_type().is_symlink() {
            return Err(CoreError::InvalidInput(
                "SYMLINKED_VAULT_GENERATION: refusing to rotate a generation containing symlinks"
                    .into(),
            ));
        }
        if metadata.is_dir() {
            fs::create_dir(&destination_path).ctx("create staged directory", &destination_path)?;
            copy_tree(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            // Interrupted blob writes leave `.partial` files; they are not data.
            if source_path.extension().is_some_and(|ext| ext == "partial") {
                continue;
            }
            fs::copy(&source_path, &destination_path).ctx("copy vault file", &source_path)?;
        } else {
            return Err(CoreError::InvalidInput(
                "INVALID_VAULT_GENERATION: unsupported filesystem entry".into(),
            ));
        }
    }
    Ok(())
}

fn sync_tree(root: &Path) -> CoreResult<()> {
    for entry in fs::read_dir(root).ctx("list directory for sync", root)? {
        let path = entry.ctx("list directory for sync", root)?.path();
        let metadata = fs::symlink_metadata(&path).ctx("inspect path for sync", &path)?;
        if metadata.is_dir() {
            sync_tree(&path)?;
        } else if metadata.is_file() {
            fs::File::open(&path)
                .and_then(|file| file.sync_all())
                .ctx("sync file", &path)?;
        }
    }
    sync_directory(root)?;
    Ok(())
}

fn sync_directory(path: &Path) -> CoreResult<()> {
    #[cfg(unix)]
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .ctx("sync directory", path)?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod test_hooks {
    use crate::error::{CoreError, CoreResult};
    use std::cell::Cell;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum Fault {
        BlobBeforePublish,
        DirectorySyncAfterPublish,
    }

    thread_local! {
        static REQUESTED: Cell<Option<Fault>> = const { Cell::new(None) };
    }

    pub(super) fn inject(fault: Option<Fault>) {
        REQUESTED.with(|requested| requested.set(fault));
    }

    pub(super) fn fail_if_requested(fault: Fault) -> CoreResult<()> {
        if REQUESTED.with(Cell::get) == Some(fault) {
            return Err(CoreError::InvalidInput("injected fault".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod rotation_fault_tests {
    use super::*;

    #[test]
    fn rotation_interruption_at_each_publication_boundary_reopens_a_complete_generation() {
        for failed_stage in [
            RotationCheckpoint::FilesWritten,
            RotationCheckpoint::GenerationSynced,
            RotationCheckpoint::GenerationRenamed,
            RotationCheckpoint::PointerPublished,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let config = VaultConfig {
                vault_id: format!("v_fault_{failed_stage:?}"),
                encryption_algorithm: EncryptionAlgorithm::AES_256_GCM,
                encryption_at_rest: true,
            };
            let mut vault = VaultStorage::create_with_key_storage(
                temp.path(),
                config,
                KeyStorage::FILE_FALLBACK,
            )
            .unwrap();
            vault.write_blob("one", b"first blob").unwrap();
            vault.write_blob("two", b"second blob").unwrap();
            vault.write_sqlite_bytes(b"sqlite payload").unwrap();

            let result = vault.rotate_dek_with_checkpoint("rotated", |stage| {
                if stage == failed_stage {
                    Err(CoreError::InvalidInput("injected interruption".into()))
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err(), "{failed_stage:?}");

            let reopened = VaultStorage::open(temp.path()).unwrap();
            assert_eq!(reopened.read_blob("one").unwrap(), b"first blob");
            assert_eq!(reopened.read_blob("two").unwrap(), b"second blob");
            assert_eq!(reopened.read_sqlite_bytes().unwrap(), b"sqlite payload");
            let active_key_id = reopened.key_state.key_id.as_str();
            assert_eq!(
                active_key_id == "rotated",
                failed_stage == RotationCheckpoint::PointerPublished
            );
        }
    }

    fn plaintext_free_vault(root: &Path, id: &str) -> VaultStorage {
        VaultStorage::create_with_key_storage(
            root,
            VaultConfig {
                vault_id: id.to_string(),
                encryption_algorithm: EncryptionAlgorithm::AES_256_GCM,
                encryption_at_rest: true,
            },
            KeyStorage::FILE_FALLBACK,
        )
        .unwrap()
    }

    #[test]
    fn directory_sync_failure_after_pointer_publish_does_not_fail_or_orphan_the_rotation() {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = plaintext_free_vault(temp.path(), "v_post_commit_sync");
        vault.write_blob("kept", b"still here").unwrap();

        test_hooks::inject(Some(test_hooks::Fault::DirectorySyncAfterPublish));
        let result = vault.rotate_dek("rotated");
        test_hooks::inject(None);
        result.expect("a committed publish must not be reported as failed");

        let reopened = VaultStorage::open(temp.path()).unwrap();
        assert_eq!(reopened.key_state.key_id, "rotated");
        assert_eq!(reopened.read_blob("kept").unwrap(), b"still here");
        assert!(reopened.generation_root.is_dir());
    }

    #[test]
    fn failed_blob_write_leaves_no_partial_file_and_does_not_block_rotation() {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = plaintext_free_vault(temp.path(), "v_partial_blob");
        vault.write_blob("good", b"intact").unwrap();

        test_hooks::inject(Some(test_hooks::Fault::BlobBeforePublish));
        let failed = vault.write_blob("broken", b"never published");
        test_hooks::inject(None);
        assert!(failed.is_err());

        let blobs = vault.generation_root.join("blobs");
        let names: Vec<_> = fs::read_dir(&blobs)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["good.bin".to_string()]);

        vault
            .rotate_dek("rotated")
            .expect("rotation is not blocked");
        vault.write_blob("broken", b"second attempt").unwrap();
        assert_eq!(vault.read_blob("broken").unwrap(), b"second attempt");
        assert_eq!(vault.read_blob("good").unwrap(), b"intact");
    }

    #[test]
    fn a_stale_partial_blob_is_not_carried_into_the_next_generation() {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = plaintext_free_vault(temp.path(), "v_stale_partial");
        vault.write_blob("good", b"intact").unwrap();
        fs::write(
            vault.generation_root.join("blobs/.good.1.partial"),
            b"{trunc",
        )
        .unwrap();
        vault.rotate_dek("rotated").unwrap();
        assert!(!vault.generation_root.join("blobs/.good.1.partial").exists());
        assert_eq!(vault.read_blob("good").unwrap(), b"intact");
    }
}
