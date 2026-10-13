use crate::error::{CoreError, CoreResult};
use crate::storage::crypto::{
    decrypt_bytes, encrypt_bytes, generate_dek_32, EncryptedBlob, EncryptionAlgorithm,
};
use crate::storage::key_management::{create_kek, load_kek, KeyStorage};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

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

pub struct VaultStorage {
    root: PathBuf,
    generation_root: PathBuf,
    dek: [u8; 32],
    cfg: VaultConfig,
    key_state: VaultKeyState,
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
        fs::create_dir_all(&meta)?;
        let creation_lock = meta.join(".vault_create.lock");
        let _creation_guard = VaultFileGuard::create(creation_lock)?;
        if meta.join("vault_config.json").exists()
            || meta.join("key_state.json").exists()
            || meta.join("active_generation").exists()
            || root
                .join("generations/generation-0/meta/key_state.json")
                .exists()
        {
            return Err(CoreError::InvalidInput(
                "VAULT_ALREADY_EXISTS: refusing to overwrite vault state".into(),
            ));
        }
        let generation_root = root.join("generations").join("generation-0");
        fs::create_dir_all(generation_root.join("sqlite"))?;
        fs::create_dir_all(generation_root.join("blobs"))?;
        fs::create_dir_all(generation_root.join("caches"))?;
        fs::create_dir_all(generation_root.join("meta"))?;

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
        fs::write(
            generation_root.join("meta").join("key_state.json"),
            serde_json::to_vec_pretty(&key_state)?,
        )?;
        sync_tree(&generation_root)?;
        write_synced_replace(
            &root.join("meta").join("vault_config.json"),
            &serde_json::to_vec_pretty(&cfg)?,
        )?;
        publish_generation(&root, "generation-0")?;
        Ok(Self {
            root,
            generation_root,
            dek,
            cfg,
            key_state,
        })
    }

    pub fn open(root: impl AsRef<Path>) -> CoreResult<Self> {
        let root = root.as_ref().to_path_buf();
        reject_symlink_if_present(&root, "VAULT_ROOT_SYMLINK")?;
        let meta = root.join("meta");
        reject_symlink_if_present(&meta, "VAULT_META_SYMLINK")?;
        let pointer_path = meta.join("active_generation");
        reject_symlink_if_present(&pointer_path, "ACTIVE_GENERATION_SYMLINK")?;
        let cfg_bytes = fs::read(meta.join("vault_config.json"))?;
        let cfg: VaultConfig = serde_json::from_slice(&cfg_bytes)?;
        let generation_pointer = pointer_path;
        let generation_name = match fs::read_to_string(&generation_pointer) {
            Ok(value) => Some(value),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
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
            let metadata = fs::symlink_metadata(&generation_root)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(CoreError::InvalidInput(
                    "INVALID_ACTIVE_GENERATION: active generation must be a real directory".into(),
                ));
            }
        }
        let key_state_path = generation_root.join("meta").join("key_state.json");
        let key_state_bytes = fs::read(key_state_path)?;
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
        })
    }

    pub fn write_blob(&self, blob_id: &str, plaintext: &[u8]) -> CoreResult<()> {
        let blob_id = BlobId::try_from(blob_id)?;
        let blobs_dir = self.generation_root.join("blobs");
        let path = blobs_dir.join(format!("{}.bin", blob_id.0));
        if fs::symlink_metadata(&blobs_dir)?.file_type().is_symlink() {
            return Err(CoreError::InvalidInput(
                "SYMLINKED_BLOB_DIRECTORY: symlinked blob directory rejected".into(),
            ));
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(path)?;
        if self.cfg.encryption_at_rest {
            let enc = encrypt_bytes(self.cfg.encryption_algorithm, &self.dek, plaintext)?;
            use std::io::Write;
            file.write_all(&serde_json::to_vec(&enc)?)?;
        } else {
            use std::io::Write;
            file.write_all(plaintext)?;
        }
        Ok(())
    }

    pub fn read_blob(&self, blob_id: &str) -> CoreResult<Vec<u8>> {
        let blob_id = BlobId::try_from(blob_id)?;
        let blobs_dir = self.generation_root.join("blobs");
        let path = blobs_dir.join(format!("{}.bin", blob_id.0));
        if fs::symlink_metadata(&blobs_dir)?.file_type().is_symlink() {
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
        let mut file = read_options.open(path)?;
        let mut bytes = Vec::new();
        use std::io::Read;
        file.read_to_end(&mut bytes)?;
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
            fs::write(path, serde_json::to_vec(&enc)?)?;
        } else {
            fs::write(path, db_bytes)?;
        }
        Ok(())
    }

    pub fn read_sqlite_bytes(&self) -> CoreResult<Vec<u8>> {
        let path = self.generation_root.join("sqlite").join("vault.db.enc");
        let bytes = fs::read(path)?;
        if self.cfg.encryption_at_rest {
            let enc: EncryptedBlob = serde_json::from_slice(&bytes)?;
            decrypt_bytes(&enc, &self.dek)
        } else {
            Ok(bytes)
        }
    }

    pub fn rotate_dek(&mut self, new_key_id: &str) -> CoreResult<serde_json::Value> {
        self.rotate_dek_with_checkpoint(new_key_id, |_| Ok(()))
    }

    fn rotate_dek_with_checkpoint<F>(
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
        let generation_name = format!(
            "generation-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| CoreError::InvalidInput(error.to_string()))?
                .as_nanos()
        );
        let generations = self.root.join("generations");
        fs::create_dir_all(&generations)?;
        let stage = generations.join(format!(".staging-{generation_name}"));
        let _stage_guard = VaultStageGuard(stage.clone());
        copy_generation(&self.generation_root, &stage)?;

        let sqlite_path = stage.join("sqlite/vault.db.enc");
        if sqlite_path.exists() {
            let current_db = self.read_sqlite_bytes()?;
            if self.cfg.encryption_at_rest {
                let encrypted =
                    encrypt_bytes(self.cfg.encryption_algorithm, &new_dek, &current_db)?;
                fs::write(&sqlite_path, serde_json::to_vec(&encrypted)?)?;
            } else {
                fs::write(&sqlite_path, current_db)?;
            }
        }

        let blobs_dir = stage.join("blobs");
        for entry in fs::read_dir(&blobs_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("bin") {
                continue;
            }
            if self.cfg.encryption_at_rest {
                let source = self.generation_root.join("blobs").join(
                    path.file_name()
                        .ok_or_else(|| CoreError::InvalidInput("invalid blob filename".into()))?,
                );
                let bytes = fs::read(source)?;
                let encrypted: EncryptedBlob = serde_json::from_slice(&bytes)?;
                let plaintext = decrypt_bytes(&encrypted, &old_dek)?;
                let replacement =
                    encrypt_bytes(self.cfg.encryption_algorithm, &new_dek, &plaintext)?;
                fs::write(&path, serde_json::to_vec(&replacement)?)?;
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
        fs::write(
            stage.join("meta/key_state.json"),
            serde_json::to_vec_pretty(&new_key_state)?,
        )?;
        checkpoint(RotationCheckpoint::FilesWritten)?;
        sync_tree(&stage)?;
        checkpoint(RotationCheckpoint::GenerationSynced)?;
        let final_path = generations.join(&generation_name);
        fs::rename(&stage, &final_path)?;
        sync_directory(&generations)?;
        if let Err(error) = checkpoint(RotationCheckpoint::GenerationRenamed) {
            if let Err(cleanup_error) = fs::remove_dir_all(&final_path) {
                eprintln!("failed to remove unpublished vault generation: {cleanup_error}");
            }
            return Err(error);
        }
        if let Err(error) = publish_generation(&self.root, &generation_name) {
            if let Err(cleanup_error) = fs::remove_dir_all(&final_path) {
                eprintln!("failed to remove unpublished vault generation: {cleanup_error}");
            }
            return Err(error);
        }
        let old_generation = std::mem::replace(&mut self.generation_root, final_path);
        self.key_state = new_key_state;
        self.dek = new_dek;
        checkpoint(RotationCheckpoint::PointerPublished)?;
        if old_generation != self.root {
            if let Err(error) = fs::remove_dir_all(old_generation) {
                eprintln!("failed to remove retired vault generation: {error}");
            }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RotationCheckpoint {
    FilesWritten,
    GenerationSynced,
    GenerationRenamed,
    PointerPublished,
}

struct VaultStageGuard(PathBuf);

struct VaultFileGuard(PathBuf);

impl VaultFileGuard {
    fn create(path: PathBuf) -> CoreResult<Self> {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    CoreError::InvalidInput(
                        "VAULT_CREATE_IN_PROGRESS: another create operation holds the vault lock"
                            .into(),
                    )
                } else {
                    error.into()
                }
            })?;
        Ok(Self(path))
    }
}

impl Drop for VaultFileGuard {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.0) {
            if error.kind() != std::io::ErrorKind::NotFound {
                eprintln!("failed to remove vault create lock: {error}");
            }
        }
    }
}

impl Drop for VaultStageGuard {
    fn drop(&mut self) {
        if self.0.exists() {
            if let Err(error) = fs::remove_dir_all(&self.0) {
                eprintln!("failed to remove staged vault generation: {error}");
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
        Err(error) => Err(error.into()),
    }
}

fn publish_generation(root: &Path, name: &str) -> CoreResult<()> {
    let meta = root.join("meta");
    let sequence = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| CoreError::InvalidInput(error.to_string()))?
        .as_nanos();
    let temporary = meta.join(format!(".active_generation-{sequence}.tmp"));
    let _temporary_guard = VaultFileGuard::create(temporary.clone())?;
    let mut pointer = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&temporary)?;
    use std::io::Write;
    pointer.write_all(name.as_bytes())?;
    pointer.write_all(b"\n")?;
    pointer.sync_all()?;
    atomic_replace(&temporary, &meta.join("active_generation"))?;
    sync_directory(&meta)?;
    Ok(())
}

fn write_synced_replace(path: &Path, bytes: &[u8]) -> CoreResult<()> {
    let parent = path.parent().ok_or_else(|| {
        CoreError::InvalidInput("INVALID_VAULT_PATH: config path has no parent".into())
    })?;
    let sequence = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| CoreError::InvalidInput(error.to_string()))?
        .as_nanos();
    let temporary = parent.join(format!(".vault-config-{sequence}.tmp"));
    let _temporary_guard = VaultFileGuard::create(temporary.clone())?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&temporary)?;
    use std::io::Write;
    file.write_all(bytes)?;
    file.sync_all()?;
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
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        fs::rename(source, destination)?;
        Ok(())
    }
}

fn copy_generation(source: &Path, destination: &Path) -> CoreResult<()> {
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_symlink() {
            return Err(CoreError::InvalidInput(
                "SYMLINKED_VAULT_GENERATION: refusing to rotate a generation containing symlinks"
                    .into(),
            ));
        }
        if metadata.is_dir() {
            copy_generation(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            fs::copy(source_path, destination_path)?;
        } else {
            return Err(CoreError::InvalidInput(
                "INVALID_VAULT_GENERATION: unsupported filesystem entry".into(),
            ));
        }
    }
    Ok(())
}

fn sync_tree(root: &Path) -> CoreResult<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            sync_tree(&path)?;
        } else if metadata.is_file() {
            fs::File::open(path)?.sync_all()?;
        }
    }
    sync_directory(root)?;
    Ok(())
}

fn sync_directory(path: &Path) -> CoreResult<()> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
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
}
