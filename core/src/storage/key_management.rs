use crate::error::{CoreError, CoreResult};
use rand::RngCore;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use std::process::Command;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyStorage {
    MACOS_KEYCHAIN,
    WINDOWS_DPAPI,
    FILE_FALLBACK,
}

#[derive(Debug, Clone)]
pub struct KekMaterial {
    pub kek: [u8; 32],
    pub storage: KeyStorage,
}

pub fn get_or_create_kek(
    vault_id: &str,
    fallback_path: &std::path::Path,
) -> CoreResult<KekMaterial> {
    #[cfg(target_os = "macos")]
    {
        if let Ok(kek) = macos_get_or_create_kek(vault_id) {
            return Ok(KekMaterial {
                kek,
                storage: KeyStorage::MACOS_KEYCHAIN,
            });
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(kek) = windows_get_or_create_kek_dpapi(vault_id, fallback_path) {
            return Ok(KekMaterial {
                kek,
                storage: KeyStorage::WINDOWS_DPAPI,
            });
        }
    }

    // Fallback keeps local development deterministic and testable.
    let kek = file_get_or_create_kek(fallback_path)?;
    Ok(KekMaterial {
        kek,
        storage: KeyStorage::FILE_FALLBACK,
    })
}

#[cfg(target_os = "macos")]
fn macos_get_or_create_kek(vault_id: &str) -> CoreResult<[u8; 32]> {
    let service = "aigc-core-vault-kek";
    let account = format!("vault:{}", vault_id);

    // Try find existing secret in Keychain.
    let out = Command::new("security")
        .args(["find-generic-password", "-s", service, "-a", &account, "-w"])
        .output()?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let bytes = base64_decode(&s)?;
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Ok(arr);
        }
    }

    // Create and persist new KEK in Keychain.
    let mut kek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut kek);
    let encoded = base64_encode(&kek);
    let out = Command::new("security")
        .args([
            "add-generic-password",
            "-U",
            "-s",
            service,
            "-a",
            &account,
            "-w",
            &encoded,
        ])
        .output()?;
    if !out.status.success() {
        return Err(CoreError::PolicyBlocked(
            "failed to store KEK in macOS Keychain".to_string(),
        ));
    }
    Ok(kek)
}

fn file_get_or_create_kek(path: &std::path::Path) -> CoreResult<[u8; 32]> {
    if path.exists() {
        harden_secret_file_permissions(path)?;
        let bytes = std::fs::read(path)?;
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Ok(arr);
        }
        return Err(CoreError::InvalidInput(
            "invalid fallback KEK length".to_string(),
        ));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        harden_secret_dir_permissions(parent)?;
    }
    let mut kek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut kek);
    std::fs::write(path, kek)?;
    harden_secret_file_permissions(path)?;
    Ok(kek)
}

fn harden_secret_dir_permissions(path: &std::path::Path) -> CoreResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(path, permissions)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn harden_secret_file_permissions(path: &std::path::Path) -> CoreResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, permissions)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_get_or_create_kek_dpapi(vault_id: &str, path: &std::path::Path) -> CoreResult<[u8; 32]> {
    if path.exists() {
        let enc = std::fs::read(path)?;
        let dec = dpapi_unprotect(&enc, vault_id)?;
        if dec.len() != 32 {
            return Err(CoreError::InvalidInput(
                "DPAPI-unwrapped KEK invalid length".to_string(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&dec);
        return Ok(arr);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut kek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut kek);
    let enc = dpapi_protect(&kek, vault_id)?;
    std::fs::write(path, enc)?;
    Ok(kek)
}

#[cfg(target_os = "windows")]
fn dpapi_protect(bytes: &[u8], entropy_label: &str) -> CoreResult<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptProtectData};

    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut entropy = entropy_label.as_bytes().to_vec();
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_mut_ptr(),
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let ok = unsafe {
        CryptProtectData(
            &in_blob,
            std::ptr::null(),
            &entropy_blob,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            &mut out_blob,
        )
    };
    if ok == 0 {
        return Err(CoreError::PolicyBlocked(
            "CryptProtectData failed".to_string(),
        ));
    }
    let out =
        unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(out_blob.pbData as *mut core::ffi::c_void);
    }
    Ok(out)
}

#[cfg(target_os = "windows")]
fn dpapi_unprotect(bytes: &[u8], entropy_label: &str) -> CoreResult<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptUnprotectData};

    let mut input = bytes.to_vec();
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: input.len() as u32,
        pbData: input.as_mut_ptr(),
    };
    let mut entropy = entropy_label.as_bytes().to_vec();
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_mut_ptr(),
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &in_blob,
            std::ptr::null_mut(),
            &entropy_blob,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            &mut out_blob,
        )
    };
    if ok == 0 {
        return Err(CoreError::PolicyBlocked(
            "CryptUnprotectData failed".to_string(),
        ));
    }
    let out =
        unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(out_blob.pbData as *mut core::ffi::c_void);
    }
    Ok(out)
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i] as u32;
        let b1 = if i + 1 < bytes.len() {
            bytes[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < bytes.len() {
            bytes[i + 2] as u32
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8) | b2;
        let c0 = ((n >> 18) & 63) as usize;
        let c1 = ((n >> 12) & 63) as usize;
        let c2 = ((n >> 6) & 63) as usize;
        let c3 = (n & 63) as usize;
        out.push(TABLE[c0] as char);
        out.push(TABLE[c1] as char);
        if i + 1 < bytes.len() {
            out.push(TABLE[c2] as char);
        } else {
            out.push('=');
        }
        if i + 2 < bytes.len() {
            out.push(TABLE[c3] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

fn base64_decode(s: &str) -> CoreResult<Vec<u8>> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c0 = b64_val(bytes[i])?;
        let c1 = b64_val(bytes.get(i + 1).copied().unwrap_or(b'='))?;
        let c2 = b64_val(bytes.get(i + 2).copied().unwrap_or(b'='))?;
        let c3 = b64_val(bytes.get(i + 3).copied().unwrap_or(b'='))?;
        let n = ((c0 as u32) << 18) | ((c1 as u32) << 12) | ((c2 as u32) << 6) | (c3 as u32);
        out.push(((n >> 16) & 0xFF) as u8);
        if bytes.get(i + 2).copied().unwrap_or(b'=') != b'=' {
            out.push(((n >> 8) & 0xFF) as u8);
        }
        if bytes.get(i + 3).copied().unwrap_or(b'=') != b'=' {
            out.push((n & 0xFF) as u8);
        }
        i += 4;
    }
    Ok(out)
}

fn b64_val(c: u8) -> CoreResult<u8> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        b'=' => Ok(0),
        _ => Err(CoreError::InvalidInput(
            "invalid base64 character".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::file_get_or_create_kek;
    use tempfile::tempdir;

    #[test]
    fn file_fallback_creates_kek_with_secure_permissions() {
        let temp = tempdir().expect("tempdir should be created");
        let key_path = temp.path().join("vault").join("kek.bin");

        let created = file_get_or_create_kek(&key_path).expect("kek should be created");
        let loaded = file_get_or_create_kek(&key_path).expect("kek should be loaded");
        assert_eq!(created, loaded);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path)
                .expect("kek file should be readable")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn file_fallback_rejects_invalid_kek_length() {
        let temp = tempdir().expect("tempdir should be created");
        let key_path = temp.path().join("kek-invalid.bin");
        std::fs::write(&key_path, [1_u8, 2, 3]).expect("invalid key fixture should be written");

        let result = file_get_or_create_kek(&key_path);
        assert!(result.is_err());
        assert!(
            result
                .err()
                .expect("expected invalid length error")
                .to_string()
                .contains("invalid fallback KEK length")
        );
    }

    #[test]
    fn file_fallback_hardens_existing_lax_permissions() {
        let temp = tempdir().expect("tempdir should be created");
        let key_path = temp.path().join("kek-perms.bin");
        std::fs::write(&key_path, [9_u8; 32]).expect("valid key fixture should be written");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
                .expect("fixture permissions should be set");
        }

        let _ = file_get_or_create_kek(&key_path).expect("kek load should succeed");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path)
                .expect("kek metadata should be readable")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
