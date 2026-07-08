use crate::error::{CoreError, CoreResult};
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce as AesNonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    XCHACHA20_POLY1305,
    AES_256_GCM,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub algorithm: EncryptionAlgorithm,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub fn generate_dek_32() -> [u8; 32] {
    let mut out = [0u8; 32];
    rand::rng().fill_bytes(&mut out);
    out
}

pub fn encrypt_bytes(
    algorithm: EncryptionAlgorithm,
    dek: &[u8; 32],
    plaintext: &[u8],
) -> CoreResult<EncryptedBlob> {
    match algorithm {
        EncryptionAlgorithm::XCHACHA20_POLY1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(dek)
                .map_err(|e| CoreError::InvalidInput(format!("invalid key: {}", e)))?;
            let mut nonce = [0u8; 24];
            rand::rng().fill_bytes(&mut nonce);
            let ct = cipher
                .encrypt(XNonce::from_slice(&nonce), plaintext)
                .map_err(|e| CoreError::PolicyBlocked(format!("encryption failed: {}", e)))?;
            Ok(EncryptedBlob {
                algorithm,
                nonce: nonce.to_vec(),
                ciphertext: ct,
            })
        }
        EncryptionAlgorithm::AES_256_GCM => {
            let cipher = Aes256Gcm::new_from_slice(dek)
                .map_err(|e| CoreError::InvalidInput(format!("invalid key: {}", e)))?;
            let mut nonce = [0u8; 12];
            rand::rng().fill_bytes(&mut nonce);
            let ct = cipher
                .encrypt(AesNonce::from_slice(&nonce), plaintext)
                .map_err(|e| CoreError::PolicyBlocked(format!("encryption failed: {}", e)))?;
            Ok(EncryptedBlob {
                algorithm,
                nonce: nonce.to_vec(),
                ciphertext: ct,
            })
        }
    }
}

pub fn decrypt_bytes(blob: &EncryptedBlob, dek: &[u8; 32]) -> CoreResult<Vec<u8>> {
    match blob.algorithm {
        EncryptionAlgorithm::XCHACHA20_POLY1305 => {
            if blob.nonce.len() != 24 {
                return Err(CoreError::InvalidInput(
                    "XChaCha20 nonce must be 24 bytes".to_string(),
                ));
            }
            let cipher = XChaCha20Poly1305::new_from_slice(dek)
                .map_err(|e| CoreError::InvalidInput(format!("invalid key: {}", e)))?;
            cipher
                .decrypt(XNonce::from_slice(&blob.nonce), blob.ciphertext.as_ref())
                .map_err(|e| CoreError::PolicyBlocked(format!("decryption failed: {}", e)))
        }
        EncryptionAlgorithm::AES_256_GCM => {
            if blob.nonce.len() != 12 {
                return Err(CoreError::InvalidInput(
                    "AES-GCM nonce must be 12 bytes".to_string(),
                ));
            }
            let cipher = Aes256Gcm::new_from_slice(dek)
                .map_err(|e| CoreError::InvalidInput(format!("invalid key: {}", e)))?;
            cipher
                .decrypt(AesNonce::from_slice(&blob.nonce), blob.ciphertext.as_ref())
                .map_err(|e| CoreError::PolicyBlocked(format!("decryption failed: {}", e)))
        }
    }
}
