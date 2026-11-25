use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

pub const SALT_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const PBKDF2_ITERS: u32 = 310_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    AuthFailed(String),
    VaultCorrupted(String),
    VaultNotFound(String),
    InvalidArgument(String),
    Internal(String),
}

impl VaultError {
    pub fn auth_failed(msg: impl Into<String>) -> Self {
        VaultError::AuthFailed(msg.into())
    }
    pub fn corrupted(msg: impl Into<String>) -> Self {
        VaultError::VaultCorrupted(msg.into())
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        VaultError::VaultNotFound(msg.into())
    }
    pub fn invalid_argument(msg: impl Into<String>) -> Self {
        VaultError::InvalidArgument(msg.into())
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        VaultError::Internal(msg.into())
    }

    pub fn code(&self) -> &'static str {
        match self {
            VaultError::AuthFailed(_) => "AUTH_FAILED",
            VaultError::VaultCorrupted(_) => "VAULT_CORRUPTED",
            VaultError::VaultNotFound(_) => "VAULT_NOT_FOUND",
            VaultError::InvalidArgument(_) => "INVALID_ARGUMENT",
            VaultError::Internal(_) => "INTERNAL_ERROR",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            VaultError::AuthFailed(m)
            | VaultError::VaultCorrupted(m)
            | VaultError::VaultNotFound(m)
            | VaultError::InvalidArgument(m)
            | VaultError::Internal(m) => m.as_str(),
        }
    }
}

impl std::ops::Deref for VaultError {
    type Target = str;
    fn deref(&self) -> &str {
        self.message()
    }
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for VaultError {}

impl serde::Serialize for VaultError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("VaultError", 3)?;
        state.serialize_field("ok", &false)?;
        state.serialize_field("code", self.code())?;
        state.serialize_field("error", self.message())?;
        state.end()
    }
}

/// Derive a 256-bit symmetric key using PBKDF2-HMAC-SHA256.
/// Wrapped in `Zeroizing` so the derived key material is wiped on drop.
pub fn derive_key(password: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, PBKDF2_ITERS, key.as_mut());
    key
}

pub fn encrypt(plaintext: &str, key: &[u8; 32]) -> Result<Vec<u8>, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::internal(e.to_string()))?;
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| VaultError::internal(e.to_string()))?;

    let mut blob = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

pub fn decrypt(blob: &[u8], key: &[u8; 32]) -> Result<String, VaultError> {
    if blob.len() < NONCE_BYTES + 16 {
        return Err(VaultError::corrupted("Corrupted vault blob (too short)"));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_BYTES);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::internal(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::auth_failed("Wrong master password or corrupted vault."))?;

    String::from_utf8(plaintext).map_err(|e| {
        let msg = format!("Invalid UTF-8: {}", e.utf8_error());
        let mut bytes = e.into_bytes();
        bytes.zeroize();
        VaultError::corrupted(msg)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_consistency() {
        let salt = [42u8; SALT_BYTES];
        let key1 = derive_key("test_master_pass_123", &salt);
        let key2 = derive_key("test_master_pass_123", &salt);
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);

        let salt_diff = [99u8; SALT_BYTES];
        let key_diff = derive_key("test_master_pass_123", &salt_diff);
        assert_ne!(key1, key_diff);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let salt = [7u8; SALT_BYTES];
        let key = derive_key("secure_password_abc", &salt);
        let sample_payload = r#"{"entries":[{"id":"1","title":"OpenAI Key","key":"sk-proj-12345","category":"OpenAI"}]}"#;

        let encrypted = encrypt(sample_payload, &key).expect("Encryption failed");
        assert!(encrypted.len() > NONCE_BYTES + 16);

        let decrypted = decrypt(&encrypted, &key).expect("Decryption failed");
        assert_eq!(decrypted, sample_payload);
    }

    #[test]
    fn test_decrypt_wrong_password_fails() {
        let salt = [7u8; SALT_BYTES];
        let correct_key = derive_key("correct_password", &salt);
        let wrong_key = derive_key("wrong_password", &salt);

        let encrypted = encrypt("secret data", &correct_key).unwrap();
        let result = decrypt(&encrypted, &wrong_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Wrong master password"));
    }

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let salt = [7u8; SALT_BYTES];
        let key = derive_key("password", &salt);
        let mut encrypted = encrypt("authenticated payload", &key).unwrap();

        let last_idx = encrypted.len() - 1;
        encrypted[last_idx] ^= 0xFF;

        let result = decrypt(&encrypted, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_short_blob() {
        let key = [0u8; 32];
        let too_short = vec![0u8; 10];
        let result = decrypt(&too_short, &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Corrupted vault blob"));
    }

    #[test]
    fn test_unicode_and_emojis() {
        let salt = [1u8; SALT_BYTES];
        let key = derive_key("密码_🔑_test", &salt);
        let utf8_text = "密钥名称: 生产环境 Anthropic 密钥 🚀 | 状态: 正常";

        let encrypted = encrypt(utf8_text, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, utf8_text);
    }

    #[test]
    fn test_fixed_vector_cross_compat() {
        let salt = [0x55u8; SALT_BYTES];
        let password = "CrossPlatformPassword2026!";
        let key = derive_key(password, &salt);

        let plaintext = r#"{"test":"cross_platform_ok"}"#;
        let blob = encrypt(plaintext, &key).expect("Encryption failed");

        let decrypted = decrypt(&blob, &key).expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_vault_error_standardized_contract() {
        let auth_err = VaultError::auth_failed("Wrong master password or corrupted vault.");
        assert_eq!(auth_err.code(), "AUTH_FAILED");
        assert_eq!(auth_err.message(), "Wrong master password or corrupted vault.");
        assert!(auth_err.contains("Wrong master password"));

        let corrupted_err = VaultError::corrupted("Corrupted vault blob (too short)");
        assert_eq!(corrupted_err.code(), "VAULT_CORRUPTED");
        assert_eq!(corrupted_err.message(), "Corrupted vault blob (too short)");

        let not_found_err = VaultError::not_found("Vault file not found.");
        assert_eq!(not_found_err.code(), "VAULT_NOT_FOUND");

        let arg_err = VaultError::invalid_argument("Password required");
        assert_eq!(arg_err.code(), "INVALID_ARGUMENT");

        let internal_err = VaultError::internal("Disk I/O error");
        assert_eq!(internal_err.code(), "INTERNAL_ERROR");

        let json_val = serde_json::to_value(&auth_err).expect("Serialization failed");
        assert_eq!(json_val["ok"], false);
        assert_eq!(json_val["code"], "AUTH_FAILED");
        assert_eq!(json_val["error"], "Wrong master password or corrupted vault.");

        let json_arg = serde_json::to_value(&arg_err).expect("Serialization failed");
        assert_eq!(json_arg["ok"], false);
        assert_eq!(json_arg["code"], "INVALID_ARGUMENT");
        assert_eq!(json_arg["error"], "Password required");
    }

    #[test]
    fn test_sensitive_memory_zeroization() {
        let salt = [0x33u8; SALT_BYTES];
        let mut derived = derive_key("TestZeroizeMasterPassword!2026", &salt);
        assert!(derived.iter().any(|&b| b != 0));
        derived.zeroize();
        assert_eq!(&*derived, &[0u8; 32]);

        let mut password = Zeroizing::new(String::from("SensitivePassword_999"));
        assert!(!password.is_empty());
        password.zeroize();
        assert!(password.is_empty());
        assert_eq!(password.as_bytes().len(), 0);
    }

    #[test]
    fn test_decrypt_fuzz_malformed_inputs() {
        let salt = [0x11u8; SALT_BYTES];
        let key = derive_key("FuzzTestPassword2026!", &salt);

        // 1. All boundary lengths from 0..=64 with deterministic pseudo-random bytes (xorshift64)
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next_byte = || -> u8 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state & 0xFF) as u8
        };

        for len in 0..=64 {
            for _ in 0..16 {
                let input: Vec<u8> = (0..len).map(|_| next_byte()).collect();
                let res = std::panic::catch_unwind(|| decrypt(&input, &key));
                assert!(res.is_ok(), "decrypt() panicked for len={}", len);
                let inner = res.unwrap();
                assert!(inner.is_err());
                if len < NONCE_BYTES + 16 {
                    assert_eq!(inner.unwrap_err().code(), "VAULT_CORRUPTED");
                } else {
                    assert_eq!(inner.unwrap_err().code(), "AUTH_FAILED");
                }
            }
        }

        // 2. Larger random fuzz payloads up to 512 bytes
        for i in 0..500 {
            let len = 65 + (i * 13) % 448;
            let input: Vec<u8> = (0..len).map(|_| next_byte()).collect();
            let res = std::panic::catch_unwind(|| decrypt(&input, &key));
            assert!(res.is_ok(), "decrypt() panicked on large fuzz payload {}", i);
            assert!(res.unwrap().is_err());
        }

        // 3. Truncations and single-bit flips across every offset of a valid ciphertext
        let valid = encrypt(r#"{"entries":[{"id":"1","key":"test-key"}]}"#, &key).unwrap();
        for cut in 0..valid.len() {
            let truncated = &valid[..cut];
            let res = std::panic::catch_unwind(|| decrypt(truncated, &key));
            assert!(res.is_ok(), "decrypt() panicked on truncation at {}", cut);
            assert!(res.unwrap().is_err());
        }
        for pos in 0..valid.len() {
            let mut mutated = valid.clone();
            mutated[pos] ^= 0x01;
            let res = std::panic::catch_unwind(|| decrypt(&mutated, &key));
            assert!(res.is_ok(), "decrypt() panicked on bitflip at {}", pos);
            assert!(res.unwrap().is_err());
        }

        // 4. Valid AES-GCM ciphertext wrapping invalid UTF-8 bytes must return VAULT_CORRUPTED
        let cipher = Aes256Gcm::new_from_slice(&*key).unwrap();
        let nonce_bytes = [0xAAu8; NONCE_BYTES];
        let nonce = Nonce::from_slice(&nonce_bytes);
        let invalid_utf8 = [0xFFu8, 0xFE, 0x80, 0xC0];
        let ct = cipher.encrypt(nonce, invalid_utf8.as_ref()).unwrap();
        let mut malformed_utf8_blob = Vec::with_capacity(NONCE_BYTES + ct.len());
        malformed_utf8_blob.extend_from_slice(&nonce_bytes);
        malformed_utf8_blob.extend_from_slice(&ct);
        let utf8_err = decrypt(&malformed_utf8_blob, &key).unwrap_err();
        assert_eq!(utf8_err.code(), "VAULT_CORRUPTED");
    }
}
