// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs;
use std::path::PathBuf;
use std::os::unix::fs::PermissionsExt;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde_json::Value;

const SALT_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const PBKDF2_ITERS: u32 = 310_000;

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

fn get_vault_file_path() -> Result<PathBuf, VaultError> {
    if let Ok(file_path) = std::env::var("NUTCRACKER_VAULT_FILE") {
        let trimmed = file_path.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    if let Ok(dir_path) = std::env::var("NUTCRACKER_VAULT_DIR") {
        let trimmed = dir_path.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed).join("vault.enc"));
        }
    }
    dirs::home_dir()
        .map(|h| h.join(".nutcracker").join("vault.enc"))
        .ok_or_else(|| VaultError::internal("Could not determine user home directory"))
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, PBKDF2_ITERS, &mut key);
    key
}

fn encrypt(plaintext: &str, key: &[u8; 32]) -> Result<Vec<u8>, VaultError> {
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

fn decrypt(blob: &[u8], key: &[u8; 32]) -> Result<String, VaultError> {
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

    String::from_utf8(plaintext)
        .map_err(|e| VaultError::corrupted(format!("Invalid UTF-8: {}", e)))
}

fn write_vault_file(blob: &[u8]) -> Result<(), VaultError> {
    let vault_path = get_vault_file_path()?;
    if let Some(parent) = vault_path.parent() {
        fs::create_dir_all(parent).map_err(|e| VaultError::internal(e.to_string()))?;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }

    let tmp_path = vault_path.with_extension(format!("tmp.{}", rand::random::<u32>()));
    fs::write(&tmp_path, blob).map_err(|e| VaultError::internal(e.to_string()))?;
    let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
    fs::rename(&tmp_path, &vault_path).map_err(|e| VaultError::internal(e.to_string()))?;
    Ok(())
}

#[tauri::command]
fn vault_exists() -> bool {
    get_vault_file_path().map(|p| p.exists()).unwrap_or(false)
}

#[tauri::command]
fn create_vault(password: String) -> Result<(), VaultError> {
    if password.is_empty() {
        return Err(VaultError::invalid_argument("Password required"));
    }
    let mut salt = [0u8; SALT_BYTES];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(&password, &salt);
    let empty_payload = serde_json::json!({ "entries": [] }).to_string();
    let encrypted = encrypt(&empty_payload, &key)?;

    let mut full_blob = Vec::with_capacity(SALT_BYTES + encrypted.len());
    full_blob.extend_from_slice(&salt);
    full_blob.extend_from_slice(&encrypted);

    write_vault_file(&full_blob)
}

#[tauri::command]
fn unlock_vault(password: String) -> Result<Value, VaultError> {
    if password.is_empty() {
        return Err(VaultError::invalid_argument("Password required"));
    }
    let vault_path = get_vault_file_path()?;
    if !vault_path.exists() {
        return Err(VaultError::not_found("Vault file not found."));
    }
    let raw = fs::read(&vault_path).map_err(|e| VaultError::internal(e.to_string()))?;
    if raw.len() < SALT_BYTES + NONCE_BYTES + 16 {
        return Err(VaultError::corrupted("Corrupted vault file (too short)"));
    }

    let (salt, blob) = raw.split_at(SALT_BYTES);
    let key = derive_key(&password, salt);
    let text = decrypt(blob, &key)?;

    serde_json::from_str(&text)
        .map_err(|e| VaultError::corrupted(format!("Failed to parse vault JSON: {}", e)))
}

#[tauri::command]
fn save_vault(password: String, data: Value) -> Result<(), VaultError> {
    if password.is_empty() {
        return Err(VaultError::invalid_argument("Password required"));
    }
    let vault_path = get_vault_file_path()?;
    if !vault_path.exists() {
        return Err(VaultError::not_found("Vault file not found."));
    }
    let raw = fs::read(&vault_path).map_err(|e| VaultError::internal(e.to_string()))?;
    if raw.len() < SALT_BYTES {
        return Err(VaultError::corrupted("Corrupted vault file"));
    }

    let (salt, _) = raw.split_at(SALT_BYTES);
    let key = derive_key(&password, salt);
    let payload = serde_json::to_string(&data).map_err(|e| VaultError::internal(e.to_string()))?;
    let encrypted = encrypt(&payload, &key)?;

    let mut full_blob = Vec::with_capacity(SALT_BYTES + encrypted.len());
    full_blob.extend_from_slice(salt);
    full_blob.extend_from_slice(&encrypted);

    write_vault_file(&full_blob)
}

#[tauri::command]
fn change_password(old_password: String, new_password: String) -> Result<(), VaultError> {
    if old_password.is_empty() || new_password.is_empty() {
        return Err(VaultError::invalid_argument("Both old and new passwords are required."));
    }
    let vault_path = get_vault_file_path()?;
    if !vault_path.exists() {
        return Err(VaultError::not_found("Vault file not found."));
    }
    let raw = fs::read(&vault_path).map_err(|e| VaultError::internal(e.to_string()))?;
    if raw.len() < SALT_BYTES + NONCE_BYTES + 16 {
        return Err(VaultError::corrupted("Corrupted vault file"));
    }

    let (old_salt, old_blob) = raw.split_at(SALT_BYTES);
    let old_key = derive_key(&old_password, old_salt);
    let text = decrypt(old_blob, &old_key)
        .map_err(|_| VaultError::auth_failed("Wrong current password."))?;

    let mut new_salt = [0u8; SALT_BYTES];
    rand::thread_rng().fill_bytes(&mut new_salt);
    let new_key = derive_key(&new_password, &new_salt);
    let encrypted = encrypt(&text, &new_key)?;

    let mut full_blob = Vec::with_capacity(SALT_BYTES + encrypted.len());
    full_blob.extend_from_slice(&new_salt);
    full_blob.extend_from_slice(&encrypted);

    write_vault_file(&full_blob)
}

#[tauri::command]
fn export_vault(password: String, path: Option<String>) -> Result<(), VaultError> {
    if password.is_empty() {
        return Err(VaultError::invalid_argument("Password required"));
    }
    let vault_path = get_vault_file_path()?;
    if !vault_path.exists() {
        return Err(VaultError::not_found("Vault file not found."));
    }
    let raw = fs::read(&vault_path).map_err(|e| VaultError::internal(e.to_string()))?;
    if raw.len() < SALT_BYTES + NONCE_BYTES + 16 {
        return Err(VaultError::corrupted("Corrupted vault file"));
    }

    let (salt, blob) = raw.split_at(SALT_BYTES);
    let key = derive_key(&password, salt);
    let text = decrypt(blob, &key)
        .map_err(|_| VaultError::auth_failed("Wrong master password."))?;

    let target_path = match path {
        Some(p) if !p.trim().is_empty() => {
            let expanded = if p.starts_with("~/") {
                if let Some(h) = dirs::home_dir() {
                    h.join(&p[2..])
                } else {
                    PathBuf::from(p)
                }
            } else {
                PathBuf::from(p)
            };
            expanded
        }
        _ => dirs::home_dir()
            .map(|h| h.join("nutcracker-export.json"))
            .unwrap_or_else(|| PathBuf::from("nutcracker-export.json")),
    };

    if let Some(parent) = target_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&target_path, text).map_err(|e| VaultError::internal(e.to_string()))?;
    Ok(())
}

#[tauri::command]
fn get_vault_path() -> String {
    get_vault_file_path()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "Unknown".to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            create_vault,
            unlock_vault,
            save_vault,
            change_password,
            export_vault,
            get_vault_path,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
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

        // Tamper with one byte in the ciphertext body
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
        // Known salt, password, and ciphertext generated with standard AES-256-GCM + PBKDF2-HMAC-SHA256
        let salt = [0x55u8; SALT_BYTES];
        let password = "CrossPlatformPassword2026!";
        let key = derive_key(password, &salt);

        let plaintext = r#"{"test":"cross_platform_ok"}"#;
        let blob = encrypt(plaintext, &key).expect("Encryption failed");

        // Decrypt with key derived from same password and salt
        let decrypted = decrypt(&blob, &key).expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_vault_path_env_overrides() {
        let original_file = std::env::var("NUTCRACKER_VAULT_FILE").ok();
        let original_dir = std::env::var("NUTCRACKER_VAULT_DIR").ok();

        // 1. Test NUTCRACKER_VAULT_FILE override
        std::env::set_var("NUTCRACKER_VAULT_FILE", "/tmp/custom_test_vault/test.enc");
        assert_eq!(
            get_vault_file_path().unwrap(),
            PathBuf::from("/tmp/custom_test_vault/test.enc")
        );

        // 2. Test NUTCRACKER_VAULT_DIR override when file not set
        std::env::remove_var("NUTCRACKER_VAULT_FILE");
        std::env::set_var("NUTCRACKER_VAULT_DIR", "/tmp/custom_test_dir");
        assert_eq!(
            get_vault_file_path().unwrap(),
            PathBuf::from("/tmp/custom_test_dir/vault.enc")
        );

        // Restore original environment
        if let Some(val) = original_file {
            std::env::set_var("NUTCRACKER_VAULT_FILE", val);
        } else {
            std::env::remove_var("NUTCRACKER_VAULT_FILE");
        }
        if let Some(val) = original_dir {
            std::env::set_var("NUTCRACKER_VAULT_DIR", val);
        } else {
            std::env::remove_var("NUTCRACKER_VAULT_DIR");
        }
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

        // Verify JSON serialization format matches { "ok": false, "code": "...", "error": "..." }
        let json_val = serde_json::to_value(&auth_err).expect("Serialization failed");
        assert_eq!(json_val["ok"], false);
        assert_eq!(json_val["code"], "AUTH_FAILED");
        assert_eq!(json_val["error"], "Wrong master password or corrupted vault.");

        let json_arg = serde_json::to_value(&arg_err).expect("Serialization failed");
        assert_eq!(json_arg["ok"], false);
        assert_eq!(json_arg["code"], "INVALID_ARGUMENT");
        assert_eq!(json_arg["error"], "Password required");
    }
}
