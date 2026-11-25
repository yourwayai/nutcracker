// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use nutcracker::crypto::{decrypt, derive_key, encrypt, VaultError, NONCE_BYTES, SALT_BYTES};
use rand::RngCore;
use serde_json::Value;
use zeroize::Zeroizing;

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

fn write_vault_file_to(vault_path: &Path, blob: &[u8]) -> Result<(), VaultError> {
    if let Some(parent) = vault_path.parent() {
        fs::create_dir_all(parent).map_err(|e| VaultError::internal(e.to_string()))?;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }

    let tmp_path = vault_path.with_extension(format!("tmp.{}", rand::random::<u32>()));
    fs::write(&tmp_path, blob).map_err(|e| VaultError::internal(e.to_string()))?;
    let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
    fs::rename(&tmp_path, vault_path).map_err(|e| VaultError::internal(e.to_string()))?;
    Ok(())
}

fn write_vault_file(blob: &[u8]) -> Result<(), VaultError> {
    let vault_path = get_vault_file_path()?;
    write_vault_file_to(&vault_path, blob)
}

#[tauri::command]
fn vault_exists() -> bool {
    get_vault_file_path().map(|p| p.exists()).unwrap_or(false)
}

#[tauri::command]
fn create_vault(password: String) -> Result<(), VaultError> {
    let password = Zeroizing::new(password);
    if password.is_empty() {
        return Err(VaultError::invalid_argument("Password required"));
    }
    let mut salt = [0u8; SALT_BYTES];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(&password, &salt);
    let empty_payload = Zeroizing::new(serde_json::json!({ "entries": [] }).to_string());
    let encrypted = encrypt(&empty_payload, &key)?;

    let mut full_blob = Vec::with_capacity(SALT_BYTES + encrypted.len());
    full_blob.extend_from_slice(&salt);
    full_blob.extend_from_slice(&encrypted);

    write_vault_file(&full_blob)
}

#[tauri::command]
fn unlock_vault(password: String) -> Result<Value, VaultError> {
    let password = Zeroizing::new(password);
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
    let text = Zeroizing::new(decrypt(blob, &key)?);

    serde_json::from_str(&text)
        .map_err(|e| VaultError::corrupted(format!("Failed to parse vault JSON: {}", e)))
}

#[tauri::command]
fn save_vault(password: String, data: Value) -> Result<(), VaultError> {
    let password = Zeroizing::new(password);
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
    let payload = Zeroizing::new(
        serde_json::to_string(&data).map_err(|e| VaultError::internal(e.to_string()))?,
    );
    let encrypted = encrypt(&payload, &key)?;

    let mut full_blob = Vec::with_capacity(SALT_BYTES + encrypted.len());
    full_blob.extend_from_slice(salt);
    full_blob.extend_from_slice(&encrypted);

    write_vault_file(&full_blob)
}

#[tauri::command]
fn change_password(old_password: String, new_password: String) -> Result<(), VaultError> {
    let old_password = Zeroizing::new(old_password);
    let new_password = Zeroizing::new(new_password);
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
    let text = Zeroizing::new(
        decrypt(old_blob, &old_key)
            .map_err(|_| VaultError::auth_failed("Wrong current password."))?,
    );

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
    let password = Zeroizing::new(password);
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
    let text = Zeroizing::new(
        decrypt(blob, &key).map_err(|_| VaultError::auth_failed("Wrong master password."))?,
    );

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
    fs::write(&target_path, text.as_bytes()).map_err(|e| VaultError::internal(e.to_string()))?;
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
    fn test_large_vault_5000_entries_reencryption_and_atomic_write() {
        let temp_dir = std::env::temp_dir()
            .join(format!("nutcracker_rust_stress_{}", rand::random::<u32>()));
        let vault_path = temp_dir.join("vault.enc");

        // Build 5,200 synthetic API key entries
        let entries: Vec<Value> = (0..5200)
            .map(|i| {
                serde_json::json!({
                    "id": format!("entry_{:04}", i),
                    "title": format!("Test Key #{:04}", i),
                    "key": format!("test-sk-synthetic-{:04}-abcdef1234567890", i),
                    "category": if i % 2 == 0 { "OpenAI" } else { "Anthropic" },
                    "notes": format!("Synthetic stress item {}", i)
                })
            })
            .collect();
        let initial_payload = Zeroizing::new(serde_json::json!({ "entries": entries }).to_string());

        // Initial encrypt + atomic write
        let mut salt1 = [0u8; SALT_BYTES];
        rand::thread_rng().fill_bytes(&mut salt1);
        let key1 = derive_key("StressOldPassword2026!", &salt1);
        let enc1 = encrypt(&initial_payload, &key1).unwrap();
        let mut blob1 = Vec::with_capacity(SALT_BYTES + enc1.len());
        blob1.extend_from_slice(&salt1);
        blob1.extend_from_slice(&enc1);
        write_vault_file_to(&vault_path, &blob1).expect("Initial atomic write failed");

        // Verify POSIX 0600 permission and no leftover .tmp files
        let mode = fs::metadata(&vault_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // Simulate master password rotation (decrypt + re-encrypt + atomic swap)
        let raw = fs::read(&vault_path).unwrap();
        let (read_salt1, read_blob1) = raw.split_at(SALT_BYTES);
        let dec_key1 = derive_key("StressOldPassword2026!", read_salt1);
        let decrypted_text = Zeroizing::new(decrypt(read_blob1, &dec_key1).unwrap());

        let mut salt2 = [0u8; SALT_BYTES];
        rand::thread_rng().fill_bytes(&mut salt2);
        let key2 = derive_key("StressNewPassword2026!", &salt2);
        let enc2 = encrypt(&decrypted_text, &key2).unwrap();
        let mut blob2 = Vec::with_capacity(SALT_BYTES + enc2.len());
        blob2.extend_from_slice(&salt2);
        blob2.extend_from_slice(&enc2);
        write_vault_file_to(&vault_path, &blob2).expect("Rotation atomic write failed");

        // Ensure no temporary files remain in temp_dir
        let leftover_tmps: Vec<_> = fs::read_dir(&temp_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftover_tmps.is_empty(), "Found leftover tmp files");

        // Verify rotated vault decrypts cleanly with new password and preserves all 5,200 entries
        let raw2 = fs::read(&vault_path).unwrap();
        let (read_salt2, read_blob2) = raw2.split_at(SALT_BYTES);
        let dec_key2 = derive_key("StressNewPassword2026!", read_salt2);
        let final_text = Zeroizing::new(decrypt(read_blob2, &dec_key2).unwrap());
        let parsed: Value = serde_json::from_str(&final_text).unwrap();
        let parsed_entries = parsed["entries"].as_array().unwrap();
        assert_eq!(parsed_entries.len(), 5200);
        assert_eq!(parsed_entries[0]["id"], "entry_0000");
        assert_eq!(parsed_entries[5199]["id"], "entry_5199");

        // Old password must fail on rotated vault
        let wrong_key = derive_key("StressOldPassword2026!", read_salt2);
        assert!(decrypt(read_blob2, &wrong_key).is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
