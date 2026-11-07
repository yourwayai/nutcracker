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

fn get_vault_file_path() -> Result<PathBuf, String> {
    dirs::home_dir()
        .map(|h| h.join(".nutcracker").join("vault.enc"))
        .ok_or_else(|| "Could not determine user home directory".to_string())
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, PBKDF2_ITERS, &mut key);
    key
}

fn encrypt(plaintext: &str, key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| e.to_string())?;

    let mut blob = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

fn decrypt(blob: &[u8], key: &[u8; 32]) -> Result<String, String> {
    if blob.len() < NONCE_BYTES + 16 {
        return Err("Corrupted vault blob (too short)".to_string());
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_BYTES);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Wrong master password or corrupted vault.".to_string())?;

    String::from_utf8(plaintext).map_err(|e| format!("Invalid UTF-8: {}", e))
}

fn write_vault_file(blob: &[u8]) -> Result<(), String> {
    let vault_path = get_vault_file_path()?;
    if let Some(parent) = vault_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }

    let tmp_path = vault_path.with_extension(format!("tmp.{}", rand::random::<u32>()));
    fs::write(&tmp_path, blob).map_err(|e| e.to_string())?;
    let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
    fs::rename(&tmp_path, &vault_path).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn vault_exists() -> bool {
    get_vault_file_path().map(|p| p.exists()).unwrap_or(false)
}

#[tauri::command]
fn create_vault(password: String) -> Result<(), String> {
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
fn unlock_vault(password: String) -> Result<Value, String> {
    let vault_path = get_vault_file_path()?;
    let raw = fs::read(&vault_path).map_err(|e| e.to_string())?;
    if raw.len() < SALT_BYTES + NONCE_BYTES + 16 {
        return Err("Corrupted vault file".to_string());
    }

    let (salt, blob) = raw.split_at(SALT_BYTES);
    let key = derive_key(&password, salt);
    let text = decrypt(blob, &key)?;

    serde_json::from_str(&text).map_err(|e| format!("Failed to parse vault JSON: {}", e))
}

#[tauri::command]
fn save_vault(password: String, data: Value) -> Result<(), String> {
    let vault_path = get_vault_file_path()?;
    let raw = fs::read(&vault_path).map_err(|e| e.to_string())?;
    if raw.len() < SALT_BYTES {
        return Err("Invalid vault file".to_string());
    }

    let (salt, _) = raw.split_at(SALT_BYTES);
    let key = derive_key(&password, salt);
    let payload = serde_json::to_string(&data).map_err(|e| e.to_string())?;
    let encrypted = encrypt(&payload, &key)?;

    let mut full_blob = Vec::with_capacity(SALT_BYTES + encrypted.len());
    full_blob.extend_from_slice(salt);
    full_blob.extend_from_slice(&encrypted);

    write_vault_file(&full_blob)
}

#[tauri::command]
fn change_password(old_password: String, new_password: String) -> Result<(), String> {
    let vault_path = get_vault_file_path()?;
    let raw = fs::read(&vault_path).map_err(|e| e.to_string())?;
    if raw.len() < SALT_BYTES {
        return Err("Corrupted vault file".to_string());
    }

    let (old_salt, old_blob) = raw.split_at(SALT_BYTES);
    let old_key = derive_key(&old_password, old_salt);
    let text = decrypt(old_blob, &old_key)?;

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
fn export_vault(password: String, path: Option<String>) -> Result<(), String> {
    let vault_path = get_vault_file_path()?;
    let raw = fs::read(&vault_path).map_err(|e| e.to_string())?;
    if raw.len() < SALT_BYTES {
        return Err("Corrupted vault file".to_string());
    }

    let (salt, blob) = raw.split_at(SALT_BYTES);
    let key = derive_key(&password, salt);
    let text = decrypt(blob, &key)?;

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
    fs::write(&target_path, text).map_err(|e| e.to_string())?;
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
