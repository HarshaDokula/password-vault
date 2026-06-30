use std::fs;
use std::io::Read;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::db;
use crate::models::Account;
use crate::services::Vault;

/// Metadata for backup archives.
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub format_version: u32,
    pub created_at: String,
    pub app_version: String,
    pub kdf: String,
    pub cipher: String,
}

impl BackupMetadata {
    pub fn new() -> Self {
        BackupMetadata {
            format_version: 1,
            created_at: Utc::now().to_rfc3339(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            kdf: "argon2id".to_string(),
            cipher: "xchacha20poly1305".to_string(),
        }
    }
}

/// Export the vault to a `.vlt` encrypted tar archive.
/// `audit_path` is the path to the audit.log file to include in the backup.
pub fn export_vault(vault: &Vault, audit_path: &str, output_path: &str) -> Result<(), String> {
    let metadata = BackupMetadata::new();
    
    // Get all accounts
    let accounts = vault.export_accounts()?;
    let accounts_json = serde_json::to_string_pretty(&accounts)
        .map_err(|e| format!("Serialization error: {}", e))?;

    // Read audit log if it exists
    let audit_content = fs::read_to_string(audit_path).unwrap_or_default();
    
    // Build tar archive in memory
    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);
        
        // Add metadata.json
        let metadata_json = serde_json::to_string_pretty(&metadata)
            .map_err(|e| format!("Serialization error: {}", e))?;
        let mut header = tar::Header::new_gnu();
        header.set_size(metadata_json.len() as u64);
        header.set_mode(0o644);
        builder.append_data(&mut header, "metadata.json", metadata_json.as_bytes())
            .map_err(|e| format!("Tar error: {}", e))?;
        
        // Add vault.json (encrypted account data)
        let mut header = tar::Header::new_gnu();
        header.set_size(accounts_json.len() as u64);
        header.set_mode(0o644);
        builder.append_data(&mut header, "vault.json", accounts_json.as_bytes())
            .map_err(|e| format!("Tar error: {}", e))?;

        // Add audit.log
        if !audit_content.is_empty() {
            let mut header = tar::Header::new_gnu();
            header.set_size(audit_content.len() as u64);
            header.set_mode(0o644);
            builder.append_data(&mut header, "audit.log", audit_content.as_bytes())
                .map_err(|e| format!("Tar error: {}", e))?;
        }
        
        builder.finish().map_err(|e| format!("Tar finish error: {}", e))?;
    }
    
    // Compress and encrypt
    let export_key = crypto::generate_random_key();
    let encrypted = crypto::encrypt(&export_key, &tar_data)?;
    
    // Write export key + encrypted data
    let mut output = Vec::new();
    output.extend_from_slice(&export_key);
    output.extend_from_slice(&encrypted);
    
    fs::write(output_path, &output)
        .map_err(|e| format!("Cannot write backup: {}", e))?;
    
    Ok(())
}

/// Import a backup, decrypting and inserting accounts and audit log into the vault.
pub fn import_vault(vault: &Vault, audit_path: &str, input_path: &str) -> Result<usize, String> {
    let data = fs::read(input_path)
        .map_err(|e| format!("Cannot read backup: {}", e))?;
    
    if data.len() < 32 {
        return Err("Invalid backup format: too short".to_string());
    }
    
    let (key_bytes, encrypted) = data.split_at(32);
    let mut key = [0u8; 32];
    key.copy_from_slice(key_bytes);
    
    let tar_data = crypto::decrypt(&key, encrypted)?;
    
    // Extract tar
    let mut archive = tar::Archive::new(tar_data.as_slice());
    let mut count = 0;
    
    for entry in archive.entries().map_err(|e| format!("Tar read error: {}", e))? {
        let mut entry = entry.map_err(|e| format!("Entry error: {}", e))?;
        let path = entry.path().map_err(|e| format!("Path error: {}", e))?
            .to_string_lossy().to_string();
        
        if path == "vault.json" {
            let mut content = String::new();
            entry.read_to_string(&mut content)
                .map_err(|e| format!("Read error: {}", e))?;
            
            let accounts: Vec<Account> = serde_json::from_str(&content)
                .map_err(|e| format!("Parse error: {}", e))?;
            
            for account in &accounts {
                // Only import if not soft-deleted and not already present
                if account.deleted_at.is_none() {
                    match db::get_account(&vault.db, &account.id) {
                        Ok(None) => {
                            db::insert_account(&vault.db, account)?;
                            count += 1;
                        }
                        _ => {} // Already exists, skip
                    }
                }
            }
        } else if path == "audit.log" {
            let mut content = String::new();
            entry.read_to_string(&mut content)
                .map_err(|e| format!("Read error: {}", e))?;
            // Append audit log to existing file
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(audit_path)
                .map_err(|e| format!("Cannot open audit log for import: {}", e))?;
            file.write_all(content.as_bytes())
                .map_err(|e| format!("Cannot write imported audit log: {}", e))?;
        }
    }
    
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use crate::audit::IntegrityLog;
    use crate::models::AppConfig;
    use uuid::Uuid;

    fn setup_test_vault() -> Vault {
        let db_path = "/tmp/test_storage_vault.db";
        let audit_path = "/tmp/test_storage_audit.log";
        let _ = fs::remove_file(db_path);
        let _ = fs::remove_file(audit_path);

        let conn = db::open(db_path).unwrap();
        let integrity_log = IntegrityLog::open(audit_path).unwrap();
        let master_key = crypto::generate_random_key();
        let session_id = Uuid::new_v4().to_string();
        let config = AppConfig::default();

        Vault::new(conn, integrity_log, master_key, session_id, config)
    }

    #[test]
    fn test_export_import() {
        let vault = setup_test_vault();
        vault.create_account("github", "user", "pass", None).unwrap();
        vault.create_account("gitlab", "admin", "secret", Some("notes")).unwrap();
        
        let export_path = "/tmp/test_backup.vlt";
        let audit_path = "/tmp/test_storage_audit.log";
        let _ = fs::remove_file(export_path);
        
        export_vault(&vault, audit_path, export_path).unwrap();
        assert!(Path::new(export_path).exists());
        
        // Create a fresh vault and import
        let vault2 = setup_test_vault();
        let audit_path2 = "/tmp/test_storage2_audit.log";
        let _ = fs::remove_file(audit_path2);
        let count = import_vault(&vault2, audit_path2, export_path).unwrap();
        assert_eq!(count, 2);
        
        let results = vault2.search_accounts("git").unwrap();
        assert_eq!(results.len(), 2);
        
        let _ = fs::remove_file(export_path);
        let _ = fs::remove_file(audit_path2);
    }
}
