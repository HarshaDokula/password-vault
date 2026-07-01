use chrono::Utc;
use rusqlite::Connection;
use uuid::Uuid;

use crate::audit::IntegrityLog;
use crate::crypto;
use crate::db;
use crate::models::{Account, AccountSummary, AuditEntry, EventType, PasswordHistoryEntry, AppConfig};

/// The core vault service that orchestrates all operations.
pub struct Vault {
    pub db: Connection,
    integrity_log: IntegrityLog,
    master_key: [u8; 32],
    session_id: String,
    config: AppConfig,
}

impl Vault {
    /// Create a new vault service with an active session.
    pub fn new(
        db: Connection,
        integrity_log: IntegrityLog,
        master_key: [u8; 32],
        session_id: String,
        config: AppConfig,
    ) -> Self {
        Vault {
            db,
            integrity_log,
            master_key,
            session_id,
            config,
        }
    }

    // ── Public API for future features (see README § "Implementation Status") ──

    /// Get the current session UUID.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Search accounts including soft-deleted.
    pub fn search_all_accounts(&self, query: &str) -> Result<Vec<AccountSummary>, String> {
        db::search_accounts(&self.db, query, true)
    }

    /// Get password history for an account (passwords decrypted).
    pub fn get_password_history_decrypted(&self, account_id: &str) -> Result<Vec<String>, String> {
        let entries = db::get_password_history(&self.db, account_id)?;
        let mut passwords = Vec::new();
        for entry in entries {
            let pw = crypto::decrypt_string(&self.master_key, &entry.password)?;
            passwords.push(pw);
        }
        Ok(passwords)
    }

    /// Verify database and audit log integrity.
    pub fn verify_integrity(&self) -> Result<Vec<String>, String> {
        let mut issues = Vec::new();

        // Verify integrity log hash chain
        match self.integrity_log.verify() {
            Ok(()) => {}
            Err(e) => {
                issues.push(format!("Integrity log failure: {}", e));
                self.log_event(EventType::IntegrityCheckFailure, None, None)?;
            }
        }

        // Verify database integrity
        match self.db.query_row("PRAGMA integrity_check", [], |row| {
            row.get::<_, String>(0)
        }) {
            Ok(result) => {
                if result != "ok" {
                    issues.push(format!("Database integrity issue: {}", result));
                }
            }
            Err(e) => {
                issues.push(format!("Database integrity check failed: {}", e));
            }
        }

        Ok(issues)
    }

    // ── Active API ──

    /// Log an event to both the integrity chain and operational store.
    pub(crate) fn log_event(
        &self,
        event_type: EventType,
        account_id: Option<&str>,
        metadata: Option<&str>,
    ) -> Result<(), String> {
        if !self.config.logging.enable_audit_logs {
            return Ok(());
        }

        let entry_hash = self.integrity_log.append(
            event_type.clone(),
            &self.session_id,
            account_id,
            metadata,
        )?;

        // Also insert into SQLite operational audit_log table
        let prev_entries = self.get_audit_log_last_hash()?;
        let id = Uuid::new_v4().to_string();
        let timestamp = Utc::now().to_rfc3339();

        let entry = AuditEntry {
            id,
            timestamp,
            session_id: self.session_id.clone(),
            event_type,
            account_id: account_id.map(|s| s.to_string()),
            metadata: metadata.map(|s| s.to_string()),
            prev_hash: prev_entries,
            entry_hash,
        };

        db::insert_audit_entry(&self.db, &entry)
    }

    fn get_audit_log_last_hash(&self) -> Result<String, String> {
        let mut stmt = self
            .db
            .prepare("SELECT entry_hash FROM audit_log ORDER BY timestamp DESC LIMIT 1")
            .map_err(|e| format!("Cannot prepare: {}", e))?;
        match stmt.query_row([], |row| row.get::<_, String>(0)) {
            Ok(h) => Ok(h),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(String::new()),
            Err(e) => Err(format!("Cannot get last hash: {}", e)),
        }
    }

    /// Create a new account.
    pub fn create_account(
        &self,
        service_name: &str,
        username: &str,
        password: &str,
        notes: Option<&str>,
    ) -> Result<Account, String> {
        let now = Utc::now().to_rfc3339();
        let id = Uuid::new_v4().to_string();

        let encrypted_username = crypto::encrypt_string(&self.master_key, username)?;
        let encrypted_password = crypto::encrypt_string(&self.master_key, password)?;
        let encrypted_notes = notes.map(|n| crypto::encrypt_string(&self.master_key, n)).transpose()?;

        let account = Account {
            id: id.clone(),
            service_name: service_name.to_string(),
            username: encrypted_username,
            password: encrypted_password,
            notes: encrypted_notes,
            created_at: now.clone(),
            updated_at: now,
            deleted_at: None,
        };

        db::insert_account(&self.db, &account)?;

        let metadata = serde_json::json!({
            "service_name": service_name,
            "fields_present": {
                "username": true,
                "notes": notes.is_some()
            }
        })
        .to_string();

        self.log_event(EventType::AccountCreate, Some(&id), Some(&metadata))?;

        Ok(account)
    }

    /// Update an existing account.
    /// If the password changed, moves old password to history.
    pub fn update_account(
        &self,
        id: &str,
        service_name: Option<&str>,
        username: Option<&str>,
        password: Option<&str>,
        notes: Option<Option<&str>>,
    ) -> Result<Account, String> {
        let mut account = db::get_account(&self.db, id)?
            .ok_or_else(|| format!("Account {} not found", id))?;

        if account.deleted_at.is_some() {
            return Err("Cannot update a deleted account".to_string());
        }

        let now = Utc::now().to_rfc3339();
        let mut password_changed = false;

        if let Some(sn) = service_name {
            account.service_name = sn.to_string();
        }
        if let Some(un) = username {
            account.username = crypto::encrypt_string(&self.master_key, un)?;
        }
        if let Some(pw) = password {
            // Move old password to history before updating
            let history_entry = PasswordHistoryEntry {
                id: Uuid::new_v4().to_string(),
                account_id: id.to_string(),
                password: account.password.clone(),
                changed_at: now.clone(),
            };
            db::insert_password_history(&self.db, &history_entry)?;
            db::prune_password_history(&self.db, id)?;

            account.password = crypto::encrypt_string(&self.master_key, pw)?;
            password_changed = true;
        }
        if let Some(notes_val) = notes {
            account.notes = match notes_val {
                Some(n) => Some(crypto::encrypt_string(&self.master_key, n)?),
                None => None,
            };
        }

        account.updated_at = now;

        db::update_account(&self.db, &account)?;

        let metadata = serde_json::json!({
            "service_name": account.service_name,
            "password_changed": password_changed
        })
        .to_string();

        self.log_event(EventType::AccountUpdate, Some(id), Some(&metadata))?;

        Ok(account)
    }

    /// Soft-delete an account.
    pub fn delete_account(&self, id: &str) -> Result<(), String> {
        let account = db::get_account(&self.db, id)?
            .ok_or_else(|| format!("Account {} not found", id))?;

        if account.deleted_at.is_some() {
            return Err("Account already deleted".to_string());
        }

        let now = Utc::now().to_rfc3339();
        db::soft_delete_account(&self.db, id, &now)?;

        let metadata = serde_json::json!({
            "service_name": account.service_name
        })
        .to_string();

        self.log_event(EventType::AccountSoftDelete, Some(id), Some(&metadata))?;

        Ok(())
    }

    /// Get an account by ID with its passwords decrypted.
    pub fn get_account_decrypted(&self, id: &str) -> Result<DecryptedAccount, String> {
        let account = db::get_account(&self.db, id)?
            .ok_or_else(|| format!("Account {} not found", id))?;

        let username = crypto::decrypt_string(&self.master_key, &account.username)?;
        let password = crypto::decrypt_string(&self.master_key, &account.password)?;
        let notes = match &account.notes {
            Some(n) => Some(crypto::decrypt_string(&self.master_key, n)?),
            None => None,
        };

        Ok(DecryptedAccount {
            service_name: account.service_name,
            username,
            password,
            notes,
            created_at: account.created_at,
            updated_at: account.updated_at,
            deleted_at: account.deleted_at,
        })
    }

    /// Search accounts by service name.
    pub fn search_accounts(&self, query: &str) -> Result<Vec<AccountSummary>, String> {
        db::search_accounts(&self.db, query, false)
    }

    /// Log a password show event.
    pub fn log_password_show(&self, account_id: &str) -> Result<(), String> {
        let metadata = serde_json::json!({
            "reveal_duration_seconds": self.config.ui.show_password_seconds
        })
        .to_string();
        self.log_event(EventType::PasswordShow, Some(account_id), Some(&metadata))
    }

    /// Log a password copy event.
    pub fn log_password_copy(&self, account_id: &str) -> Result<(), String> {
        self.log_event(EventType::PasswordCopy, Some(account_id), None)
    }

    /// Log auto-lock event.
    pub fn log_auto_lock(&self) -> Result<(), String> {
        self.log_event(EventType::AutoLock, None, None)
    }

    /// Log manual lock event.
    pub fn log_manual_lock(&self) -> Result<(), String> {
        self.log_event(EventType::ManualLock, None, None)
    }

    /// Log app start.
    pub fn log_app_start(&self) -> Result<(), String> {
        self.log_event(EventType::AppStart, None, None)
    }

    /// Log unlock success.
    pub fn log_unlock_success(&self) -> Result<(), String> {
        self.log_event(EventType::UnlockSuccess, None, None)
    }

    /// Log app exit.
    pub fn log_app_exit(&self) -> Result<(), String> {
        self.log_event(EventType::AppExit, None, None)
    }

    /// Export all accounts (still encrypted).
    pub fn export_accounts(&self) -> Result<Vec<Account>, String> {
        db::get_all_accounts(&self.db)
    }

    /// Log config change event.
    pub fn log_config_change(&self) -> Result<(), String> {
        self.log_event(EventType::ConfigChange, None, None)
    }

    /// Log backup export event.
    pub fn log_backup_export(&self) -> Result<(), String> {
        self.log_event(EventType::BackupExport, None, None)
    }

    /// Log backup import event.
    pub fn log_backup_import(&self) -> Result<(), String> {
        self.log_event(EventType::BackupImport, None, None)
    }

}

/// A decrypted account for display.
#[derive(Debug, Clone)]
pub struct DecryptedAccount {
    pub service_name: String,
    pub username: String,
    pub password: String,
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_vault() -> Vault {
        let db_path = "/tmp/test_service_vault.db";
        let audit_path = "/tmp/test_service_audit.log";
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
    fn test_create_and_read_account() {
        let vault = setup_vault();
        
        let account = vault.create_account("github", "user@example.com", "mypassword", Some("personal account")).unwrap();
        assert_eq!(account.service_name, "github");
        
        let decrypted = vault.get_account_decrypted(&account.id).unwrap();
        assert_eq!(decrypted.username, "user@example.com");
        assert_eq!(decrypted.password, "mypassword");
        assert_eq!(decrypted.notes, Some("personal account".to_string()));
    }

    #[test]
    fn test_update_account() {
        let vault = setup_vault();
        let account = vault.create_account("github", "user", "pass1", None).unwrap();
        
        let _updated = vault.update_account(&account.id, None, Some("newuser"), Some("pass2"), None).unwrap();
        
        let decrypted = vault.get_account_decrypted(&account.id).unwrap();
        assert_eq!(decrypted.username, "newuser");
        assert_eq!(decrypted.password, "pass2");
        
        // Check history: pass1 should be in history
        let history = vault.get_password_history_decrypted(&account.id).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0], "pass1");
    }

    #[test]
    fn test_delete_account() {
        let vault = setup_vault();
        let account = vault.create_account("test", "user", "pass", None).unwrap();
        
        vault.delete_account(&account.id).unwrap();
        
        // Should not appear in search
        let results = vault.search_accounts("test").unwrap();
        assert_eq!(results.len(), 0);
        
        // Should appear in search when including deleted
        let results = vault.search_all_accounts("test").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search() {
        let vault = setup_vault();
        vault.create_account("GitHub", "a", "b", None).unwrap();
        vault.create_account("GitLab", "c", "d", None).unwrap();
        vault.create_account("Twitter", "e", "f", None).unwrap();
        
        let results = vault.search_accounts("git").unwrap();
        assert_eq!(results.len(), 2);
        
        let results = vault.search_accounts("twitter").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_password_history_pruning() {
        let vault = setup_vault();
        let account = vault.create_account("test", "u", "pass1", None).unwrap();
        
        // Change password 5 times
        vault.update_account(&account.id, None, None, Some("pass2"), None).unwrap();
        vault.update_account(&account.id, None, None, Some("pass3"), None).unwrap();
        vault.update_account(&account.id, None, None, Some("pass4"), None).unwrap();
        vault.update_account(&account.id, None, None, Some("pass5"), None).unwrap();
        
        // Should only have 3 history entries (oldest pruned)
        let history = vault.get_password_history_decrypted(&account.id).unwrap();
        assert_eq!(history.len(), 3);
    }
}
