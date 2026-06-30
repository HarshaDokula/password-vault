use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Represents an account credential.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct Account {
    pub id: String,
    pub service_name: String,
    pub username: Vec<u8>,   // encrypted
    pub password: Vec<u8>,   // encrypted
    pub notes: Option<Vec<u8>>, // encrypted
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

/// Display-safe representation (no plaintext secrets).
#[derive(Debug, Clone)]
pub struct AccountSummary {
    pub id: String,
    pub service_name: String,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

/// Password history entry (encrypted).
#[derive(Debug, Clone, Zeroize)]
pub struct PasswordHistoryEntry {
    pub id: String,
    pub account_id: String,
    pub password: Vec<u8>, // encrypted
    pub changed_at: String,
}

/// Audit event types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    AppStart,
    UnlockSuccess,
    UnlockFailure,
    AutoLock,
    ManualLock,
    AppExit,
    AccountCreate,
    AccountUpdate,
    AccountSoftDelete,
    PasswordShow,
    PasswordCopy,
    IntegrityCheckFailure,
    CorruptedLogDetected,
    RateLimitTriggered,
    BackupExport,
    BackupImport,
    ConfigChange,
    VaultInit,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::AppStart => "app_start",
            EventType::UnlockSuccess => "unlock_success",
            EventType::UnlockFailure => "unlock_failure",
            EventType::AutoLock => "auto_lock",
            EventType::ManualLock => "manual_lock",
            EventType::AppExit => "app_exit",
            EventType::AccountCreate => "account_create",
            EventType::AccountUpdate => "account_update",
            EventType::AccountSoftDelete => "account_soft_delete",
            EventType::PasswordShow => "password_show",
            EventType::PasswordCopy => "password_copy",
            EventType::IntegrityCheckFailure => "integrity_check_failure",
            EventType::CorruptedLogDetected => "corrupted_log_detected",
            EventType::RateLimitTriggered => "rate_limit_triggered",
            EventType::BackupExport => "backup_export",
            EventType::BackupImport => "backup_import",
            EventType::ConfigChange => "config_change",
            EventType::VaultInit => "vault_init",
        }
    }
}

/// Audit log entry (operational store).
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: String,
    pub session_id: String,
    pub event_type: EventType,
    pub account_id: Option<String>,
    pub metadata: Option<String>, // JSON
    pub prev_hash: String,
    pub entry_hash: String,
}

/// Configurable settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub security: SecurityConfig,
    pub clipboard: ClipboardConfig,
    pub ui: UiConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    pub max_attempts_per_minute: u32,
    pub auto_lock_minutes: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClipboardConfig {
    pub clear_after_seconds: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UiConfig {
    pub show_password_seconds: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub enable_audit_logs: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            security: SecurityConfig {
                max_attempts_per_minute: 5,
                auto_lock_minutes: 15,
            },
            clipboard: ClipboardConfig {
                clear_after_seconds: 20,
            },
            ui: UiConfig {
                show_password_seconds: 10,
            },
            logging: LoggingConfig {
                enable_audit_logs: true,
            },
        }
    }
}
