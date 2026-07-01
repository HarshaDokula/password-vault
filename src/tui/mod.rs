use std::io;
use std::time::{Duration, Instant};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use uuid::Uuid;

use crate::audit::IntegrityLog;
use crate::auth;
use crate::config;
use crate::db;
use crate::models::{AccountSummary, AppConfig};
use crate::services::{DecryptedAccount, Vault};
use crate::utils::RateLimiter;

/// Application state for the TUI.
enum AppState {
    Locked,
    ConfirmingPassword,
    Unlocked,
    AddingService,
    AddingUsername,
    AddingPassword,
    AddingNotes,
    EditingAccount { account_id: String, field: EditField },
    ShowingPassword { account: DecryptedAccount, reveal_until: Instant },
    ShowingHistory,
    EditingSettings,
    ConfirmDelete { account_id: String, service_name: String },
    SearchMode,
    Quitting,
}

#[derive(Clone, PartialEq)]
enum EditField {
    ServiceName,
    Username,
    Password,
    Notes,
}

/// Focused element in unlocked mode.
#[derive(Clone, PartialEq)]
enum Focus {
    AccountList,
    SearchBar,
}

/// Main TUI application.
pub struct App {
    state: AppState,
    vault_dir: String,
    db_path: String,
    audit_path: String,
    vault_exists: bool,
    
    // Authenticated state
    vault: Option<Vault>,
    rate_limiter: RateLimiter,
    
    // Lock screen
    password_input: String,
    first_password: String,
    
    // Search / accounts
    search_query: String,
    accounts: Vec<AccountSummary>,
    list_state: ListState,
    focus: Focus,
    
    // Add form
    add_service: String,
    add_username: String,
    add_password: String,
    add_notes: String,
    
    // Edit fields
    edit_input: String,
    
    // Messages
    message: String,
    message_until: Option<Instant>,
    
    // Auto-lock
    last_activity: Instant,
    config: AppConfig,
    
    // Clipboard manager
    clipboard: Option<Box<dyn crate::utils::clipboard::ClipboardProvider>>,
    clipboard_supported: bool,
    clipboard_clear_at: Option<Instant>,
    clipboard_account: Option<String>,
    // Integrity warnings
    integrity_warnings: Vec<String>,
    // Deleted accounts visibility
    show_deleted: bool,
    // Password history data
    history_account_name: String,
    history_passwords: Vec<(String, String)>, // (password, changed_at)
    // Settings editor
    settings_selected: usize,
    settings_editing: bool,
    settings_input: String,
}

impl App {
    pub fn new(vault_dir: String) -> Self {
        let db_path = format!("{}/vault.db", vault_dir);
        let audit_path = format!("{}/audit.log", vault_dir);
        let config = AppConfig::default();
        let vault_exists = std::path::Path::new(&db_path).exists();
        
        let (clipboard, clipboard_supported) = match crate::utils::clipboard::create_clipboard() {
            Ok(c) => {
                let supported = c.is_supported();
                (Some(c), supported)
            }
            Err(_) => (None, false),
        };
        
        App {
            state: AppState::Locked,
            vault_dir,
            db_path,
            audit_path,
            vault_exists,
            vault: None,
            rate_limiter: RateLimiter::new(config.security.max_attempts_per_minute),
            password_input: String::new(),
            first_password: String::new(),
            search_query: String::new(),
            accounts: Vec::new(),
            list_state: ListState::default(),
            focus: Focus::AccountList,
            add_service: String::new(),
            add_username: String::new(),
            add_password: String::new(),
            add_notes: String::new(),
            edit_input: String::new(),
            message: String::new(),
            message_until: None,
            last_activity: Instant::now(),
            config,
            clipboard,
            clipboard_supported,
            clipboard_clear_at: None,
            clipboard_account: None,
            integrity_warnings: Vec::new(),
            show_deleted: false,
            history_account_name: String::new(),
            history_passwords: Vec::new(),
            settings_selected: 0,
            settings_editing: false,
            settings_input: String::new(),
        }
    }

    fn ensure_vault_exists(&self) -> Result<(), String> {
        config::ensure_vault_dir(&self.vault_dir)?;
        
        // Init db if it doesn't exist
        if !std::path::Path::new(&self.db_path).exists() {
            db::open(&self.db_path)?;
        }
        Ok(())
    }

    fn try_unlock(&mut self) -> Result<(), String> {
        self.ensure_vault_exists()?;
        
        let conn = db::open(&self.db_path)?;
        let salt = auth::get_or_create_salt(&conn)?;
        let il = IntegrityLog::open(&self.audit_path).ok();
        
        match auth::authenticate(&conn, &self.password_input, &salt, &mut self.rate_limiter, "tui", il.as_ref())? {
            auth::AuthResult::VaultCreated { master_key: _ } => {
                // First launch: store password for confirmation step
                self.first_password = self.password_input.clone();
                self.password_input.clear();
                self.state = AppState::ConfirmingPassword;
                self.message = String::new();
                self.message_until = None;
            }
            auth::AuthResult::Unlocked { master_key } => {
                let session_id = Uuid::new_v4().to_string();
                let integrity_log = IntegrityLog::open(&self.audit_path)?;
                
                let vault = Vault::new(conn, integrity_log, master_key, session_id, self.config.clone());
                vault.log_app_start()?;
                vault.log_unlock_success()?;
                
                self.vault = Some(vault);
                self.state = AppState::Unlocked;
                self.password_input.clear();
                self.refresh_accounts()?;
                self.vault_exists = true;
                self.last_activity = Instant::now();

                // Run integrity check on startup
                if let Some(ref v) = self.vault {
                    match v.verify_integrity() {
                        Ok(issues) => {
                            if !issues.is_empty() {
                                self.integrity_warnings = issues;
                            }
                        }
                        Err(_) => {
                            self.integrity_warnings = vec!["Integrity check failed to run.".to_string()];
                        }
                    }
                }

                self.message = "Vault unlocked!".to_string();
                self.message_until = Some(Instant::now() + Duration::from_secs(2));
            }
            auth::AuthResult::Failed(msg) => {
                self.message = msg;
                self.message_until = Some(Instant::now() + Duration::from_secs(3));
                self.password_input.clear();
                // Log failure
                if let Ok(il) = IntegrityLog::open(&self.audit_path) {
                    let remaining = self.rate_limiter.remaining_attempts("tui");
                    let _ = il.append(
                        crate::models::EventType::UnlockFailure,
                        "pre-auth",
                        None,
                        Some(&serde_json::json!({"remaining_attempts": remaining}).to_string()),
                    );
                }
            }
        }
        
        Ok(())
    }

    fn confirm_password(&mut self) -> Result<(), String> {
        if self.password_input != self.first_password {
            // Clear the prematurely stored validation token so user can start over
            if let Ok(conn) = db::open(&self.db_path) {
                let _ = conn.execute(
                    "DELETE FROM vault_metadata WHERE key = 'validation_token'",
                    [],
                );
            }
            self.vault_exists = false;
            self.message = "Passwords do not match. Please try again.".to_string();
            self.message_until = Some(Instant::now() + Duration::from_secs(3));
            self.password_input.clear();
            self.first_password.clear();
            self.state = AppState::Locked;
            return Ok(());
        }

        self.ensure_vault_exists()?;
        let conn = db::open(&self.db_path)?;
        let salt = auth::get_or_create_salt(&conn)?;
        let master_key = auth::derive_master_key(&self.password_input, &salt)?;

        let session_id = Uuid::new_v4().to_string();
        let integrity_log = IntegrityLog::open(&self.audit_path)?;
        
        let vault = Vault::new(conn, integrity_log, master_key, session_id.clone(), self.config.clone());
        
        // Log vault init through the vault's integrity log
        vault.log_event(crate::models::EventType::VaultInit, None, None)?;
        vault.log_app_start()?;
        vault.log_unlock_success()?;
        
        // Write a commented default config.toml so the user sees all options
        let _ = config::save_default_config_if_missing(&self.vault_dir);
        
        self.vault = Some(vault);
        self.state = AppState::Unlocked;
        self.password_input.clear();
        self.first_password.clear();
        self.vault_exists = true;
        self.refresh_accounts()?;

        // Run integrity check on startup
        if let Some(ref v) = self.vault {
            match v.verify_integrity() {
                Ok(issues) => {
                    if !issues.is_empty() {
                        self.integrity_warnings = issues;
                    }
                }
                Err(_) => {
                    self.integrity_warnings = vec!["Integrity check failed to run.".to_string()];
                }
            }
        }

        self.message = "New vault created!".to_string();
        self.message_until = Some(Instant::now() + Duration::from_secs(3));
        self.last_activity = Instant::now();

        Ok(())
    }

    fn lock(&mut self) -> Result<(), String> {
        if let Some(ref vault) = self.vault {
            vault.log_manual_lock()?;
        }
        self.vault = None;
        self.state = AppState::Locked;
        self.accounts.clear();
        self.search_query.clear();
        self.show_deleted = false;
        Ok(())
    }

    fn auto_lock(&mut self) -> Result<(), String> {
        if let Some(ref vault) = self.vault {
            vault.log_auto_lock()?;
        }
        self.vault = None;
        self.state = AppState::Locked;
        self.accounts.clear();
        self.search_query.clear();
        self.show_deleted = false;
        self.password_input.clear();
        self.message = "Auto-locked due to inactivity.".to_string();
        self.message_until = Some(Instant::now() + Duration::from_secs(5));
        Ok(())
    }

    fn refresh_accounts(&mut self) -> Result<(), String> {
        if let Some(ref vault) = self.vault {
            self.accounts = if self.show_deleted {
                vault.search_all_accounts(&self.search_query)?
            } else {
                vault.search_accounts(&self.search_query)?
            };
            
            if self.accounts.is_empty() && self.list_state.selected().is_some() {
                self.list_state.select(None);
            }
        }
        Ok(())
    }

    fn handle_key_locked(&mut self, key: KeyEvent) -> Result<(), String> {
        match key.code {
            KeyCode::Enter => {
                if !self.password_input.is_empty() {
                    self.try_unlock()?;
                }
            }
            KeyCode::Char(c) => {
                self.password_input.push(c);
            }
            KeyCode::Backspace => {
                self.password_input.pop();
            }
            KeyCode::Esc => {
                self.state = AppState::Quitting;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_key_confirming_password(&mut self, key: KeyEvent) -> Result<(), String> {
        match key.code {
            KeyCode::Enter => {
                if !self.password_input.is_empty() {
                    self.confirm_password()?;
                }
            }
            KeyCode::Char(c) => {
                self.password_input.push(c);
            }
            KeyCode::Backspace => {
                self.password_input.pop();
            }
            KeyCode::Esc => {
                // Cancel: go back to lock screen, remove the premature validation token
                self.password_input.clear();
                self.first_password.clear();
                if let Ok(conn) = db::open(&self.db_path) {
                    let _ = conn.execute(
                        "DELETE FROM vault_metadata WHERE key = 'validation_token'",
                        [],
                    );
                }
                self.vault_exists = false;
                self.state = AppState::Locked;
                self.message = "Vault creation cancelled.".to_string();
                self.message_until = Some(Instant::now() + Duration::from_secs(2));
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_key_unlocked(&mut self, key: KeyEvent) -> Result<(), String> {
        self.last_activity = Instant::now();
        
        match &self.state {
            AppState::SearchMode => {
                match key.code {
                    KeyCode::Esc => {
                        self.search_query.clear();
                        self.state = AppState::Unlocked;
                        self.focus = Focus::AccountList;
                        self.refresh_accounts()?;
                    }
                    KeyCode::Enter => {
                        self.state = AppState::Unlocked;
                        self.focus = Focus::AccountList;
                        self.refresh_accounts()?;
                    }
                    KeyCode::Char(c) => {
                        self.search_query.push(c);
                        self.refresh_accounts()?;
                    }
                    KeyCode::Backspace => {
                        self.search_query.pop();
                        self.refresh_accounts()?;
                    }
                    _ => {}
                }
            }
            _ => self.handle_unlocked_default(key)?,
        }
        Ok(())
    }

    fn handle_unlocked_default(&mut self, key: KeyEvent) -> Result<(), String> {
        match key.code {
            KeyCode::Char('/') => {
                self.state = AppState::SearchMode;
                self.focus = Focus::SearchBar;
                self.search_query.clear();
            }
            KeyCode::Char('q') => {
                self.state = AppState::Quitting;
            }
            KeyCode::Char('l') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.lock()?;
            }
            KeyCode::Char('a') => {
                // Start adding
                self.state = AppState::AddingService;
                self.add_service.clear();
                self.add_username.clear();
                self.add_password.clear();
                self.add_notes.clear();
            }
            KeyCode::Char('e') => {
                // Edit selected account
                if let Some(idx) = self.list_state.selected() {
                    if let Some(account) = self.accounts.get(idx) {
                        self.state = AppState::EditingAccount {
                            account_id: account.id.clone(),
                            field: EditField::ServiceName,
                        };
                        self.edit_input.clear();
                    }
                }
            }
            KeyCode::Char('s') => {
                // Show password
                if let Some(idx) = self.list_state.selected() {
                    if let Some(account) = self.accounts.get(idx) {
                        if let Some(ref vault) = self.vault {
                            match vault.get_account_decrypted(&account.id) {
                                Ok(decrypted) => {
                                    let duration = Duration::from_secs(
                                        self.config.ui.show_password_seconds as u64
                                    );
                                    vault.log_password_show(&account.id)?;
                                    self.state = AppState::ShowingPassword {
                                        account: decrypted,
                                        reveal_until: Instant::now() + duration,
                                    };
                                }
                                Err(e) => {
                                    self.message = format!("Error: {}", e);
                                    self.message_until = Some(Instant::now() + Duration::from_secs(3));
                                }
                            }
                        }
                    }
                }
            }
            KeyCode::Char('c') => {
                // Copy password
                if !self.clipboard_supported {
                    self.message = "Clipboard unsupported on this platform.".to_string();
                    self.message_until = Some(Instant::now() + Duration::from_secs(3));
                } else if let Some(idx) = self.list_state.selected() {
                    if let Some(acct) = self.accounts.get(idx) {
                        if let Some(ref vault) = self.vault {
                            match vault.get_account_decrypted(&acct.id) {
                                Ok(decrypted) => {
                                    if let Some(ref mut clip) = self.clipboard {
                                        match clip.copy_to_clipboard(&decrypted.password) {
                                            Ok(()) => {
                                                vault.log_password_copy(&acct.id)?;
                                                let dur = Duration::from_secs(
                                                    self.config.clipboard.clear_after_seconds as u64
                                                );
                                                self.clipboard_clear_at = Some(Instant::now() + dur);
                                                self.clipboard_account = Some(acct.id.clone());
                                                self.message = "Password copied to clipboard!".to_string();
                                                self.message_until = Some(Instant::now() + Duration::from_secs(3));
                                            }
                                            Err(e) => {
                                                self.message = e;
                                                self.message_until = Some(Instant::now() + Duration::from_secs(3));
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    self.message = format!("Error: {}", e);
                                    self.message_until = Some(Instant::now() + Duration::from_secs(3));
                                }
                            }
                        }
                    }
                }
            }
            KeyCode::Char('d') => {
                // Delete
                if let Some(idx) = self.list_state.selected() {
                    if let Some(account) = self.accounts.get(idx) {
                        self.edit_input.clear();
                        self.state = AppState::ConfirmDelete {
                            account_id: account.id.clone(),
                            service_name: account.service_name.clone(),
                        };
                    }
                }
            }
            KeyCode::F(2) => {
                // Open settings
                self.settings_selected = 0;
                self.settings_editing = false;
                self.settings_input.clear();
                self.state = AppState::EditingSettings;
            }
            KeyCode::Char('t') => {
                // Toggle show deleted
                self.show_deleted = !self.show_deleted;
                self.refresh_accounts()?;
            }
            KeyCode::Char('h') => {
                // View password history
                if let Some(idx) = self.list_state.selected() {
                    if let Some(account) = self.accounts.get(idx) {
                        if let Some(ref vault) = self.vault {
                            match vault.get_password_history_decrypted(&account.id) {
                                Ok(passwords) => {
                                    // Also get timestamps from the db entries
                                    let entries = db::get_password_history(&vault.db, &account.id).unwrap_or_default();
                                    let mut history: Vec<(String, String)> = Vec::new();
                                    for (i, pw) in passwords.iter().enumerate() {
                                        let ts = entries.get(i)
                                            .map(|e| e.changed_at.clone())
                                            .unwrap_or_else(|| "unknown".to_string());
                                        history.push((pw.clone(), ts));
                                    }
                                    self.history_account_name = account.service_name.clone();
                                    self.history_passwords = history;
                                    self.state = AppState::ShowingHistory;
                                }
                                Err(e) => {
                                    self.message = format!("Error: {}", e);
                                    self.message_until = Some(Instant::now() + Duration::from_secs(3));
                                }
                            }
                        }
                    }
                }
            }
            KeyCode::Up => {
                if !self.accounts.is_empty() {
                    let selected = self.list_state.selected().unwrap_or(0);
                    let new = if selected == 0 {
                        self.accounts.len() - 1
                    } else {
                        selected - 1
                    };
                    self.list_state.select(Some(new));
                }
            }
            KeyCode::Down
                if !self.accounts.is_empty() => {
                    let selected = self.list_state.selected().unwrap_or(0);
                    let new = if selected + 1 >= self.accounts.len() {
                        0
                    } else {
                        selected + 1
                    };
                    self.list_state.select(Some(new));
                }
            _ => {}
        }
        Ok(())
    }

    fn handle_add_service(&mut self, key: KeyEvent) -> Result<(), String> {
        match key.code {
            KeyCode::Esc => {
                self.state = AppState::Unlocked;
                self.refresh_accounts()?;
            }
            KeyCode::Enter => {
                if !self.add_service.is_empty() {
                    self.state = AppState::AddingUsername;
                }
            }
            KeyCode::Char(c) => self.add_service.push(c),
            KeyCode::Backspace => { self.add_service.pop(); }
            _ => {}
        }
        Ok(())
    }

    fn handle_add_username(&mut self, key: KeyEvent) -> Result<(), String> {
        match key.code {
            KeyCode::Esc => {
                self.state = AppState::Unlocked;
                self.refresh_accounts()?;
            }
            KeyCode::Enter => {
                if !self.add_username.is_empty() {
                    self.state = AppState::AddingPassword;
                }
            }
            KeyCode::Char(c) => self.add_username.push(c),
            KeyCode::Backspace => { self.add_username.pop(); }
            _ => {}
        }
        Ok(())
    }

    fn handle_add_password(&mut self, key: KeyEvent) -> Result<(), String> {
        match key.code {
            KeyCode::Esc => {
                self.state = AppState::Unlocked;
                self.refresh_accounts()?;
            }
            KeyCode::Enter => {
                if !self.add_password.is_empty() {
                    self.state = AppState::AddingNotes;
                }
            }
            KeyCode::Char(c) => self.add_password.push(c),
            KeyCode::Backspace => { self.add_password.pop(); }
            _ => {}
        }
        Ok(())
    }

    fn handle_add_notes(&mut self, key: KeyEvent) -> Result<(), String> {
        match key.code {
            KeyCode::Esc => {
                self.state = AppState::Unlocked;
                self.refresh_accounts()?;
            }
            KeyCode::Enter => {
                // Create account
                if let Some(ref vault) = self.vault {
                    let notes = if self.add_notes.is_empty() { None } else { Some(self.add_notes.as_str()) };
                    match vault.create_account(&self.add_service, &self.add_username, &self.add_password, notes) {
                        Ok(_) => {
                            self.message = format!("Account '{}' created!", self.add_service);
                            self.message_until = Some(Instant::now() + Duration::from_secs(3));
                        }
                        Err(e) => {
                            self.message = format!("Error: {}", e);
                            self.message_until = Some(Instant::now() + Duration::from_secs(3));
                        }
                    }
                }
                self.state = AppState::Unlocked;
                self.refresh_accounts()?;
            }
            KeyCode::Char(c) => self.add_notes.push(c),
            KeyCode::Backspace => { self.add_notes.pop(); }
            _ => {}
        }
        Ok(())
    }

    fn handle_editing(&mut self, key: KeyEvent, account_id: &str, field: &EditField) -> Result<(), String> {
        match key.code {
            KeyCode::Esc => {
                self.state = AppState::Unlocked;
                self.refresh_accounts()?;
            }
            KeyCode::Enter => {
                if let Some(ref vault) = self.vault {
                    let edit_val = self.edit_input.clone();
                    let result = match field {
                        EditField::ServiceName => vault.update_account(account_id, Some(&edit_val), None, None, None),
                        EditField::Username => vault.update_account(account_id, None, Some(&edit_val), None, None),
                        EditField::Password => vault.update_account(account_id, None, None, Some(&edit_val), None),
                        EditField::Notes => vault.update_account(account_id, None, None, None, Some(Some(&edit_val))),
                    };
                    
                    match result {
                        Ok(_) => {
                            // Move to next field or finish
                            match field {
                                EditField::ServiceName => {
                                    self.state = AppState::EditingAccount {
                                        account_id: account_id.to_string(),
                                        field: EditField::Username,
                                    };
                                    self.edit_input.clear();
                                    return Ok(());
                                }
                                EditField::Username => {
                                    self.state = AppState::EditingAccount {
                                        account_id: account_id.to_string(),
                                        field: EditField::Password,
                                    };
                                    self.edit_input.clear();
                                    return Ok(());
                                }
                                EditField::Password => {
                                    self.state = AppState::EditingAccount {
                                        account_id: account_id.to_string(),
                                        field: EditField::Notes,
                                    };
                                    self.edit_input.clear();
                                    return Ok(());
                                }
                                EditField::Notes => {
                                    self.state = AppState::Unlocked;
                                    self.refresh_accounts()?;
                                    self.message = "Account updated!".to_string();
                                    self.message_until = Some(Instant::now() + Duration::from_secs(2));
                                }
                            }
                        }
                        Err(e) => {
                            self.message = format!("Error: {}", e);
                            self.message_until = Some(Instant::now() + Duration::from_secs(3));
                            self.state = AppState::Unlocked;
                            self.refresh_accounts()?;
                        }
                    }
                }
            }
            KeyCode::Tab => {
                // Skip to next field
                match field {
                    EditField::ServiceName => {
                        self.state = AppState::EditingAccount {
                            account_id: account_id.to_string(),
                            field: EditField::Username,
                        };
                    }
                    EditField::Username => {
                        self.state = AppState::EditingAccount {
                            account_id: account_id.to_string(),
                            field: EditField::Password,
                        };
                    }
                    EditField::Password => {
                        self.state = AppState::EditingAccount {
                            account_id: account_id.to_string(),
                            field: EditField::Notes,
                        };
                    }
                    EditField::Notes => {
                        self.state = AppState::Unlocked;
                        self.refresh_accounts()?;
                    }
                }
                self.edit_input.clear();
            }
            KeyCode::Char(c) => self.edit_input.push(c),
            KeyCode::Backspace => { self.edit_input.pop(); }
            _ => {}
        }
        Ok(())
    }

    fn handle_delete_confirm(&mut self, key: KeyEvent, account_id: &str) -> Result<(), String> {
        match key.code {
            KeyCode::Esc => {
                self.state = AppState::Unlocked;
                self.refresh_accounts()?;
            }
            KeyCode::Enter => {
                if self.edit_input == "DELETE" {
                    if let Some(ref vault) = self.vault {
                        match vault.delete_account(account_id) {
                            Ok(()) => {
                                self.message = "Account deleted.".to_string();
                                self.message_until = Some(Instant::now() + Duration::from_secs(3));
                            }
                            Err(e) => {
                                self.message = format!("Error: {}", e);
                                self.message_until = Some(Instant::now() + Duration::from_secs(3));
                            }
                        }
                    }
                }
                self.state = AppState::Unlocked;
                self.refresh_accounts()?;
            }
            KeyCode::Char(c) => self.edit_input.push(c),
            KeyCode::Backspace => { self.edit_input.pop(); }
            _ => {}
        }
        Ok(())
    }

    fn handle_key_event(&mut self, key: KeyEvent) -> Result<(), String> {
        // Global Ctrl+C to quit
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.state = AppState::Quitting;
            return Ok(());
        }

        match &self.state {
            AppState::Locked => self.handle_key_locked(key)?,
            AppState::ConfirmingPassword => self.handle_key_confirming_password(key)?,
            AppState::Unlocked | AppState::SearchMode => self.handle_key_unlocked(key)?,
            AppState::AddingService => self.handle_add_service(key)?,
            AppState::AddingUsername => self.handle_add_username(key)?,
            AppState::AddingPassword => self.handle_add_password(key)?,
            AppState::AddingNotes => self.handle_add_notes(key)?,
            AppState::EditingAccount { account_id, field } => {
                let account_id = account_id.clone();
                let field = field.clone();
                self.handle_editing(key, &account_id, &field)?;
            }
            AppState::ConfirmDelete { account_id, .. } => {
                let account_id = account_id.clone();
                self.handle_delete_confirm(key, &account_id)?;
            }
            AppState::ShowingPassword { .. } | AppState::ShowingHistory => {
                if key.code == KeyCode::Esc || key.code == KeyCode::Enter {
                    self.state = AppState::Unlocked;
                }
            }
            AppState::EditingSettings => self.handle_settings(key)?,
            AppState::Quitting => {}
        }
        Ok(())
    }

    fn check_timeouts(&mut self) -> Result<(), String> {
        // Auto-lock check (0 = disabled, applies to all authenticated states)
        let is_authenticated = !matches!(self.state, AppState::Locked | AppState::ConfirmingPassword | AppState::Quitting);
        if is_authenticated
            && self.config.security.auto_lock_minutes > 0 {
                let auto_lock = Duration::from_secs(self.config.security.auto_lock_minutes as u64 * 60);
                if self.last_activity.elapsed() >= auto_lock {
                    self.auto_lock()?;
                }
            }

        // Password show timeout
        if let AppState::ShowingPassword { reveal_until, .. } = self.state {
            if Instant::now() >= reveal_until {
                self.state = AppState::Unlocked;
            }
        }

        // Clipboard clear timeout
        if let Some(clear_at) = self.clipboard_clear_at {
            if Instant::now() >= clear_at {
                if let Some(ref mut clip) = self.clipboard {
                    let _ = clip.clear_clipboard();
                }
                self.clipboard_clear_at = None;
                self.clipboard_account = None;
            }
        }

        // Message timeout
        if let Some(until) = self.message_until {
            if Instant::now() >= until {
                self.message.clear();
                self.message_until = None;
            }
        }

        Ok(())
    }

    /// Run the main TUI loop.
    pub fn run(&mut self) -> Result<(), String> {
        enable_raw_mode().map_err(|e| format!("Terminal error: {}", e))?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
            .map_err(|e| format!("Terminal error: {}", e))?;

        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend).map_err(|e| format!("Terminal error: {}", e))?;

        let res = self.event_loop(&mut terminal);

        // Cleanup - ignore errors during cleanup
        let _ = disable_raw_mode();
        let _ = execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        let _ = terminal.show_cursor();

        res
    }

    fn event_loop<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<(), String> {
        loop {
            self.check_timeouts()?;

            // Draw
            terminal
                .draw(|f| self.ui(f))
                .map_err(|e| format!("Render error: {}", e))?;

            // Handle input with a timeout to allow auto-lock etc.
            if event::poll(Duration::from_millis(100))
                .map_err(|e| format!("Event error: {}", e))?
            {
                let evt = event::read().map_err(|e| format!("Event error: {}", e))?;
                if let Event::Key(key) = evt {
                    self.handle_key_event(key)?;
                }
            }

            if matches!(self.state, AppState::Quitting) {
                break;
            }
        }

        // Log exit
        if let Some(ref vault) = self.vault {
            vault.log_app_exit()?;
        }

        // Clear clipboard on exit
        if let Some(ref mut clip) = self.clipboard {
            let _ = clip.clear_clipboard();
        }

        Ok(())
    }

    fn ui(&mut self, f: &mut Frame) {
        let size = f.area();

        match &self.state {
            AppState::Locked => self.render_lock_screen(f, size),
            AppState::ConfirmingPassword => self.render_confirm_password(f, size),
            AppState::ShowingPassword { account, .. } => self.render_password_screen(f, size, account),
            AppState::ShowingHistory => self.render_history_screen(f, size),
            AppState::EditingSettings => self.render_settings(f, size),
            AppState::AddingService | AppState::AddingUsername | AppState::AddingPassword | AppState::AddingNotes => {
                self.render_add_form(f, size);
            }
            AppState::EditingAccount { account_id, field } => {
                self.render_edit_form(f, size, account_id, field);
            }
            AppState::ConfirmDelete { account_id, service_name } => {
                self.render_delete_confirm(f, size, account_id, service_name);
            }
            _ => self.render_main(f, size),
        }
    }

    fn render_lock_screen(&self, f: &mut Frame, area: Rect) {
        let title = if self.vault_exists {
            " Vault Locked "
        } else {
            " Create Vault "
        };

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .style(Style::default());

        let inner = block.inner(area);
        f.render_widget(block, area);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
            ])
            .split(inner);

        let prompt = if self.vault_exists {
            "Enter Master Password:"
        } else {
            "Choose a Master Password:"
        };

        let title_p = Paragraph::new(prompt)
            .style(Style::default().fg(Color::Yellow))
            .alignment(Alignment::Center);
        f.render_widget(title_p, chunks[0]);

        let masked: String = self.password_input.chars().map(|_| '•').collect();
        let input = Paragraph::new(masked)
            .block(Block::default().borders(Borders::ALL))
            .style(Style::default().fg(Color::White));
        f.render_widget(input, chunks[1]);

        if !self.message.is_empty() {
            let msg = Paragraph::new(self.message.as_str())
                .style(Style::default().fg(Color::Red))
                .alignment(Alignment::Center);
            f.render_widget(msg, chunks[2]);
        }

        let help = Paragraph::new("Enter: Submit | Esc: Quit")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center);
        let help_area = Rect::new(area.x, area.y + area.height - 1, area.width, 1);
        f.render_widget(help, help_area);
    }

    fn render_confirm_password(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" Create Vault ")
            .borders(Borders::ALL)
            .style(Style::default());

        let inner = block.inner(area);
        f.render_widget(block, area);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
            ])
            .split(inner);

        let title = Paragraph::new("Confirm Master Password:")
            .style(Style::default().fg(Color::Yellow))
            .alignment(Alignment::Center);
        f.render_widget(title, chunks[0]);

        let masked: String = self.password_input.chars().map(|_| '•').collect();
        let input = Paragraph::new(masked)
            .block(Block::default().borders(Borders::ALL))
            .style(Style::default().fg(Color::White));
        f.render_widget(input, chunks[1]);

        if !self.message.is_empty() {
            let msg = Paragraph::new(self.message.as_str())
                .style(Style::default().fg(Color::Red))
                .alignment(Alignment::Center);
            f.render_widget(msg, chunks[2]);
        }

        let help = Paragraph::new("Enter: Confirm | Esc: Cancel")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center);
        let help_area = Rect::new(area.x, area.y + area.height - 1, area.width, 1);
        f.render_widget(help, help_area);
    }

    fn render_main(&mut self, f: &mut Frame, area: Rect) {
        let has_warnings = !self.integrity_warnings.is_empty();

        let constraints: Vec<Constraint> = if has_warnings {
            vec![
                Constraint::Length(2),
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(2),
                Constraint::Length(2),
                Constraint::Length(1),
            ]
        } else {
            vec![
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(2),
                Constraint::Length(2),
                Constraint::Length(1),
            ]
        };
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(area);

        // Integrity warnings
        if has_warnings {
            let warn_text = self.integrity_warnings.join(" | ");
            let warning = Paragraph::new(warn_text)
                .block(Block::default().borders(Borders::ALL).title(" ⚠ Integrity Warning "))
                .style(Style::default().fg(Color::Yellow).bg(Color::Red))
                .alignment(Alignment::Center);
            f.render_widget(warning, chunks[0]);
        }

        let offset = if has_warnings { 1 } else { 0 };

        // Search bar
        let in_search = matches!(self.state, AppState::SearchMode);
        let search_text = if in_search {
            format!("Search: {}█", self.search_query)
        } else if !self.search_query.is_empty() {
            format!("Filter: {} (press / to search)", self.search_query)
        } else {
            "Press / to search".to_string()
        };

        let search_style = if in_search {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::White)
        };
        let search_block = if in_search {
            Block::default()
                .borders(Borders::ALL)
                .title(" Search ")
                .border_style(Style::default().fg(Color::Yellow))
                .style(Style::default().bg(Color::DarkGray))
        } else {
            Block::default()
                .borders(Borders::ALL)
                .title(" Search ")
        };

        let search = Paragraph::new(search_text)
            .block(search_block)
            .style(search_style);
        f.render_widget(search, chunks[offset]);

        // Account list
        let items: Vec<ListItem> = self
            .accounts
            .iter()
            .map(|a| {
                let label = if a.deleted_at.is_some() {
                    format!("{} [deleted]", a.service_name)
                } else {
                    a.service_name.clone()
                };
                ListItem::new(label)
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(" Accounts "))
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");

        f.render_stateful_widget(list, chunks[offset + 1], &mut self.list_state);

        // Status / message
        let status = if !self.message.is_empty() {
            Span::styled(&self.message, Style::default().fg(Color::Green))
        } else if let Some(account) = self.list_state.selected().and_then(|i| self.accounts.get(i)) {
            let label = if account.deleted_at.is_some() {
                format!("Selected: {} (created: {}, updated: {}, deleted)", account.service_name, account.created_at, account.updated_at)
            } else {
                format!("Selected: {} (created: {}, updated: {})", account.service_name, account.created_at, account.updated_at)
            };
            Span::styled(label, Style::default().fg(Color::Gray))
        } else {
            Span::styled("No accounts", Style::default().fg(Color::Gray))
        };

        let status_line = Line::from(status);
        f.render_widget(Paragraph::new(status_line), chunks[offset + 2]);

        // Help
        let deleted_indicator = if self.show_deleted { " [DELETED]" } else { "" };
        let help_text = format!("[a] add  [e] edit  [s] show  [c] copy  [h] history  [d] delete  [t] toggle  [/] search  [F2] settings  [Ctrl+L] lock  [q] quit{}", deleted_indicator);
        let help = Paragraph::new(help_text)
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center);
        f.render_widget(help, chunks[offset + 3]);

        // Status bar
        let session_short = self.vault.as_ref()
            .map(|v| v.session_id())
            .map(|s| format!("Session: {}", &s[..8.min(s.len())]))
            .unwrap_or_default();

        let status_parts = vec![
            format!("Vault: {}", self.vault_dir),
            session_short,
            if self.config.security.auto_lock_minutes > 0 {
                let elapsed = self.last_activity.elapsed().as_secs();
                let max_secs = self.config.security.auto_lock_minutes as u64 * 60;
                if max_secs > elapsed {
                    format!("Auto-lock: {}s", max_secs - elapsed)
                } else {
                    "Auto-lock: now".to_string()
                }
            } else {
                "Auto-lock: off".to_string()
            },
            if self.show_deleted {
                "[Showing deleted]".to_string()
            } else {
                String::new()
            },
            if !self.clipboard_supported {
                "⚠ No clipboard".to_string()
            } else {
                String::new()
            },
            if !self.integrity_warnings.is_empty() {
                "⚠ Integrity issue".to_string()
            } else {
                String::new()
            },
        ];
        let status_text: Vec<String> = status_parts.into_iter().filter(|s| !s.is_empty()).collect();
        let status = Paragraph::new(status_text.join(" | "))
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Left);
        f.render_widget(status, chunks[offset + 4]);
    }

    fn handle_settings(&mut self, key: KeyEvent) -> Result<(), String> {
        self.last_activity = Instant::now();

        // Ctrl+S: save
        if key.code == KeyCode::Char('s') && key.modifiers.contains(KeyModifiers::CONTROL) {
            // Write config to file
            config::save_config(&self.vault_dir, &self.config)?;
            // Log config change
            if let Some(ref vault) = self.vault {
                vault.log_config_change()?;
            }
            self.message = "Settings saved!".to_string();
            self.message_until = Some(Instant::now() + Duration::from_secs(2));
            self.state = AppState::Unlocked;
            self.refresh_accounts()?;
            return Ok(());
        }

        if self.settings_editing {
            match key.code {
                KeyCode::Esc => {
                    self.settings_editing = false;
                    self.settings_input.clear();
                }
                KeyCode::Enter => {
                    // Parse and apply the value
                    let parsed = self.settings_input.trim().to_string();
                    match self.settings_selected {
                        0 => {
                            if let Ok(v) = parsed.parse::<u32>() {
                                self.config.security.max_attempts_per_minute = v;
                                self.rate_limiter = RateLimiter::new(v);
                            }
                        }
                        1 => {
                            if let Ok(v) = parsed.parse::<u32>() {
                                self.config.security.auto_lock_minutes = v;
                            }
                        }
                        2 => {
                            if let Ok(v) = parsed.parse::<u32>() {
                                self.config.clipboard.clear_after_seconds = v;
                            }
                        }
                        3 => {
                            if let Ok(v) = parsed.parse::<u32>() {
                                self.config.ui.show_password_seconds = v;
                            }
                        }
                        4 => {
                            let lower = parsed.to_lowercase();
                            if lower == "true" || lower == "yes" || lower == "1" {
                                self.config.logging.enable_audit_logs = true;
                            } else if lower == "false" || lower == "no" || lower == "0" {
                                self.config.logging.enable_audit_logs = false;
                            }
                        }
                        _ => {}
                    }
                    self.settings_editing = false;
                    self.settings_input.clear();
                }
                KeyCode::Char(c) => {
                    self.settings_input.push(c);
                }
                KeyCode::Backspace => {
                    self.settings_input.pop();
                }
                _ => {}
            }
        } else {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.state = AppState::Unlocked;
                    self.refresh_accounts()?;
                }
                KeyCode::Up => {
                    if self.settings_selected > 0 {
                        self.settings_selected -= 1;
                    }
                }
                KeyCode::Down => {
                    if self.settings_selected < 4 {
                        self.settings_selected += 1;
                    }
                }
                KeyCode::Enter => {
                    // Start editing this field's current value
                    self.settings_editing = true;
                    self.settings_input = match self.settings_selected {
                        0 => self.config.security.max_attempts_per_minute.to_string(),
                        1 => self.config.security.auto_lock_minutes.to_string(),
                        2 => self.config.clipboard.clear_after_seconds.to_string(),
                        3 => self.config.ui.show_password_seconds.to_string(),
                        4 => self.config.logging.enable_audit_logs.to_string(),
                        _ => String::new(),
                    };
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn settings_field_value(&self, idx: usize) -> String {
        if self.settings_editing && self.settings_selected == idx {
            format!("{}█", self.settings_input)
        } else {
            match idx {
                0 => self.config.security.max_attempts_per_minute.to_string(),
                1 => self.config.security.auto_lock_minutes.to_string(),
                2 => self.config.clipboard.clear_after_seconds.to_string(),
                3 => self.config.ui.show_password_seconds.to_string(),
                4 => self.config.logging.enable_audit_logs.to_string(),
                _ => String::new(),
            }
        }
    }

    fn render_settings(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" Settings ")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Yellow));

        let inner = block.inner(area);
        f.render_widget(block, area);

        let field_names = [
            "max_attempts_per_minute",
            "auto_lock_minutes",
            "clipboard_clear_after_seconds",
            "show_password_seconds",
            "enable_audit_logs",
        ];

        let mut constraints: Vec<Constraint> = Vec::new();
        for _ in &field_names {
            constraints.push(Constraint::Length(3));
        }
        constraints.push(Constraint::Length(1));

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints(constraints)
            .split(inner);

        for (i, name) in field_names.iter().enumerate() {
            let is_selected = i == self.settings_selected;
            let field_style = if is_selected {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let text = if is_selected {
                format!("> {}: {}", name, self.settings_field_value(i))
            } else {
                format!("  {}: {}", name, self.settings_field_value(i))
            };

            f.render_widget(
                Paragraph::new(text).style(field_style),
                chunks[i],
            );
        }

        let help = if self.settings_editing {
            "Enter: confirm  |  Esc: cancel edit  |  Ctrl+S: save"
        } else {
            "Up/Down: navigate  |  Enter: edit  |  Esc: cancel  |  Ctrl+S: save"
        };
        f.render_widget(
            Paragraph::new(help)
                .style(Style::default().fg(Color::DarkGray))
                .alignment(Alignment::Center),
            chunks[5],
        );
    }

    fn render_password_screen(&self, f: &mut Frame, area: Rect, account: &DecryptedAccount) {
        let block = Block::default()
            .title(format!(" {} ", account.service_name))
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Yellow));

        let inner_rect = block.inner(area);
        f.render_widget(block, area);

        // Count how many rows we need
        let has_notes = account.notes.is_some();
        let has_deleted = account.deleted_at.is_some();
        let mut row_count = 5; // username, password, created, updated, timeout
        if has_notes { row_count += 1; }
        if has_deleted { row_count += 1; }

        let mut constraints: Vec<Constraint> = Vec::new();
        for _ in 0..row_count {
            constraints.push(Constraint::Length(2));
        }
        constraints.push(Constraint::Length(1));

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints(constraints)
            .split(inner_rect);

        let mut row = 0;

        f.render_widget(
            Paragraph::new(format!("Username: {}", account.username)),
            chunks[row],
        );
        row += 1;

        f.render_widget(
            Paragraph::new(format!("Password: {}", account.password))
                .style(Style::default().fg(Color::Green)),
            chunks[row],
        );
        row += 1;

        if let Some(ref notes) = account.notes {
            f.render_widget(
                Paragraph::new(format!("Notes: {}", notes)),
                chunks[row],
            );
            row += 1;
        }

        f.render_widget(
            Paragraph::new(format!("Created: {}", account.created_at))
                .style(Style::default().fg(Color::DarkGray)),
            chunks[row],
        );
        row += 1;

        f.render_widget(
            Paragraph::new(format!("Updated: {}", account.updated_at))
                .style(Style::default().fg(Color::DarkGray)),
            chunks[row],
        );
        row += 1;

        if let Some(ref deleted) = account.deleted_at {
            f.render_widget(
                Paragraph::new(format!("Deleted: {}", deleted))
                    .style(Style::default().fg(Color::Red)),
                chunks[row],
            );
            row += 1;
        }

        let timeout_msg = format!(
            "Auto-hiding in {} seconds. Press any key to close.",
            self.config.ui.show_password_seconds
        );
        f.render_widget(
            Paragraph::new(timeout_msg)
                .style(Style::default().fg(Color::Gray)),
            chunks[row],
        );
    }

    fn render_history_screen(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(format!(" Password History: {} ", self.history_account_name))
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Yellow));

        let inner_rect = block.inner(area);
        f.render_widget(block, area);

        if self.history_passwords.is_empty() {
            let msg = Paragraph::new("No password history available.")
                .style(Style::default().fg(Color::Gray))
                .alignment(Alignment::Center);
            f.render_widget(msg, inner_rect);
        } else {
            let constraints: Vec<Constraint> = self.history_passwords
                .iter()
                .flat_map(|_| vec![Constraint::Length(2), Constraint::Length(1)])
                .chain(std::iter::once(Constraint::Length(1)))
                .collect();

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints(constraints)
                .split(inner_rect);

            for (i, (password, timestamp)) in self.history_passwords.iter().enumerate() {
                let ci = i * 2;
                let label = format!("Password #{} (changed {}):", i + 1, timestamp);
                f.render_widget(
                    Paragraph::new(label).style(Style::default().fg(Color::White)),
                    chunks[ci],
                );
                f.render_widget(
                    Paragraph::new(password.as_str()).style(Style::default().fg(Color::Green)),
                    chunks[ci + 1],
                );
            }

            let help_idx = self.history_passwords.len() * 2;
            if help_idx < chunks.len() {
                let help = Paragraph::new("Esc: close")
                    .style(Style::default().fg(Color::DarkGray))
                    .alignment(Alignment::Center);
                f.render_widget(help, chunks[help_idx]);
            }
        }
    }

    fn render_add_form(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" Add Account ")
            .borders(Borders::ALL);

        let inner_rect = block.inner(area);
        f.render_widget(block, area);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(inner_rect);

        let active_field = match &self.state {
            AppState::AddingService => 0,
            AppState::AddingUsername => 1,
            AppState::AddingPassword => 2,
            AppState::AddingNotes => 3,
            _ => 0,
        };

        let fields = [
            ("Service Name:", &self.add_service, active_field == 0),
            ("Username:", &self.add_username, active_field == 1),
            ("Password:", &self.add_password, active_field == 2),
            ("Notes (optional):", &self.add_notes, active_field == 3),
        ];

        for (i, (label, value, active)) in fields.iter().enumerate() {
            let style = if *active {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::White)
            };
            let display = if *active {
                format!("{} {}█", label, value)
            } else {
                format!("{} {}", label, value)
            };
            f.render_widget(Paragraph::new(display).style(style), chunks[i]);
        }

        let help = Paragraph::new("Enter: next  |  Esc: cancel")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(help, chunks[4]);
    }

    fn render_edit_form(&self, f: &mut Frame, area: Rect, _account_id: &str, field: &EditField) {
        let block = Block::default()
            .title(" Edit Account ")
            .borders(Borders::ALL);

        let inner_rect = block.inner(area);
        f.render_widget(block, area);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(inner_rect);

        let field_name = match field {
            EditField::ServiceName => "Service Name",
            EditField::Username => "Username",
            EditField::Password => "Password",
            EditField::Notes => "Notes",
        };

        f.render_widget(
            Paragraph::new(format!("{}: {}█", field_name, self.edit_input))
                .style(Style::default().fg(Color::Yellow)),
            chunks[0],
        );

        let help = Paragraph::new("Enter: next  |  Tab: skip  |  Esc: cancel")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(help, chunks[1]);
    }

    fn render_delete_confirm(&self, f: &mut Frame, area: Rect, _account_id: &str, service_name: &str) {
        let block = Block::default()
            .title(" Delete Account ")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Red));

        let inner_rect = block.inner(area);
        f.render_widget(block, area);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(2),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(inner_rect);

        f.render_widget(
            Paragraph::new(format!("Delete '{}'?", service_name))
                .style(Style::default().fg(Color::Red))
                .alignment(Alignment::Center),
            chunks[0],
        );

        f.render_widget(
            Paragraph::new(format!("Type DELETE to confirm: {}█", self.edit_input))
                .block(Block::default().borders(Borders::ALL)),
            chunks[1],
        );

        let help = Paragraph::new("Esc: cancel")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(help, chunks[2]);
    }

}
