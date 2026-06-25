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
use crate::models::AppConfig;
use crate::services::{DecryptedAccount, Vault};
use crate::utils::RateLimiter;

/// Application state for the TUI.
enum AppState {
    Locked,
    Unlocked,
    AddingService,
    AddingUsername,
    AddingPassword,
    AddingNotes,
    EditingAccount { account_id: String, field: EditField },
    ShowingPassword { account: DecryptedAccount, reveal_until: Instant },
    ConfirmDelete { account_id: String },
    ConfirmMessage { message: String },
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
    
    // Authenticated state
    vault: Option<Vault>,
    rate_limiter: RateLimiter,
    
    // Lock screen
    password_input: String,
    
    // Search / accounts
    search_query: String,
    accounts: Vec<(String, String)>, // (id, service_name)
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
    clipboard_clear_at: Option<Instant>,
    clipboard_account: Option<String>,
    
    // Password show

}

impl App {
    pub fn new(vault_dir: String) -> Self {
        let db_path = format!("{}/vault.db", vault_dir);
        let audit_path = format!("{}/audit.log", vault_dir);
        let config = AppConfig::default();
        
        let clipboard = crate::utils::clipboard::create_clipboard().ok();
        
        App {
            state: AppState::Locked,
            vault_dir,
            db_path,
            audit_path,
            vault: None,
            rate_limiter: RateLimiter::new(config.security.max_attempts_per_minute),
            password_input: String::new(),
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
            clipboard_clear_at: None,
            clipboard_account: None,
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
        
        match auth::authenticate(&conn, &self.password_input, &salt, &mut self.rate_limiter, "tui")? {
            auth::AuthResult::VaultCreated => {
                let master_key = auth::derive_master_key(&self.password_input, &salt)?;
                let session_id = Uuid::new_v4().to_string();
                let integrity_log = IntegrityLog::open(&self.audit_path)?;
                
                let vault = Vault::new(conn, integrity_log, master_key, session_id.clone(), self.config.clone());
                
                // Log vault init
                let il = IntegrityLog::open(&self.audit_path)?;
                il.append(crate::models::EventType::VaultInit, &session_id, None, None)?;
                
                vault.log_app_start()?;
                vault.log_unlock_success()?;
                
                self.vault = Some(vault);
                self.state = AppState::Unlocked;
                self.password_input.clear();
                self.refresh_accounts()?;
                self.message = "New vault created!".to_string();
                self.message_until = Some(Instant::now() + Duration::from_secs(3));
                self.last_activity = Instant::now();
            }
            auth::AuthResult::Unlocked => {
                let master_key = auth::derive_master_key(&self.password_input, &salt)?;
                let session_id = Uuid::new_v4().to_string();
                let integrity_log = IntegrityLog::open(&self.audit_path)?;
                
                let vault = Vault::new(conn, integrity_log, master_key, session_id, self.config.clone());
                vault.log_app_start()?;
                vault.log_unlock_success()?;
                
                self.vault = Some(vault);
                self.state = AppState::Unlocked;
                self.password_input.clear();
                self.refresh_accounts()?;
                self.message = "Vault unlocked!".to_string();
                self.message_until = Some(Instant::now() + Duration::from_secs(2));
                self.last_activity = Instant::now();
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

    fn lock(&mut self) -> Result<(), String> {
        if let Some(ref vault) = self.vault {
            vault.log_manual_lock()?;
        }
        self.vault = None;
        self.state = AppState::Locked;
        self.accounts.clear();
        self.search_query.clear();
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
        self.message = "Auto-locked due to inactivity.".to_string();
        self.message_until = Some(Instant::now() + Duration::from_secs(5));
        Ok(())
    }

    fn refresh_accounts(&mut self) -> Result<(), String> {
        if let Some(ref vault) = self.vault {
            let results = vault.search_accounts(&self.search_query)?;
            self.accounts = results
                .into_iter()
                .map(|a| (a.id, a.service_name))
                .collect();
            
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
                    if let Some((id, _)) = self.accounts.get(idx) {
                        self.state = AppState::EditingAccount {
                            account_id: id.clone(),
                            field: EditField::ServiceName,
                        };
                        self.edit_input.clear();
                    }
                }
            }
            KeyCode::Char('s') => {
                // Show password
                if let Some(idx) = self.list_state.selected() {
                    if let Some((id, _)) = self.accounts.get(idx) {
                        if let Some(ref vault) = self.vault {
                            match vault.get_account_decrypted(id) {
                                Ok(account) => {
                                    let duration = Duration::from_secs(
                                        self.config.ui.show_password_seconds as u64
                                    );
                                    vault.log_password_show(id)?;
                                    self.state = AppState::ShowingPassword {
                                        account,
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
                if let Some(idx) = self.list_state.selected() {
                    if let Some((id, _)) = self.accounts.get(idx) {
                        if let Some(ref vault) = self.vault {
                            match vault.get_account_decrypted(id) {
                                Ok(account) => {
                                    if let Some(ref mut clip) = self.clipboard {
                                        match clip.copy_to_clipboard(&account.password) {
                                            Ok(()) => {
                                                vault.log_password_copy(id)?;
                                                let dur = Duration::from_secs(
                                                    self.config.clipboard.clear_after_seconds as u64
                                                );
                                                self.clipboard_clear_at = Some(Instant::now() + dur);
                                                self.clipboard_account = Some(id.clone());
                                                self.message = "Password copied to clipboard!".to_string();
                                                self.message_until = Some(Instant::now() + Duration::from_secs(3));
                                            }
                                            Err(e) => {
                                                self.message = e;
                                                self.message_until = Some(Instant::now() + Duration::from_secs(3));
                                            }
                                        }
                                    } else {
                                        self.message = "Clipboard unsupported on this platform.".to_string();
                                        self.message_until = Some(Instant::now() + Duration::from_secs(3));
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
                    if let Some((id, _service_name)) = self.accounts.get(idx) {
                        self.state = AppState::ConfirmDelete {
                            account_id: id.clone(),
                        };
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
            KeyCode::Down => {
                if !self.accounts.is_empty() {
                    let selected = self.list_state.selected().unwrap_or(0);
                    let new = if selected + 1 >= self.accounts.len() {
                        0
                    } else {
                        selected + 1
                    };
                    self.list_state.select(Some(new));
                }
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
            AppState::ConfirmDelete { account_id } => {
                let account_id = account_id.clone();
                self.handle_delete_confirm(key, &account_id)?;
            }
            AppState::ShowingPassword { .. } => {
                if key.code == KeyCode::Esc || key.code == KeyCode::Enter {
                    self.state = AppState::Unlocked;
                }
            }
            AppState::ConfirmMessage { .. } => {
                if key.code == KeyCode::Esc || key.code == KeyCode::Enter {
                    self.state = AppState::Unlocked;
                }
            }
            AppState::Quitting => {}
        }
        Ok(())
    }

    fn check_timeouts(&mut self) -> Result<(), String> {
        // Auto-lock check
        if let AppState::Unlocked = self.state {
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
                match evt {
                    Event::Key(key) => {
                        self.handle_key_event(key)?;
                    }
                    _ => {}
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
            AppState::ShowingPassword { account, .. } => self.render_password_screen(f, size, account),
            AppState::AddingService | AppState::AddingUsername | AppState::AddingPassword | AppState::AddingNotes => {
                self.render_add_form(f, size);
            }
            AppState::EditingAccount { account_id, field } => {
                self.render_edit_form(f, size, account_id, field);
            }
            AppState::ConfirmDelete { account_id } => {
                self.render_delete_confirm(f, size, account_id);
            }
            AppState::ConfirmMessage { message } => {
                self.render_message(f, size, message);
            }
            _ => self.render_main(f, size),
        }
    }

    fn render_lock_screen(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" Vault Locked ")
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

        let title = Paragraph::new("Enter Master Password:")
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

        let help = Paragraph::new("Enter: Submit | Esc: Quit")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center);
        let help_area = Rect::new(area.x, area.y + area.height - 1, area.width, 1);
        f.render_widget(help, help_area);
    }

    fn render_main(&mut self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(2),
                Constraint::Length(2),
            ])
            .split(area);

        // Search bar
        let search_text = if matches!(self.state, AppState::SearchMode) {
            format!("Search: {}█", self.search_query)
        } else if !self.search_query.is_empty() {
            format!("Filter: {} (press / to search)", self.search_query)
        } else {
            "Press / to search".to_string()
        };

        let search = Paragraph::new(search_text)
            .block(Block::default().borders(Borders::ALL).title(" Search "))
            .style(Style::default().fg(Color::White));
        f.render_widget(search, chunks[0]);

        // Account list
        let items: Vec<ListItem> = self
            .accounts
            .iter()
            .map(|(_, name)| ListItem::new(name.as_str()))
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

        f.render_stateful_widget(list, chunks[1], &mut self.list_state);

        // Status / message
        let status = if !self.message.is_empty() {
            Span::styled(&self.message, Style::default().fg(Color::Green))
        } else if let Some((_, name)) = self.list_state.selected().and_then(|i| self.accounts.get(i)) {
            Span::styled(format!("Selected: {}", name), Style::default().fg(Color::Gray))
        } else {
            Span::styled("No accounts", Style::default().fg(Color::Gray))
        };

        let status_line = Line::from(status);
        f.render_widget(Paragraph::new(status_line), chunks[2]);

        // Help
        let help = Paragraph::new("[a] add  [e] edit  [s] show  [c] copy  [d] delete  [/] search  [Ctrl+L] lock  [q] quit")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center);
        f.render_widget(help, chunks[3]);
    }

    fn render_password_screen(&self, f: &mut Frame, area: Rect, account: &DecryptedAccount) {
        let block = Block::default()
            .title(format!(" {} ", account.service_name))
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Yellow));

        let inner_rect = block.inner(area);
        f.render_widget(block, area);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(2),
                Constraint::Length(2),
                Constraint::Length(2),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(inner_rect);

        f.render_widget(
            Paragraph::new(format!("Username: {}", account.username)),
            chunks[0],
        );

        f.render_widget(
            Paragraph::new(format!("Password: {}", account.password))
                .style(Style::default().fg(Color::Green)),
            chunks[1],
        );

        if let Some(ref notes) = account.notes {
            f.render_widget(
                Paragraph::new(format!("Notes: {}", notes)),
                chunks[2],
            );
        }

        let timeout_msg = format!(
            "Auto-hiding in {} seconds. Press any key to close.",
            self.config.ui.show_password_seconds
        );
        f.render_widget(
            Paragraph::new(timeout_msg)
                .style(Style::default().fg(Color::Gray)),
            chunks[3],
        );
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

    fn render_delete_confirm(&self, f: &mut Frame, area: Rect, account_id: &str) {
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
            Paragraph::new(format!("Delete {}?", account_id))
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

    fn render_message(&self, f: &mut Frame, area: Rect, msg: &str) {
        let block = Block::default()
            .borders(Borders::ALL);

        let inner_rect = block.inner(area);
        f.render_widget(block, area);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(2)
            .constraints([Constraint::Length(3), Constraint::Length(1)])
            .split(inner_rect);

        f.render_widget(
            Paragraph::new(msg)
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::Yellow)),
            chunks[0],
        );

        f.render_widget(
            Paragraph::new("Press any key to continue")
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::Gray)),
            chunks[1],
        );
    }
}
