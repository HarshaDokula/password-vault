use std::fs;
use std::path::Path;

use crate::models::AppConfig;

/// Load configuration from the vault directory.
pub fn load_config(vault_dir: &str) -> AppConfig {
    let config_path = Path::new(vault_dir).join("config.toml");
    
    if config_path.exists() {
        match fs::read_to_string(&config_path) {
            Ok(content) => {
                match toml::from_str(&content) {
                    Ok(config) => return config,
                    Err(_) => {}
                }
            }
            Err(_) => {}
        }
    }
    
    AppConfig::default()
}

/// Save configuration to the vault directory.
pub fn save_config(vault_dir: &str, config: &AppConfig) -> Result<(), String> {
    let config_path = Path::new(vault_dir).join("config.toml");
    let content = toml::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    
    fs::write(&config_path, content)
        .map_err(|e| format!("Failed to write config: {}", e))
}

/// Get the default vault directory for the current platform.
/// Checks VAULT_DIR environment variable first, then falls back to platform dirs.
pub fn get_vault_dir() -> String {
    // Check environment variable first
    if let Ok(dir) = std::env::var("VAULT_DIR") {
        if !dir.is_empty() {
            return dir;
        }
    }
    
    if let Some(proj_dirs) = directories::ProjectDirs::from("com", "vault", "vault") {
        let dir = proj_dirs.data_dir().to_string_lossy().to_string();
        return dir;
    }
    dirs_fallback()
}

/// Get the config directory path.
pub fn get_config_dir() -> String {
    if let Some(proj_dirs) = directories::ProjectDirs::from("com", "vault", "vault") {
        proj_dirs.config_dir().to_string_lossy().to_string()
    } else {
        dirs_fallback()
    }
}

fn dirs_fallback() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    format!("{}/.vault", home)
}

/// Ensure the vault directory exists.
pub fn ensure_vault_dir(vault_dir: &str) -> Result<(), String> {
    fs::create_dir_all(vault_dir)
        .map_err(|e| format!("Cannot create vault directory: {}", e))
}
