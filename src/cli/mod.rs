use std::io::{self, Write};

use std::path::Path;
use uuid::Uuid;

use rusqlite::Connection;

use crate::audit::IntegrityLog;
use crate::auth;
use crate::config;

use crate::db;
use crate::models::AppConfig;
use crate::services::Vault;
use crate::storage;
use crate::utils::RateLimiter;


/// Run the CLI (command-line interface for verification and backup commands).
pub fn run_cli(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        print_cli_usage();
        return Ok(());
    }

    let command = &args[1];
    let vault_dir = config::get_vault_dir();
    let db_path = Path::new(&vault_dir).join("vault.db");
    let audit_path = Path::new(&vault_dir).join("audit.log");

    match command.as_str() {
        "verify" => {
            cmd_verify(&db_path, &audit_path)?;
        }
        "export" => {
            let output = if args.len() > 2 {
                args[2].clone()
            } else {
                return Err("Usage: vault export <output.vlt>".to_string());
            };
            cmd_export(&vault_dir, &db_path, &audit_path, &output)?;
        }
        "import" => {
            let input = if args.len() > 2 {
                args[2].clone()
            } else {
                return Err("Usage: vault import <input.vlt>".to_string());
            };
            cmd_import(&vault_dir, &db_path, &audit_path, &input)?;
        }
        "init" => {
            cmd_init(&vault_dir)?;
        }
        _ => {
            print_cli_usage();
        }
    }

    Ok(())
}

fn print_cli_usage() {
    println!("Vault - Terminal Password Manager");
    println!();
    println!("Usage:");
    println!("  vault              Launch TUI");
    println!("  vault init         Initialize a new vault directory");
    println!("  vault verify       Verify integrity of the vault");
    println!("  vault export <file>  Export vault to encrypted backup");
    println!("  vault import <file>  Import vault from encrypted backup");
}

fn cmd_verify(db_path: &Path, audit_path: &Path) -> Result<(), String> {
    if !db_path.exists() {
        return Err("No vault found. Run 'vault' to create one.".to_string());
    }

    let conn = db::open(&db_path.to_string_lossy())?;
    let integrity_log = IntegrityLog::open(&audit_path.to_string_lossy())?;

    println!("=== Vault Integrity Verification ===");
    println!();

    // Check audit log integrity
    match integrity_log.verify() {
        Ok(()) => println!("[PASS] Audit log hash chain is valid."),
        Err(e) => println!("[FAIL] Audit log: {}", e),
    }

    // Check database integrity
    match conn.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0)) {
        Ok(result) => {
            if result == "ok" {
                println!("[PASS] Database integrity is valid.");
            } else {
                println!("[FAIL] Database: {}", result);
            }
        }
        Err(e) => println!("[FAIL] Database check error: {}", e),
    }

    println!();
    println!("Verification complete.");
    Ok(())
}

fn unlock_interactive(
    conn: &Connection,
    rate_limiter: &mut RateLimiter,
    vault_dir: &str,
) -> Result<([u8; 32], String), String> {
    let salt = auth::get_or_create_salt(conn)?;
    let stdin = io::stdin();

    loop {
        print!("Enter master password: ");
        io::stdout().flush().map_err(|e| format!("IO error: {}", e))?;
        
        let mut password = String::new();
        stdin.read_line(&mut password).map_err(|e| format!("IO error: {}", e))?;
        let password = password.trim().to_string();

        if password.is_empty() {
            continue;
        }

        match auth::authenticate(conn, &password, &salt, rate_limiter, "cli")? {
            auth::AuthResult::VaultCreated => {
                println!("New vault created!");
                let key = auth::derive_master_key(&password, &salt)?;
                let session_id = Uuid::new_v4().to_string();

                // Log init event
                let integrity_log = IntegrityLog::open(
                    &Path::new(vault_dir).join("audit.log").to_string_lossy()
                )?;
                integrity_log.append(
                    crate::models::EventType::VaultInit,
                    &session_id,
                    None,
                    None,
                )?;

                return Ok((key, session_id));
            }
            auth::AuthResult::Unlocked => {
                println!("Vault unlocked!");
                let key = auth::derive_master_key(&password, &salt)?;
                let session_id = Uuid::new_v4().to_string();
                return Ok((key, session_id));
            }
            auth::AuthResult::Failed(msg) => {
                eprintln!("{}", msg);
            }
        }
    }
}

fn cmd_export(vault_dir: &str, db_path: &Path, audit_path: &Path, output: &str) -> Result<(), String> {
    let conn = db::open(&db_path.to_string_lossy())?;
    let mut rate_limiter = RateLimiter::new(5);
    
    let (master_key, session_id) = unlock_interactive(&conn, &mut rate_limiter, vault_dir)?;
    
    let integrity_log = IntegrityLog::open(&audit_path.to_string_lossy())?;
    let config = AppConfig::default();
    let vault = Vault::new(conn, integrity_log, master_key, session_id, config);

    vault.log_backup_export()?;
    storage::export_vault(&vault, output)?;
    println!("Vault exported to {}", output);
    
    Ok(())
}

fn cmd_import(vault_dir: &str, db_path: &Path, audit_path: &Path, input: &str) -> Result<(), String> {
    let conn = db::open(&db_path.to_string_lossy())?;
    let mut rate_limiter = RateLimiter::new(5);
    
    let (master_key, session_id) = unlock_interactive(&conn, &mut rate_limiter, vault_dir)?;
    
    let integrity_log = IntegrityLog::open(&audit_path.to_string_lossy())?;
    let config = AppConfig::default();
    let vault = Vault::new(conn, integrity_log, master_key, session_id, config);

    let count = storage::import_vault(&vault, input)?;
    vault.log_backup_import()?;
    println!("Imported {} account(s) from {}", count, input);
    
    Ok(())
}

fn cmd_init(vault_dir: &str) -> Result<(), String> {
    config::ensure_vault_dir(vault_dir)?;
    let db_path = Path::new(vault_dir).join("vault.db");
    let audit_path = Path::new(vault_dir).join("audit.log");
    
    if db_path.exists() {
        println!("Vault already exists at {}", vault_dir);
        return Ok(());
    }

    let _conn = db::open(&db_path.to_string_lossy())?;
    IntegrityLog::open(&audit_path.to_string_lossy())?;

    config::save_config(vault_dir, &AppConfig::default())?;
    println!("Vault initialized at {}", vault_dir);
    println!("Run 'vault' to create your master password and start adding accounts.");
    
    Ok(())
}
