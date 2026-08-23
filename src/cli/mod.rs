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
        "uninstall" => {
            let (delete_data, assume_yes) = parse_uninstall_flags(&args[2..])?;
            let binary_path = std::env::current_exe()
                .map_err(|e| format!("Could not determine vault binary path: {}", e))?;
            cmd_uninstall(delete_data, assume_yes, &vault_dir, &binary_path)?;
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
    println!("  vault uninstall    Remove the vault binary (keeps your passwords)");
    println!("      --delete-data, -d  Also delete all stored passwords");
    println!("      --yes, -y          Skip the confirmation prompt");
}

/// Parse uninstall flags. Returns (delete_data, assume_yes).
fn parse_uninstall_flags(args: &[String]) -> Result<(bool, bool), String> {
    let mut delete_data = false;
    let mut assume_yes = false;
    for arg in args {
        match arg.as_str() {
            "--delete-data" | "-d" => delete_data = true,
            "--yes" | "-y" => assume_yes = true,
            "--help" | "-h" => {
                print_cli_usage();
                return Err("No action taken.".to_string());
            }
            _ => {
                return Err(format!(
                    "Unknown uninstall flag: {} (use --delete-data/-d and/or --yes/-y)",
                    arg
                ));
            }
        }
    }
    Ok((delete_data, assume_yes))
}

/// Uninstall vault: remove the binary, and optionally the vault data (passwords).
fn cmd_uninstall(
    delete_data: bool,
    assume_yes: bool,
    vault_dir: &str,
    binary_path: &Path,
) -> Result<(), String> {
    println!("=== Vault Uninstall ===");
    let data_dir = Path::new(vault_dir);

    // For destructive uninstalls, confirm BEFORE removing anything.
    if delete_data && !assume_yes {
        print!(
            "WARNING: This will PERMANENTLY delete all stored passwords in {}.\nContinue? [y/N] ",
            data_dir.display()
        );
        io::stdout()
            .flush()
            .map_err(|e| format!("IO error: {}", e))?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .map_err(|e| format!("IO error: {}", e))?;
        if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("Aborted — nothing was removed.");
            return Ok(());
        }
    }

    // Remove the binary. On Unix, deleting a running executable works fine;
    // a root-owned install (e.g. /usr/local/bin) needs sudo.
    match std::fs::remove_file(binary_path) {
        Ok(()) => println!("[OK] Removed binary: {}", binary_path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            println!("[WARN] Cannot remove {}: {}", binary_path.display(), e);
            #[cfg(target_os = "windows")]
            println!("       Close vault, then delete: {}", binary_path.display());
            #[cfg(not(target_os = "windows"))]
            println!(
                "       Finish removal with: sudo rm {}",
                binary_path.display()
            );
        }
        Err(e) => println!("[WARN] Could not remove {}: {}", binary_path.display(), e),
    }

    // Remove vault data (passwords) if requested.
    if delete_data {
        if data_dir.exists() {
            std::fs::remove_dir_all(data_dir).map_err(|e| {
                format!("Failed to remove vault data {}: {}", data_dir.display(), e)
            })?;
            println!("[OK] Deleted vault data: {}", data_dir.display());
        } else {
            println!("[SKIP] No vault data found at {}", data_dir.display());
        }
    } else {
        println!("[KEEP] Vault data retained at {}", data_dir.display());
        println!(
            "       Run 'vault uninstall --delete-data' to also delete your stored passwords."
        );
    }

    println!();
    println!("Uninstall finished.");
    Ok(())
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
    let audit_path = Path::new(vault_dir).join("audit.log");

    loop {
        print!("Enter master password: ");
        io::stdout()
            .flush()
            .map_err(|e| format!("IO error: {}", e))?;

        let mut password = String::new();
        stdin
            .read_line(&mut password)
            .map_err(|e| format!("IO error: {}", e))?;
        let password = password.trim().to_string();

        if password.is_empty() {
            continue;
        }

        let il = IntegrityLog::open(&audit_path.to_string_lossy()).ok();
        match auth::authenticate(conn, &password, &salt, rate_limiter, "cli", il.as_ref())? {
            auth::AuthResult::VaultCreated { master_key } => {
                println!("New vault created!");
                let session_id = Uuid::new_v4().to_string();

                // Log init event
                let il = IntegrityLog::open(&audit_path.to_string_lossy())?;
                il.append(crate::models::EventType::VaultInit, &session_id, None, None)?;

                return Ok((master_key, session_id));
            }
            auth::AuthResult::Unlocked { master_key } => {
                println!("Vault unlocked!");
                let session_id = Uuid::new_v4().to_string();
                return Ok((master_key, session_id));
            }
            auth::AuthResult::Failed(msg) => {
                eprintln!("{}", msg);
                // Log unlock failure
                if let Ok(il) = IntegrityLog::open(&audit_path.to_string_lossy()) {
                    let remaining = rate_limiter.remaining_attempts("cli");
                    let _ = il.append(
                        crate::models::EventType::UnlockFailure,
                        "pre-auth",
                        None,
                        Some(&serde_json::json!({"remaining_attempts": remaining}).to_string()),
                    );
                }
                // If rate-limited, the message already says so — exit the loop
                if msg.contains("Rate limited") {
                    return Err(msg);
                }
            }
        }
    }
}

fn cmd_export(
    vault_dir: &str,
    db_path: &Path,
    audit_path: &Path,
    output: &str,
) -> Result<(), String> {
    let conn = db::open(&db_path.to_string_lossy())?;
    let mut rate_limiter = RateLimiter::new(5);

    let (master_key, session_id) = unlock_interactive(&conn, &mut rate_limiter, vault_dir)?;

    let integrity_log = IntegrityLog::open(&audit_path.to_string_lossy())?;
    let config = AppConfig::default();
    let vault = Vault::new(conn, integrity_log, master_key, session_id, config);

    vault.log_backup_export()?;
    storage::export_vault(&vault, &audit_path.to_string_lossy(), output)?;
    println!("Vault exported to {}", output);

    Ok(())
}

fn cmd_import(
    vault_dir: &str,
    db_path: &Path,
    audit_path: &Path,
    input: &str,
) -> Result<(), String> {
    let conn = db::open(&db_path.to_string_lossy())?;
    let mut rate_limiter = RateLimiter::new(5);

    let (master_key, session_id) = unlock_interactive(&conn, &mut rate_limiter, vault_dir)?;

    let integrity_log = IntegrityLog::open(&audit_path.to_string_lossy())?;
    let config = AppConfig::default();
    let vault = Vault::new(conn, integrity_log, master_key, session_id, config);

    let count = storage::import_vault(&vault, &audit_path.to_string_lossy(), input)?;
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

    config::save_default_config_if_missing(vault_dir)?;
    println!("Vault initialized at {}", vault_dir);
    println!("Run 'vault' to create your master password and start adding accounts.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_uninstall_flags_default_keeps_data() {
        let (delete_data, assume_yes) = parse_uninstall_flags(&flags(&[])).unwrap();
        assert!(!delete_data);
        assert!(!assume_yes);
    }

    #[test]
    fn parse_uninstall_flags_delete_data_forms() {
        let (delete_data, _) = parse_uninstall_flags(&flags(&["--delete-data"])).unwrap();
        assert!(delete_data);
        let (delete_data, _) = parse_uninstall_flags(&flags(&["-d"])).unwrap();
        assert!(delete_data);
    }

    #[test]
    fn parse_uninstall_flags_yes_forms() {
        let (delete_data, assume_yes) = parse_uninstall_flags(&flags(&["-d", "--yes"])).unwrap();
        assert!(delete_data);
        assert!(assume_yes);
        let (_, assume_yes) = parse_uninstall_flags(&flags(&["-y"])).unwrap();
        assert!(assume_yes);
    }

    #[test]
    fn parse_uninstall_flags_rejects_unknown() {
        assert!(parse_uninstall_flags(&flags(&["--purge"])).is_err());
    }

    fn temp_uninstall_env() -> (std::path::PathBuf, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!("vault-uninstall-test-{}", Uuid::new_v4()));
        let data = base.join("data");
        let binary = base.join("vault");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(&binary, b"fake vault binary").unwrap();
        std::fs::write(data.join("vault.db"), b"fake db").unwrap();
        (data, binary)
    }

    #[test]
    fn uninstall_without_delete_data_keeps_passwords() {
        let (data, binary) = temp_uninstall_env();
        cmd_uninstall(false, true, &data.to_string_lossy(), &binary).unwrap();
        assert!(!binary.exists(), "binary should be removed");
        assert!(data.join("vault.db").exists(), "passwords should be kept");
        std::fs::remove_dir_all(data.parent().unwrap()).ok();
    }

    #[test]
    fn uninstall_with_delete_data_removes_passwords() {
        let (data, binary) = temp_uninstall_env();
        cmd_uninstall(true, true, &data.to_string_lossy(), &binary).unwrap();
        assert!(!binary.exists(), "binary should be removed");
        assert!(!data.exists(), "passwords should be deleted");
        std::fs::remove_dir_all(data.parent().unwrap()).ok();
    }

    #[test]
    fn uninstall_delete_data_missing_dir_is_ok() {
        let (data, binary) = temp_uninstall_env();
        std::fs::remove_dir_all(&data).unwrap();
        cmd_uninstall(true, true, &data.to_string_lossy(), &binary).unwrap();
        assert!(!binary.exists());
        std::fs::remove_dir_all(data.parent().unwrap()).ok();
    }
}
