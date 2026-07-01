use crate::audit::IntegrityLog;
use crate::crypto;
use crate::db;
use crate::models::EventType;
use crate::utils::RateLimiter;
use rusqlite::Connection;

/// Authentication result for the vault.
pub enum AuthResult {
    /// Vault created (first launch).
    VaultCreated { master_key: [u8; 32] },
    /// Vault unlocked successfully.
    Unlocked { master_key: [u8; 32] },
    /// Authentication failed.
    Failed(String),
}

/// Handle the authentication flow.
///
/// For a new vault: creates validation token, stores it.
/// For an existing vault: validates the master password.
/// If `integrity_log` is provided, rate-limit triggers are logged.
pub fn authenticate(
    conn: &Connection,
    password: &str,
    salt: &[u8],
    rate_limiter: &mut RateLimiter,
    session_type: &str,
    integrity_log: Option<&IntegrityLog>,
) -> Result<AuthResult, String> {
    // Reject empty passwords
    if password.is_empty() {
        return Ok(AuthResult::Failed("Password cannot be empty.".to_string()));
    }

    // Check rate limiting
    let remaining = rate_limiter.remaining_attempts(session_type);
    if remaining == 0 {
        if let Some(il) = integrity_log {
            let _ = il.append(
                EventType::RateLimitTriggered,
                "pre-auth",
                None,
                Some(&serde_json::json!({"remaining_attempts": 0}).to_string()),
            );
        }
        return Ok(AuthResult::Failed("Rate limited. Please wait.".to_string()));
    }

    // Check if vault exists (has validation token) before deriving key
    let token = db::get_validation_token(conn)?;

    // Derive key (only once) — no redundant re-derivation after auth
    let master_key = crypto::derive_key(password, salt)?;

    match token {
        Some(encrypted_token) => {
            // Existing vault: validate
            match crypto::verify_validation_token(&master_key, &encrypted_token) {
                Ok(()) => {
                    rate_limiter.reset(session_type);
                    Ok(AuthResult::Unlocked { master_key })
                }
                Err(_) => {
                    let remaining = rate_limiter.record_attempt(session_type);
                    Ok(AuthResult::Failed(format!(
                        "Invalid master password. {} attempts remaining.",
                        remaining
                    )))
                }
            }
        }
        None => {
            // New vault: create validation token
            let token = crypto::create_validation_token(&master_key)?;
            db::set_validation_token(conn, &token)?;
            rate_limiter.reset(session_type);
            Ok(AuthResult::VaultCreated { master_key })
        }
    }
}

/// Derive the master key from the password. This is used after auth succeeds.
pub fn derive_master_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    crypto::derive_key(password, salt)
}

/// The salt used for key derivation. Stored in vault metadata.
pub fn get_or_create_salt(conn: &Connection) -> Result<Vec<u8>, String> {
    // Try to load existing
    let mut stmt = conn
        .prepare("SELECT value FROM vault_metadata WHERE key = 'kdf_salt'")
        .map_err(|e| format!("Cannot prepare: {}", e))?;

    let result = stmt.query_row([], |row| row.get::<_, Vec<u8>>(0));

    match result {
        Ok(salt) => Ok(salt),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            // Create new salt
            let salt = crypto::generate_salt().to_vec();
            conn.execute(
                "INSERT OR REPLACE INTO vault_metadata (key, value) VALUES ('kdf_salt', ?1)",
                rusqlite::params![salt],
            )
            .map_err(|e| format!("Cannot store salt: {}", e))?;
            Ok(salt)
        }
        Err(e) => Err(format!("Cannot get salt: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_test_db() -> (Connection, String) {
        let path = format!("/tmp/test_auth_vault_{}.db", uuid::Uuid::new_v4());
        let _ = fs::remove_file(&path);
        (db::open(&path).unwrap(), path)
    }

    #[test]
    fn test_first_launch_flow() {
        let (conn, _) = setup_test_db();
        let mut rate_limiter = RateLimiter::new(5);
        let salt = crypto::generate_salt().to_vec();

        // First call: vault doesn't exist yet
        let result = authenticate(&conn, "mypassword", &salt, &mut rate_limiter, "test", None);
        match result {
            Ok(AuthResult::Unlocked { .. }) | Ok(AuthResult::VaultCreated { .. }) => {}
            _ => panic!("Expected VaultCreated or Unlocked"),
        }
    }

    #[test]
    fn test_valid_and_invalid_password() {
        let (conn, _) = setup_test_db();
        let mut rate_limiter = RateLimiter::new(5);
        let salt = crypto::generate_salt().to_vec();

        // Create vault
        let _ = authenticate(&conn, "correct", &salt, &mut rate_limiter, "test", None);

        // Wrong password
        let result = authenticate(&conn, "wrong", &salt, &mut rate_limiter, "test", None);
        match result {
            Ok(AuthResult::Failed(_)) => {}
            _ => panic!("Expected Failed"),
        }

        // Correct password
        let result = authenticate(&conn, "correct", &salt, &mut rate_limiter, "test", None);
        match result {
            Ok(AuthResult::Unlocked { .. }) => {}
            _ => panic!("Expected Unlocked"),
        }
    }

    #[test]
    fn test_rate_limit_logging() {
        let (conn, db_path) = setup_test_db();
        let _ = fs::remove_file(&db_path);

        let salt = crypto::generate_salt().to_vec();
        let audit_path = "/tmp/test_auth_rate_limit_audit.log";
        let _ = fs::remove_file(audit_path);
        let il = IntegrityLog::open(audit_path).unwrap();

        // Create vault
        let _ = authenticate(
            &conn,
            "correct",
            &salt,
            &mut RateLimiter::new(5),
            "test",
            Some(&il),
        );

        // Exhaust rate limiter
        let mut rate_limiter = RateLimiter::new(1);
        let _ = authenticate(&conn, "wrong", &salt, &mut rate_limiter, "test", Some(&il));

        // Next attempt should be rate limited and logged
        let result = authenticate(&conn, "wrong", &salt, &mut rate_limiter, "test", Some(&il));
        match result {
            Ok(AuthResult::Failed(msg)) => assert!(msg.contains("Rate limited")),
            _ => panic!("Expected rate-limited Failed"),
        }

        // Verify the log entry was written
        let content = std::fs::read_to_string(audit_path).unwrap();
        assert!(
            content.contains("rate_limit_triggered"),
            "Expected rate_limit_triggered in audit log"
        );

        let _ = fs::remove_file(audit_path);
    }
}
