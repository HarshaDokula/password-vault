use rusqlite::{Connection, params};
use std::path::Path;

use crate::models::{Account, AccountSummary, PasswordHistoryEntry, AuditEntry};

const SCHEMA_VERSION: i32 = 1;

/// Open (or create) the SQLite operational database.
pub fn open(path: &str) -> Result<Connection, String> {
    let exists = Path::new(path).exists();
    let conn = Connection::open(path)
        .map_err(|e| format!("Cannot open database: {}", e))?;

    // Enable WAL mode
    conn.execute_batch("PRAGMA journal_mode=WAL;")
        .map_err(|e| format!("Cannot set WAL mode: {}", e))?;

    if !exists {
        initialize_schema(&conn)?;
    } else {
        // Verify schema version
        let version: i32 = conn
            .query_row(
                "SELECT value FROM vault_metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        if version != SCHEMA_VERSION {
            return Err(format!(
                "Database schema version mismatch: found {}, expected {}",
                version, SCHEMA_VERSION
            ));
        }
    }

    Ok(conn)
}

fn initialize_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            service_name TEXT NOT NULL,
            username BLOB NOT NULL,
            password BLOB NOT NULL,
            notes BLOB,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            deleted_at TEXT
        );

        CREATE TABLE IF NOT EXISTS password_history (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            password BLOB NOT NULL,
            changed_at TEXT NOT NULL,
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            session_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            account_id TEXT,
            metadata TEXT,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS vault_metadata (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_accounts_service ON accounts(service_name);
        CREATE INDEX IF NOT EXISTS idx_accounts_deleted ON accounts(deleted_at);
        CREATE INDEX IF NOT EXISTS idx_password_history_account ON password_history(account_id);
        CREATE INDEX IF NOT EXISTS idx_audit_log_event ON audit_log(event_type);
        CREATE INDEX IF NOT EXISTS idx_audit_log_session ON audit_log(session_id);
        ",
    )
    .map_err(|e| format!("Cannot initialize schema: {}", e))?;

    // Set schema version
    conn.execute(
        "INSERT OR REPLACE INTO vault_metadata (key, value) VALUES ('schema_version', ?1)",
        params![SCHEMA_VERSION],
    )
    .map_err(|e| format!("Cannot set schema version: {}", e))?;

    Ok(())
}

/// Store encrypted validation token.
pub fn set_validation_token(conn: &Connection, token: &[u8]) -> Result<(), String> {
    conn.execute(
        "INSERT OR REPLACE INTO vault_metadata (key, value) VALUES ('validation_token', ?1)",
        params![token],
    )
    .map_err(|e| format!("Cannot store validation token: {}", e))?;
    Ok(())
}

/// Retrieve encrypted validation token.
pub fn get_validation_token(conn: &Connection) -> Result<Option<Vec<u8>>, String> {
    let mut stmt = conn
        .prepare("SELECT value FROM vault_metadata WHERE key = 'validation_token'")
        .map_err(|e| format!("Cannot prepare statement: {}", e))?;
    
    let result = stmt.query_row([], |row| row.get::<_, Vec<u8>>(0));
    match result {
        Ok(token) => Ok(Some(token)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Cannot get validation token: {}", e)),
    }
}

/// Insert a new account.
pub fn insert_account(conn: &Connection, account: &Account) -> Result<(), String> {
    conn.execute(
        "INSERT INTO accounts (id, service_name, username, password, notes, created_at, updated_at, deleted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            account.id,
            account.service_name,
            account.username,
            account.password,
            account.notes,
            account.created_at,
            account.updated_at,
            account.deleted_at,
        ],
    )
    .map_err(|e| format!("Cannot insert account: {}", e))?;
    Ok(())
}

/// Update an existing account.
pub fn update_account(conn: &Connection, account: &Account) -> Result<(), String> {
    conn.execute(
        "UPDATE accounts SET service_name = ?1, username = ?2, password = ?3, notes = ?4, updated_at = ?5 WHERE id = ?6",
        params![
            account.service_name,
            account.username,
            account.password,
            account.notes,
            account.updated_at,
            account.id,
        ],
    )
    .map_err(|e| format!("Cannot update account: {}", e))?;
    Ok(())
}

/// Soft-delete an account.
pub fn soft_delete_account(conn: &Connection, id: &str, deleted_at: &str) -> Result<(), String> {
    conn.execute(
        "UPDATE accounts SET deleted_at = ?1, updated_at = ?2 WHERE id = ?3",
        params![deleted_at, deleted_at, id],
    )
    .map_err(|e| format!("Cannot soft-delete account: {}", e))?;
    Ok(())
}

/// Get an account by ID (full details, still encrypted).
pub fn get_account(conn: &Connection, id: &str) -> Result<Option<Account>, String> {
    let mut stmt = conn
        .prepare("SELECT id, service_name, username, password, notes, created_at, updated_at, deleted_at FROM accounts WHERE id = ?1")
        .map_err(|e| format!("Cannot prepare statement: {}", e))?;
    
    let result = stmt.query_row(params![id], |row| {
        Ok(Account {
            id: row.get(0)?,
            service_name: row.get(1)?,
            username: row.get(2)?,
            password: row.get(3)?,
            notes: row.get(4)?,
            created_at: row.get(5)?,
            updated_at: row.get(6)?,
            deleted_at: row.get(7)?,
        })
    });

    match result {
        Ok(account) => Ok(Some(account)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Cannot get account: {}", e)),
    }
}

/// Search accounts by service name (case-insensitive substring).
/// Only returns non-deleted accounts by default.
pub fn search_accounts(conn: &Connection, query: &str, include_deleted: bool) -> Result<Vec<AccountSummary>, String> {
    let mut stmt = if include_deleted {
        conn.prepare(
            "SELECT id, service_name, created_at, updated_at, deleted_at FROM accounts WHERE service_name LIKE ?1 COLLATE NOCASE ORDER BY service_name"
        )
        .map_err(|e| format!("Cannot prepare statement: {}", e))?
    } else {
        conn.prepare(
            "SELECT id, service_name, created_at, updated_at, deleted_at FROM accounts WHERE service_name LIKE ?1 COLLATE NOCASE AND deleted_at IS NULL ORDER BY service_name"
        )
        .map_err(|e| format!("Cannot prepare statement: {}", e))?
    };

    let pattern = format!("%{}%", query);
    let rows = stmt.query_map(params![pattern], |row| {
        Ok(AccountSummary {
            id: row.get(0)?,
            service_name: row.get(1)?,
            created_at: row.get(2)?,
            updated_at: row.get(3)?,
            deleted_at: row.get(4)?,
        })
    })
    .map_err(|e| format!("Cannot search accounts: {}", e))?;

    let mut accounts = Vec::new();
    for row in rows {
        accounts.push(row.map_err(|e| format!("Row error: {}", e))?);
    }
    Ok(accounts)
}

/// Get all accounts (for export).
pub fn get_all_accounts(conn: &Connection) -> Result<Vec<Account>, String> {
    let mut stmt = conn
        .prepare("SELECT id, service_name, username, password, notes, created_at, updated_at, deleted_at FROM accounts ORDER BY service_name")
        .map_err(|e| format!("Cannot prepare statement: {}", e))?;
    
    let rows = stmt.query_map([], |row| {
        Ok(Account {
            id: row.get(0)?,
            service_name: row.get(1)?,
            username: row.get(2)?,
            password: row.get(3)?,
            notes: row.get(4)?,
            created_at: row.get(5)?,
            updated_at: row.get(6)?,
            deleted_at: row.get(7)?,
        })
    })
    .map_err(|e| format!("Cannot get all accounts: {}", e))?;

    let mut accounts = Vec::new();
    for row in rows {
        accounts.push(row.map_err(|e| format!("Row error: {}", e))?);
    }
    Ok(accounts)
}

/// Insert a password history entry.
pub fn insert_password_history(conn: &Connection, entry: &PasswordHistoryEntry) -> Result<(), String> {
    conn.execute(
        "INSERT INTO password_history (id, account_id, password, changed_at) VALUES (?1, ?2, ?3, ?4)",
        params![entry.id, entry.account_id, entry.password, entry.changed_at],
    )
    .map_err(|e| format!("Cannot insert password history: {}", e))?;
    Ok(())
}

/// Get password history for an account, ordered by most recent first.
pub fn get_password_history(conn: &Connection, account_id: &str) -> Result<Vec<PasswordHistoryEntry>, String> {
    let mut stmt = conn
        .prepare("SELECT id, account_id, password, changed_at FROM password_history WHERE account_id = ?1 ORDER BY changed_at DESC")
        .map_err(|e| format!("Cannot prepare statement: {}", e))?;
    
    let rows = stmt.query_map(params![account_id], |row| {
        Ok(PasswordHistoryEntry {
            id: row.get(0)?,
            account_id: row.get(1)?,
            password: row.get(2)?,
            changed_at: row.get(3)?,
        })
    })
    .map_err(|e| format!("Cannot get password history: {}", e))?;

    let mut entries = Vec::new();
    for row in rows {
        entries.push(row.map_err(|e| format!("Row error: {}", e))?);
    }
    Ok(entries)
}

/// Prune password history: keep only the most recent 3 entries.
pub fn prune_password_history(conn: &Connection, account_id: &str) -> Result<(), String> {
    // Delete all but the 3 most recent
    conn.execute(
        "DELETE FROM password_history WHERE account_id = ?1 AND id NOT IN (
            SELECT id FROM password_history WHERE account_id = ?1 ORDER BY changed_at DESC LIMIT 3
        )",
        params![account_id],
    )
    .map_err(|e| format!("Cannot prune password history: {}", e))?;
    Ok(())
}

/// Insert an audit log entry into the operational audit_log table.
pub fn insert_audit_entry(conn: &Connection, entry: &AuditEntry) -> Result<(), String> {
    conn.execute(
        "INSERT INTO audit_log (id, timestamp, session_id, event_type, account_id, metadata, prev_hash, entry_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            entry.id,
            entry.timestamp,
            entry.session_id,
            entry.event_type.as_str(),
            entry.account_id,
            entry.metadata,
            entry.prev_hash,
            entry.entry_hash,
        ],
    )
    .map_err(|e| format!("Cannot insert audit entry: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_test_db() -> Connection {
        let path = "/tmp/test_vault.db";
        let _ = fs::remove_file(path);
        open(path).unwrap()
    }

    #[test]
    fn test_insert_and_get_account() {
        let conn = setup_test_db();
        let account = Account {
            id: "1".to_string(),
            service_name: "github".to_string(),
            username: vec![1, 2, 3],
            password: vec![4, 5, 6],
            notes: Some(vec![7, 8, 9]),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
            deleted_at: None,
        };
        
        insert_account(&conn, &account).unwrap();
        
        let fetched = get_account(&conn, "1").unwrap().unwrap();
        assert_eq!(fetched.service_name, "github");
        assert_eq!(fetched.username, vec![1, 2, 3]);
    }

    #[test]
    fn test_search_accounts() {
        let conn = setup_test_db();
        
        let a1 = Account {
            id: "1".to_string(),
            service_name: "GitHub".to_string(),
            username: vec![1],
            password: vec![2],
            notes: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
            deleted_at: None,
        };
        let a2 = Account {
            id: "2".to_string(),
            service_name: "GitLab".to_string(),
            username: vec![3],
            password: vec![4],
            notes: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
            deleted_at: None,
        };
        
        insert_account(&conn, &a1).unwrap();
        insert_account(&conn, &a2).unwrap();
        
        let results = search_accounts(&conn, "git", false).unwrap();
        assert_eq!(results.len(), 2);
        
        let results = search_accounts(&conn, "hub", false).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].service_name, "GitHub");
    }

    #[test]
    fn test_soft_delete() {
        let conn = setup_test_db();
        
        let account = Account {
            id: "1".to_string(),
            service_name: "test".to_string(),
            username: vec![1],
            password: vec![2],
            notes: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
            deleted_at: None,
        };
        insert_account(&conn, &account).unwrap();
        
        soft_delete_account(&conn, "1", "2024-06-01T00:00:00Z").unwrap();
        
        // Should not appear in default search
        let results = search_accounts(&conn, "test", false).unwrap();
        assert_eq!(results.len(), 0);
        
        // Should appear when including deleted
        let results = search_accounts(&conn, "test", true).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].deleted_at.is_some());
    }

    #[test]
    fn test_password_history() {
        let conn = setup_test_db();
        
        // Create an account first (FK constraint)
        let account = Account {
            id: "acc1".to_string(),
            service_name: "test".to_string(),
            username: vec![1],
            password: vec![2],
            notes: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
            deleted_at: None,
        };
        insert_account(&conn, &account).unwrap();
        
        let history = PasswordHistoryEntry {
            id: "h1".to_string(),
            account_id: "acc1".to_string(),
            password: vec![1, 2, 3],
            changed_at: "2024-01-01T00:00:00Z".to_string(),
        };
        insert_password_history(&conn, &history).unwrap();
        
        let entries = get_password_history(&conn, "acc1").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].password, vec![1, 2, 3]);
    }
}
