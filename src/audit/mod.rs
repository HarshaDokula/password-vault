use chrono::Utc;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use uuid::Uuid;

use crate::crypto;
use crate::models::EventType;

/// Append-only, hash-chained integrity audit log.
pub struct IntegrityLog {
    path: String,
}

impl IntegrityLog {
    /// Open or create an audit.log file.
    pub fn open(path: &str) -> Result<Self, String> {
        let p = Path::new(path);
        if !p.exists() {
            File::create(p).map_err(|e| format!("Cannot create audit log: {}", e))?;
        }
        Ok(IntegrityLog {
            path: path.to_string(),
        })
    }

    /// Append an entry to the audit log.
    /// Returns the entry hash.
    pub fn append(
        &self,
        event_type: EventType,
        session_id: &str,
        account_id: Option<&str>,
        metadata: Option<&str>,
    ) -> Result<String, String> {
        let prev_hash = self.get_last_hash()?;
        let timestamp = Utc::now().to_rfc3339();
        let id = Uuid::new_v4().to_string();

        // Build the entry content for hashing
        let entry_content = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            id,
            timestamp,
            session_id,
            event_type.as_str(),
            account_id.unwrap_or(""),
            metadata.unwrap_or(""),
            prev_hash
        );

        let entry_hash = crypto::sha256_hex(entry_content.as_bytes());

        // Write line to audit.log: id|timestamp|session_id|event_type|account_id|metadata|prev_hash|entry_hash
        let line = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}\n",
            id,
            timestamp,
            session_id,
            event_type.as_str(),
            account_id.unwrap_or(""),
            metadata.unwrap_or(""),
            prev_hash,
            entry_hash
        );

        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("Cannot open audit log for append: {}", e))?;

        file.write_all(line.as_bytes())
            .map_err(|e| format!("Cannot write to audit log: {}", e))?;

        file.flush()
            .map_err(|e| format!("Cannot flush audit log: {}", e))?;

        Ok(entry_hash)
    }

    /// Get the hash of the last entry in the chain.
    fn get_last_hash(&self) -> Result<String, String> {
        let path = Path::new(&self.path);
        if !path.exists() {
            return Ok(String::new());
        }

        let file = File::open(path).map_err(|e| format!("Cannot open audit log: {}", e))?;
        let reader = BufReader::new(file);

        let mut last_hash = String::new();
        for line in reader.lines() {
            let line = line.map_err(|e| format!("Cannot read audit log: {}", e))?;
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 8 {
                last_hash = parts[7].to_string();
            }
        }
        Ok(last_hash)
    }

    /// Verify the integrity of the entire hash chain.
    /// Returns Ok if valid, Err with details if tampered.
    pub fn verify(&self) -> Result<(), String> {
        let path = Path::new(&self.path);
        if !path.exists() {
            return Ok(());
        }

        let file = File::open(path).map_err(|e| format!("Cannot open audit log: {}", e))?;
        let reader = BufReader::new(file);

        let mut expected_prev_hash = String::new();
        let mut line_num = 0;

        for line in reader.lines() {
            line_num += 1;
            let line = line.map_err(|e| format!("Cannot read line {}: {}", line_num, e))?;
            let parts: Vec<&str> = line.split('|').collect();

            if parts.len() != 8 {
                return Err(format!(
                    "Line {} has {} fields, expected 8",
                    line_num,
                    parts.len()
                ));
            }

            let id = parts[0];
            let timestamp = parts[1];
            let session_id = parts[2];
            let event_type = parts[3];
            let account_id = parts[4];
            let metadata = parts[5];
            let prev_hash = parts[6];
            let entry_hash = parts[7];

            // Verify prev_hash matches chain
            if prev_hash != expected_prev_hash {
                return Err(format!(
                    "Chain broken at line {}: expected prev_hash {}, got {}",
                    line_num, expected_prev_hash, prev_hash
                ));
            }

            // Recompute entry hash
            let entry_content = format!(
                "{}|{}|{}|{}|{}|{}|{}",
                id, timestamp, session_id, event_type, account_id, metadata, prev_hash
            );
            let computed_hash = crypto::sha256_hex(entry_content.as_bytes());

            if computed_hash != entry_hash {
                return Err(format!(
                    "Hash mismatch at line {}: expected {}, got {}",
                    line_num, computed_hash, entry_hash
                ));
            }

            expected_prev_hash = entry_hash.to_string();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_audit_log_append_and_verify() {
        let tmp = "/tmp/test_audit.log";
        let _ = fs::remove_file(tmp);

        let log = IntegrityLog::open(tmp).unwrap();

        let session_id = "test-session-1";

        log.append(EventType::VaultInit, session_id, None, None)
            .unwrap();
        log.append(EventType::AppStart, session_id, None, None)
            .unwrap();

        assert!(log.verify().is_ok());

        let _ = fs::remove_file(tmp);
    }

    #[test]
    fn test_audit_log_tamper_detection() {
        let tmp = "/tmp/test_audit_tamper.log";
        let _ = fs::remove_file(tmp);

        let log = IntegrityLog::open(tmp).unwrap();
        let session_id = "test-session-2";

        log.append(EventType::VaultInit, session_id, None, None)
            .unwrap();
        log.append(
            EventType::AccountCreate,
            session_id,
            Some("acc1"),
            Some("{}"),
        )
        .unwrap();

        // Tamper: modify the file
        let content = fs::read_to_string(tmp).unwrap();
        let tampered = content.replace("account_create", "account_update");
        fs::write(tmp, tampered).unwrap();

        let log2 = IntegrityLog::open(tmp).unwrap();
        assert!(log2.verify().is_err());

        let _ = fs::remove_file(tmp);
    }
}
