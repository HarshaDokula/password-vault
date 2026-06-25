# TUI Password Manager — Technical Design Document

## Project Overview

This project is a **local-first, terminal-based password manager** written in Rust.
The application is designed to be:

* lightweight
* secure
* cross-platform
* production-grade
* minimally dependent on external tooling
* highly auditable
* modular for future extensibility

The initial target platform is **macOS**, with architecture designed to support Linux and Windows in future versions.

The application focuses on:

* secure password storage
* tamper-evident audit logging
* low-complexity TUI interaction
* modern cryptography
* local-only operation

---

# 1. Goals

## Primary Goals

* Securely store credentials locally
* Provide a lightweight TUI interface
* Use modern cryptographic standards
* Maintain append-only tamper-evident audit chain persisted independently from operational event storage
* Keep dependencies minimal
* Support password history tracking
* Support clipboard integration
* Support search functionality
* Maintain production-level reliability

---

# 2. Non-Goals

The following are intentionally out of scope for v1:

* Cloud sync
* Multi-device synchronization
* Browser integration
* Browser autofill
* Mobile support
* Shared/team vaults
* Biometric unlock
* Forensic-grade anti-tampering
* Network communication
* Web UI
* Full-text encrypted search
* Multi-profile vaults

---

# 3. Core Requirements

## Functional Requirements

The application must support:

### Credential Operations

* Add credentials
* View credentials
* Update credentials
* Soft delete credentials
* Search credentials by service name

### Password History

* Retain the current password and the previous 3 historical passwords

### Audit Logging

* Append-only tamper-evident audit chain persisted independently from operational event storage
* Hash-chain tamper detection
* Event recording for all meaningful application actions

### Authentication

* Master password protection
* Configurable rate limiting

### Security Features

* Clipboard auto-clear
* Auto-lock on inactivity
* Encrypted credential storage

### Backup

* Manual export/import support

### Integrity

* Explicit integrity verification command

---

# 4. Technology Stack

## Programming Language

### Rust

Reasoning:

* memory safety
* strong ecosystem
* cross-platform support
* low runtime overhead
* production-grade concurrency
* excellent cryptography support

---

# 5. Dependency Stack

## TUI

### ratatui

Minimal terminal UI rendering.

[ratatui](https://github.com/ratatui/ratatui?utm_source=chatgpt.com)

### crossterm

Cross-platform terminal handling.

[crossterm](https://github.com/crossterm-rs/crossterm?utm_source=chatgpt.com)

---

## Cryptography

### argon2

Used for password-based key derivation.

[argon2 crate](https://docs.rs/argon2/latest/argon2/?utm_source=chatgpt.com)

### chacha20poly1305

Used for authenticated encryption.

[chacha20poly1305 crate](https://docs.rs/chacha20poly1305/latest/chacha20poly1305/?utm_source=chatgpt.com)

### zeroize

Used to securely clear sensitive memory.

[zeroize crate](https://docs.rs/zeroize/latest/zeroize/?utm_source=chatgpt.com)

---

## Database

### rusqlite

SQLite database driver.

[rusqlite](https://github.com/rusqlite/rusqlite?utm_source=chatgpt.com)

---

## Filesystem Paths

### directories

Platform-specific application directories.

[directories crate](https://docs.rs/directories/latest/directories/?utm_source=chatgpt.com)

---

# 6. Architecture Overview

The application will follow a layered modular architecture.

```text
+-----------------------+
|        TUI            |
+-----------------------+
|        CLI            |
+-----------------------+
|      Services         |
+-----------------------+
| Crypto | Audit | DB   |
+-----------------------+
|       SQLite          |
+-----------------------+
```

---

## Storage Architecture

Three separate storage concepts:

| Concept             | Purpose                  | Backend           |
| ------------------- | ------------------------ | ----------------- |
| Operational storage | CRUD, querying, search   | SQLite            |
| Integrity storage   | Audit chain, forensics   | Append-only file  |
| Backup archive      | Export/import            | Encrypted tar     |

---

# 7. Project Structure

```text
src/
├── audit/
├── auth/
├── cli/
├── config/
├── crypto/
├── db/
├── models/
├── services/
├── storage/
├── tui/
├── utils/
└── main.rs
```

---

# 8. Data Model

## Accounts Table

```sql
CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    service_name TEXT NOT NULL,
    username BLOB NOT NULL,
    password BLOB NOT NULL,
    notes BLOB,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT
);
```

---

## Password History Table

```sql
CREATE TABLE password_history (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    password BLOB NOT NULL,
    changed_at TEXT NOT NULL
);
```

Retention policy:

* retain the current password and the previous 3 historical passwords

---

## Audit Log Table (Operational Store)

```sql
CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    session_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    account_id TEXT,
    metadata TEXT,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
```

This table is used for querying, filtering, searching, analytics, and debugging. It is mutable internally (optimized for application use) and is NOT the canonical integrity source.

---

## Vault Metadata Table

```sql
CREATE TABLE vault_metadata (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
```

Used to store the encrypted validation token (encrypted magic value) for master password verification on existing vaults.

---

# 9. Encryption Model

## Key Derivation

The master password is never stored directly.

### Algorithm

* Argon2id

### Output

* 256-bit encryption key

---

## Encryption Algorithm

### Algorithm

* XChaCha20-Poly1305

Used for:

* username encryption
* password encryption
* notes encryption

---

## Encryption Scope

| Field        | Encryption |
| ------------ | ---------- |
| service_name | No         |
| username     | Yes        |
| password     | Yes        |
| notes        | Yes        |

---

# 10. Authentication

## Master Password

The application requires a master password on startup.

The password:

* derives encryption keys
* unlocks the vault
* is never stored

---

## Authentication Flow — Case A: First Launch

```text
No vault exists
    ↓
Create new vault
    ↓
Prompt for master password
    ↓
Confirm password
    ↓
Generate salt
    ↓
Derive master key (Argon2id)
    ↓
Create vault.db
    ↓
Store encrypted validation token in vault_metadata
    ↓
Create audit.log
    ↓
Write initialization event
    ↓
Enter unlocked session
```

## Authentication Flow — Case B: Existing Vault

```text
Vault exists
    ↓
Prompt for master password
    ↓
Derive key (Argon2id)
    ↓
Validate: attempt to decrypt vault_metadata token
    ↓
If decryption succeeds → password valid, unlock vault
    ↓
If decryption fails → reject, log unlock_failure
```

## Vault Validation Mechanism

An encrypted validation token (encrypted magic value) is stored in the `vault_metadata` table. Successful decryption of this token confirms the master password is correct. This avoids storing password hashes separately.

---

## Session Model

A session begins after successful unlock.

```text
app_start
    ↓
unlock_success
    ↓
generate session_id (UUID)
    ↓
session active
    ↓
lock/exit
    ↓
session terminated
```

Events consumed during the session:
* session_id is written to every audit log event
* No separate session timeout beyond inactivity auto-lock

---

# 11. Rate Limiting

Authentication attempts are rate limited.

## Default Policy

```toml
max_attempts_per_minute = 5
```

Configurable through:

* configuration file
* future TUI settings menu

---

## Persistence

Rate limiting counters are **in-memory only**.

Reset conditions:
* process restart
* successful unlock
* timeout expiration

Reasoning: persistent rate limits complicate implementation, create lockout persistence, and are unnecessary for local-first scope.

## Audit Behavior

All rate-limit triggers are still logged as `rate_limit_triggered` events even though counters are in-memory.

---

# 12. TUI Design

## UI Philosophy

The interface should remain:

* minimal
* keyboard-driven
* lightweight
* readable
* low dependency

---

## Example Main Screen

```text
+----------------------------------+
| Search: git                      |
+----------------------------------+
| github                           |
| gitlab                           |
+----------------------------------+

[a] add
[e] edit
[d] delete
[s] show
[c] copy
[q] quit
```

---

## Search Interaction Model

Search is a **persistent inline filter mode**.

* `/` focuses the search bar
* `Esc` clears search and exits search mode
* Typing dynamically filters visible accounts

---

## Lock Screen

When the vault is locked (either on startup or after auto-lock), a lock screen overlay is shown:

```text
+----------------------------------+
|   Vault Locked                   |
|   Enter Master Password:         |
|   [________________________]     |
+----------------------------------+
```

The application process remains alive during the lock screen.

---

# 13. Search Functionality

## Supported Search

### Initial Implementation

* case-insensitive substring matching
* service name only

Example:

```text
git
```

matches:

* github
* gitlab

---

## Soft-Deleted Accounts

**Default behavior**: soft-deleted accounts are excluded from search results.

Future optional toggle:

```text
[d] show deleted
```

---

# 14. Password Reveal Behavior

## Show Password

Behavior:

* reveal temporarily
* auto-hide after timeout

Default timeout:

```toml
show_password_seconds = 10
```

---

## Clipboard Copy

Behavior:

* copy password to clipboard
* clear clipboard automatically

Default timeout:

```toml
clipboard_clear_seconds = 20
```

---

## password_show Audit Event

Logged once per account reveal event. Two separate events are logged if the user reveals github and gmail.

Metadata example:

```json
{
  "reveal_duration_seconds": 10
}
```

---

# 15. Password History

The application stores:

* current password
* previous 3 passwords

Total: 4 password states maximum.

| Type             | Count |
| ---------------- | ----- |
| current password | 1     |
| history entries  | 3     |

History entries are encrypted.

When updating:

1. existing password moves to history
2. oldest history entry removed if count exceeds 3 history entries

---

## Update Semantics

Password history updates **ONLY** when the password changes.

Changing any of the following does NOT create history entries:

* username
* notes
* any other metadata

---

# 16. Deletion Policy

## Soft Delete

Accounts are never immediately removed.

Deletion process:

1. user selects delete
2. confirmation required
3. record marked with `deleted_at`

---

## Confirmation Flow

```text
Delete github?
Type DELETE to confirm:
```

Confirmation string is an **exact match, case-sensitive**. Required input is `DELETE` in uppercase. Intentional friction is desirable for destructive actions.

---

# 17. Audit Logging

## Logging Philosophy

Every meaningful event within the application is recorded.

---

## Dual Storage Design

### SQLite `audit_log` Table (Operational Store)

Purpose:
* querying
* filtering
* searching
* analytics
* debugging

Characteristics:
* mutable internally
* optimized for application use
* NOT the canonical integrity source

### `audit.log` Append-Only File (Integrity Store)

Purpose:
* integrity verification
* tamper evidence
* forensic audit trail

Characteristics:
* append-only
* hash chained
* canonical integrity source

### Why both are necessary

SQLite alone is insufficient because:
* rows can theoretically be modified
* VACUUM/rewrite operations exist
* corruption recovery may reorder pages

The append-only file provides:
* deterministic ordering
* immutable append semantics
* cryptographic tamper detection

---

## Logged Events

### Session Events

* app_start
* unlock_success
* unlock_failure
* auto_lock
* manual_lock
* app_exit

### Vault Events

* account_create
* account_update
* account_soft_delete
* password_show
* password_copy

### Security Events

* integrity_check_failure
* corrupted_log_detected
* rate_limit_triggered

### System Events

* backup_export
* config_change

---

## Event Metadata Schema

Structured JSON per event type.

### account_create

```json
{
  "service_name": "github",
  "fields_present": ["username", "notes"]
}
```

### password_show

```json
{
  "reveal_duration_seconds": 10
}
```

### unlock_failure

```json
{
  "remaining_attempts": 2
}
```

### Rule

Metadata must NEVER contain:
* plaintext passwords
* decrypted usernames
* notes contents

---

# 18. Tamper-Evident Logging

The log system is:

* append-only
* hash chained

Each entry includes:

* previous entry hash
* current entry hash

---

## Hash Chain Example

```text
Entry 1 → Hash A
Entry 2 → Hash(Hash A + Entry 2)
Entry 3 → Hash(Hash B + Entry 3)
```

Tampering invalidates the chain.

The hash chain is enforced on the **append-only `audit.log` file** (the canonical integrity source). The SQLite `audit_log` table mirrors the chain but is not authoritative.

---

# 19. Corrupted Log Handling

If corruption is detected:

* display warning
* continue application functionality

No automatic repair occurs.

---

# 20. Clipboard Security

Passwords copied to clipboard:

* automatically expire
* are cleared after timeout

---

## Platform Abstraction

Clipboard functionality uses a **platform abstraction trait (implemented via trait)**.

* **macOS**: fully implemented
* **Unsupported platforms** (Linux, Windows before support): compile successfully, clipboard commands disabled at runtime

### Example behavior on unsupported platform

```text
Clipboard unsupported on this platform.
```

No crash. No compile failure.

---

# 21. Auto-Lock

The vault automatically locks after inactivity.

Default:

```toml
auto_lock_minutes = 15
```

Requires master password re-entry.

---

## Auto-Lock TUI Behavior

```text
Session active
    ↓ inactivity timeout
Auto-lock triggered
    ↓
Screen cleared
    ↓
Lock screen overlay shown
    ↓
Master password prompt displayed
```

The application process remains alive during the lock state.

---

# 22. Backup System

## Manual Export Only

No automatic backup support.

---

## Recommended Backup Flow

```bash
vault export backup.vlt
```

The exported backup:

* remains encrypted
* includes integrity metadata
* is versioned

---

## `.vlt` Archive Format

Structured encrypted archive:

```text
backup.vlt
├── metadata.json
├── vault.db.enc
├── audit.log.enc
└── checksum.sig
```

Packaged as a **tar archive**, then encrypted.

## Backup Metadata

```json
{
  "format_version": 1,
  "created_at": "...",
  "app_version": "...",
  "kdf": "argon2id",
  "cipher": "xchacha20poly1305"
}
```

---

## Export Contents

Exports include:

* active accounts
* soft-deleted accounts
* audit history

Reasoning: backups should represent full vault state. Soft-deleted records remain part of auditability, historical recovery, and integrity guarantees.

---

# 23. SQLite Configuration

SQLite will operate in:

* WAL mode

Benefits:

* crash safety
* transactional reliability
* reduced corruption risk

---

# 24. Security Practices

## Memory Safety

Use:

* zeroize crate
* minimal plaintext retention
* limited secret cloning

---

## Master Key Lifetime in Memory

For v1: the derived encryption key remains **resident in memory for the entire session**. It is **zeroized on lock or exit**.

Reasoning:
* simpler architecture
* better UX
* acceptable within the documented threat model

Re-deriving constantly would:
* increase complexity
* increase password handling frequency
* worsen UX

---

## Secure Defaults

* encrypted storage
* auto-lock enabled
* clipboard expiration enabled
* append-only logging enabled

---

# 25. Threat Model

## In Scope

* casual device theft
* offline vault theft
* local malware resistance
* targeted attackers
* unauthorized local access

---

## Out of Scope

* kernel-level compromise
* nation-state adversaries
* hardware implants
* forensic memory extraction
* evil maid attacks

---

# 26. Future Expansion

The architecture should support future additions:

## Planned Possibilities

* hardware token support
* YubiKey integration
* TouchID integration
* Linux support
* Windows support
* encrypted full-text search
* TOTP support
* multiple vaults

---

# 27. Recommended Development Phases

## Phase 1

Core vault:

* database
* encryption
* authentication (including first-run flow)
* CRUD operations
* vault initialization

---

## Phase 2

Audit logging:

* dual storage (SQLite + append-only file)
* hash chain verification

---

## Phase 3

TUI implementation:

* navigation
* search (persistent inline filter with `/` and `Esc`)
* editing
* deletion (with case-sensitive `DELETE` confirmation)

---

## Phase 4

Security UX:

* clipboard handling (platform abstraction trait)
* auto-lock (with lock screen overlay)
* inactivity timers

---

## Phase 5

Backup/export system:

* `.vlt` encrypted tar format
* includes full vault state (active + soft-deleted)

---

## Phase 6

Platform abstraction improvements

---

# 28. Configuration File

## Example

```toml
[security]
max_attempts_per_minute = 5
auto_lock_minutes = 15

[clipboard]
clear_after_seconds = 20

[ui]
show_password_seconds = 10

[logging]
enable_audit_logs = true
```

---

# 29. File Locations

## macOS

Recommended storage path:

```text
~/Library/Application Support/vault/
```

Files:

```text
vault.db
audit.log
config.toml
```

---

### Notes

* `vault.db` is the SQLite operational store (contains accounts, password history, audit_log table, vault_metadata)
* `audit.log` is the append-only tamper-evident integrity chain file
* The hash chain on `audit.log` is the canonical integrity source

---

# 30. Integrity Verification

## Explicit Verification Command

```bash
vault verify
```

This command should:

* verify the audit hash chain on the append-only `audit.log` file
* verify encrypted blob integrity in the database
* verify database consistency

This is a critical tool for ongoing integrity trust.

---

# 31. Final Design Principles

The project prioritizes:

* security over convenience
* simplicity over feature bloat
* local-first architecture
* auditability
* deterministic behavior
* minimal dependencies
* production-grade reliability

The resulting system should feel:

* fast
* predictable
* secure
* maintainable
* extensible
* lightweight enough for terminal-native workflows.
