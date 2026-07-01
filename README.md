# Vault — Terminal Password Manager

A local-first, terminal-based password manager written in Rust. Lightweight, secure, and keyboard-driven.

## Features

- **AES-grade encryption** — XChaCha20-Poly1305 for all secrets (username, password, notes)
- **Argon2id key derivation** — 4 MB memory-hard password hashing (3 iterations)
- **Tamper-evident audit logging** — Append-only hash-chained integrity log plus queryable SQLite audit table
- **Password history** — Retains current password + 3 previous (max 4 states)
- **Auto-lock** — Locks after configurable inactivity period (default 15 min)
- **Rate limiting** — 5 attempts/minute on master password
- **Clipboard security** — Auto-clears after configurable timeout (default 20s)
- **Soft delete** — Accounts are marked deleted, never truly gone
- **Encrypted backups** — `.vlt` format (encrypted tar with metadata)
- **Integrity verification** — `vault verify` checks the hash chain and database
- **Password confirmation** — Master password is entered twice on first launch to prevent typos
- **Search bar highlighting** — Yellow border/background indicates active search mode
- **Optimised unlock** — Single Argon2id derivation (not double) for faster unlocking
- **Zero cloud dependencies** — Everything stays local

## Quick Start

```bash
# Build
cargo build --release

# Set vault location (optional, defaults to platform data dir)
export VAULT_DIR=~/.vault

# Launch the TUI
./target/release/vault
```

**First launch**: enter a strong master password, then confirm it (typed twice) to create your vault.  
**Existing vault**: enter the same password to unlock.

The lock screen adapts: shows **"Create Vault"** on first launch and **"Vault Locked"** on subsequent visits.

## TUI Keybindings

| Key | Action |
|-----|--------|
| `a` | Add account (guided: service → username → password → notes) |
| `e` | Edit selected account (Enter to advance field, Tab to skip, Esc to cancel) |
| `s` | Reveal password — shows username, password, notes, timestamps, auto-hides after configurable timeout |
| `c` | Copy password to clipboard — auto-clears after configurable timeout, warns if clipboard unsupported |
| `h` | View password history — decrypted passwords with change timestamps |
| `d` | Delete account — type `DELETE` to confirm |
| `t` | Toggle show/hide deleted accounts — status bar shows `[Showing deleted]` when active |
| `F2` | Open settings editor — navigate with Up/Down, Enter to edit, Ctrl+S to save |
| `/` | Search accounts — search bar highlights with yellow border/background when active |
| `Esc` | Cancel / clear search / close password view / navigate back |
| `↑` `↓` | Navigate account list (wraps around) |
| `Ctrl+L` | Lock vault — returns to lock screen, zeroes secrets from memory |
| `Ctrl+C` | Quit from any screen |
| `q` | Quit when on the main account list |

## CLI Commands

```bash
vault init              # Initialize a new vault directory
vault verify            # Verify hash chain and database integrity
vault export <file>     # Export encrypted backup
vault import <file>     # Import from backup
vault                   # Launch TUI (no arguments)
```

## Configuration

A commented `config.toml` is auto-generated in your vault directory on creation.  
Edit it to customize behaviour:

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

## Architecture

```
+-----------------------+
|        TUI            |  ← ratatui + crossterm
+-----------------------+
|        CLI            |  ← init, verify, export, import
+-----------------------+
|      Services         |  ← business logic orchestrator
+-----------------------+
| Crypto | Audit | DB   |  ← XChaCha20, hash chain, SQLite
+-----------------------+
|       SQLite          |  ← WAL mode, operational store
+-----------------------+
```

### Module map

| Module | File | Responsibility |
|--------|------|---------------|
| `models` | `src/models/mod.rs` | Core data types: `Account`, `AccountSummary`, `DecryptedAccount`, `PasswordHistoryEntry`, `AuditEntry`, `EventType`, `AppConfig` |
| `crypto` | `src/crypto/mod.rs` | XChaCha20-Poly1305 encrypt/decrypt, Argon2id KDF, SHA-256, validation token |
| `db` | `src/db/mod.rs` | SQLite operations: CRUD for accounts, password history, audit_log table, search, schema init |
| `audit` | `src/audit/mod.rs` | Append-only hash-chained `audit.log` with integrity verification |
| `auth` | `src/auth/mod.rs` | Authentication flow: vault creation, unlock, rate-limiting, unlock failure logging |
| `services` | `src/services/mod.rs` | `Vault` orchestrator: combines crypto, db, audit for all operations. Defines `DecryptedAccount` |
| `config` | `src/config/mod.rs` | Config load/save, default config generation, vault directory resolution |
| `storage` | `src/storage/mod.rs` | Encrypted `.vlt` backup export/import with tar + audit log |
| `utils` | `src/utils/mod.rs` + `clipboard.rs` | Rate limiter, platform-abstracted clipboard (macOS/Linux via arboard, unsupported fallback) |
| `tui` | `src/tui/mod.rs` | Full ratatui+crossterm TUI: lock screen, account management, settings, history, status bar |
| `cli` | `src/cli/mod.rs` | CLI commands: `init`, `verify`, `export`, `import` |
| `main` | `src/main.rs` | Entry point: routes to CLI or TUI |

### Storage

| File | Purpose |
|------|---------|
| `vault.db` | SQLite operational store (accounts, password_history, audit_log, vault_metadata). WAL mode enabled. |
| `audit.log` | Append-only hash-chained integrity log (canonical source). Each line: id\|timestamp\|session_id\|event_type\|account_id\|metadata\|prev_hash\|entry_hash |
| `config.toml` | User configuration with commented defaults |

### Encryption

- **Algorithm**: XChaCha20-Poly1305 (authenticated encryption with random 24-byte nonce per operation)
- **KDF**: Argon2id (4 MiB memory, 3 iterations, 1 parallelism, 256-bit output)
- **Encrypted fields**: username, password, notes (each encrypted separately with unique nonces)
- **Plaintext fields**: service_name, id, timestamps (needed for search and display without decryption)
- **Validation token**: random 32 bytes encrypted with derived key, stored in `vault_metadata`. Decrypting it proves key correctness without storing the password.
- Master password is never stored — validated via the encrypted validation token
- Secrets are zeroized on drop via the `zeroize` crate

### Audit System

Two complementary stores that log identical events:
1. **SQLite `audit_log` table** — queryable, filterable, indexed by event_type and session_id
2. **`audit.log` file** — append-only, SHA-256 hash-chained, canonical integrity source

Every meaningful action is logged with session ID, timestamp, and metadata:

| Event | When triggered |
|-------|---------------|
| `vault_init` | First-time vault creation |
| `app_start` / `app_exit` | TUI session lifecycle |
| `unlock_success` / `unlock_failure` | Authentication attempts |
| `auto_lock` / `manual_lock` | Vault locking |
| `account_create` / `account_update` / `account_soft_delete` | Account CRUD |
| `password_show` | Reveal password (logs duration) |
| `password_copy` | Copy to clipboard |
| `backup_export` / `backup_import` | Backup operations |
| `config_change` | Settings saved via Ctrl+S |
| `rate_limit_triggered` | Authentication rate-limit hit |
| `integrity_check_failure` / `corrupted_log_detected` | Integrity verification failures |

## Backup Format

`.vlt` files are structured as: `[32-byte export key][encrypted tar archive]`.
The tar archive contains:

| Entry | Content |
|-------|--------|
| `metadata.json` | Format version, ISO 8601 timestamp, app version, KDF/cipher identifiers |
| `vault.json` | All accounts as JSON (encrypted fields remain encrypted — import uses the same master key) |
| `audit.log` | Full audit log (appended to existing log on import for continuity) |

Import skips soft-deleted accounts and accounts that already exist (matched by UUID).

## Implementation Status

All core requirements are implemented and passing tests (22 tests across 7 modules).

### What's fully working

| Feature | Status |
|---------|--------|
| Account CRUD (create, read, update, soft delete) | ✅ |
| Password history viewer (press `h`, shows current + 3 previous) | ✅ |
| XChaCha20-Poly1305 encryption (username, password, notes) | ✅ |
| Argon2id key derivation (4 MB, 3 iterations) | ✅ |
| Master password auth (validation token, never stored) | ✅ |
| Rate limiting (5 attempts/min, in-memory) | ✅ |
| Dual audit logging (hash-chained audit.log + SQLite audit_log) | ✅ |
| Auto-lock (configurable timer, lock screen overlay) | ✅ |
| Clipboard copy with auto-clear (platform-abstracted) | ✅ |
| Clipboard support detection (warns if unavailable) | ✅ |
| Password reveal with auto-hide timeout | ✅ |
| Password detail screen with timestamps (created, updated, deleted) | ✅ |
| Search (case-insensitive substring on service_name) | ✅ |
| Toggle show/hide deleted accounts (`t` key) | ✅ |
| Encrypted backup export/import (.vlt tar format) | ✅ |
| Integrity verification on unlock + `vault verify` CLI | ✅ |
| Settings screen (`F2`) — edit config live from TUI | ✅ |
| Status bar (vault path, session ID, auto-lock countdown, warnings) | ✅ |
| `vault init` (prepare directory, DB, audit log, config) | ✅ |
| SQLite WAL mode | ✅ |
| Memory zeroization (secrets cleared on lock/exit) | ✅ |

### Service layer — fully integrated

All public API methods on `Vault` are now wired into the TUI or CLI:

| Method | Where used |
|--------|-----------|
| `create_account()` | Add account flow (`a` key) |
| `update_account()` | Edit account flow (`e` key) — auto-advances field by field |
| `delete_account()` | Soft-delete (`d` key, type `DELETE` to confirm) |
| `get_account_decrypted()` | Password reveal (`s` key), clipboard copy (`c` key) |
| `search_accounts()` | Account list and search (`/` key) |
| `search_all_accounts()` | Show-deleted toggle (`t` key) |
| `get_password_history_decrypted()` | Password history viewer (`h` key) |
| `verify_integrity()` | Auto-run on vault unlock, shows banner if issues found |
| `session_id()` | Status bar (short session ID, e.g. `Session: abc12345`) |
| `log_config_change()` | Settings save (Ctrl+S) — logged to audit chain |
| `log_auto_lock()` / `log_manual_lock()` | Lock events (Ctrl+L and auto-lock timer) |
| `log_app_start()` / `log_app_exit()` | Session lifecycle |
| `export_accounts()` | Backup export (`vault export <file>`) |
| `log_backup_export()` / `log_backup_import()` | Backup audit trail |

### Status bar

The TUI status bar shows at a glance:

| Indicator | Meaning |
|-----------|--------|
| `Vault: /path/to/vault` | Current vault directory |
| `Session: abc12345` | First 8 chars of the session UUID |
| `Auto-lock: 842s` | Countdown in seconds until auto-lock (or `off` if disabled) |
| `[Showing deleted]` | Soft-deleted accounts are visible (`t` toggle active) |
| `⚠ No clipboard` | Clipboard access unavailable on this platform |
| `⚠ Integrity issue` | Audit log hash chain or database has a problem |

## Threat Model

**In scope**: casual device theft, offline vault theft, unauthorized local access  
**Out of scope**: kernel-level compromise, forensic memory extraction, hardware implants

## Development

```bash
# Run tests (22 tests across 7 modules)
cargo test

# Build
cargo build --release

# Run with custom vault location
VAULT_DIR=/tmp/test-vault cargo run
```

### Test coverage

| Module | Tests |
|--------|-------|
| `crypto` | 6 (roundtrip, string, key derivation, validation token, SHA-256, nonce uniqueness) |
| `db` | 4 (CRUD, search, soft-delete, password history) |
| `services` | 5 (create/read, update with history, delete, search, history pruning) |
| `auth` | 3 (first launch, valid/invalid password, rate limit logging) |
| `audit` | 2 (append/verify, tamper detection) |
| `storage` | 1 (export/import roundtrip) |
| `utils` | 1 (rate limiter) |

### Dependencies

| Category | Crates |
|----------|--------|
| TUI | `ratatui` 0.28, `crossterm` 0.28 |
| Crypto | `argon2` 0.5, `chacha20poly1305` 0.10, `sha2` 0.10, `zeroize` 1, `rand` 0.8 |
| Storage | `rusqlite` 0.31 (bundled SQLite), `serde` + `serde_json`, `toml` 0.8 |
| Backup | `tar` 0.4, `flate2` 1, `base64` 0.22 |
| Platform | `directories` 5, `arboard` 3.6, `signal-hook` 0.3 |
| Utilities | `uuid` 1 (v4), `chrono` 0.4 (serde) |

## License

MIT
