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
| `e` | Edit selected account (Tab through fields, Enter to save) |
| `s` | Reveal password (auto-hides after 10s) |
| `c` | Copy password to clipboard (auto-clears after 20s) |
| `d` | Delete account — type `DELETE` to confirm |
| `/` | Search accounts — search bar highlights with yellow border/background when active |
| `Esc` | Cancel / clear search / close password view |
| `↑` `↓` | Navigate account list |
| `Ctrl+L` | Lock vault |
| `q` | Quit |

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

### Storage

| File | Purpose |
|------|---------|
| `vault.db` | SQLite operational store (accounts, audit_log, metadata) |
| `audit.log` | Append-only hash-chained integrity log (canonical source) |
| `config.toml` | User configuration |

### Encryption

- **Algorithm**: XChaCha20-Poly1305 (authenticated encryption)
- **KDF**: Argon2id (4 MB, 3 iterations, 1 parallelism)
- **Encrypted fields**: username, password, notes
- **Plaintext fields**: service_name (for search)
- Master password is never stored — validated via encrypted token in `vault_metadata`

### Audit System

Two complementary stores:
1. **SQLite `audit_log` table** — queryable, filterable, optimized for application use
2. **`audit.log` file** — append-only, hash-chained, canonical integrity source

Every meaningful action is logged: create, update, delete, show, copy, lock, unlock, export, import.

## Backup Format

`.vlt` files are encrypted tar archives containing:
```
backup.vlt
├── metadata.json    # format version, timestamp, KDF, cipher
├── vault.json       # encrypted account data (all accounts incl. soft-deleted)
└── audit log data
```

## Implementation Status

All core requirements are implemented and passing tests (21 tests, 0 failures).

### What's fully working

| Feature | Status |
|---------|--------|
| Account CRUD (create, read, update, soft delete) | ✅ |
| Password history (current + 3 previous, auto-pruned) | ✅ |
| XChaCha20-Poly1305 encryption (username, password, notes) | ✅ |
| Argon2id key derivation (4 MB, 3 iterations) | ✅ |
| Master password auth (validation token, never stored) | ✅ |
| Rate limiting (5 attempts/min, in-memory) | ✅ |
| Dual audit logging (hash-chained audit.log + SQLite audit_log) | ✅ |
| Auto-lock (configurable timer, lock screen overlay) | ✅ |
| Clipboard copy with auto-clear (platform-abstracted) | ✅ |
| Password reveal with auto-hide timeout | ✅ |
| Search (case-insensitive substring on service_name) | ✅ |
| Encrypted backup export/import (.vlt tar format) | ✅ |
| Integrity verification (`vault verify`) | ✅ |
| `vault init` (prepare directory, DB, audit log, config) | ✅ |
| SQLite WAL mode | ✅ |
| Memory zeroization (secrets cleared on lock/exit) | ✅ |

### Public API available for future features

The `Vault` service layer exposes additional methods that are currently not wired
into the TUI but are ready for future use:

| Method | Purpose | Target feature |
|--------|---------|---------------|
| `session_id()` | Get current session UUID | Session management, status bar |
| `config()` / `config_mut()` | Read/write live config | Settings screen in TUI |
| `search_all_accounts()` | Search including soft-deleted | "Show deleted" toggle |
| `get_password_history_decrypted()` | Decrypt and return old passwords | Password history viewer |
| `verify_integrity()` | Run full integrity check from service | Better CLI integration |
| `log_unlock_failure()` | Log failed auth attempts | Unified logging path from CLI |

Some lower-level helpers also exist as building blocks (crypto utilities,
DB-level history query) that the service layer wraps with decryption.

## Threat Model

**In scope**: casual device theft, offline vault theft, unauthorized local access  
**Out of scope**: kernel-level compromise, forensic memory extraction, hardware implants

## Development

```bash
# Run tests
cargo test

# Build
cargo build --release

# Run with custom vault location
VAULT_DIR=/tmp/test-vault cargo run
```

### Dependencies

- **TUI**: ratatui, crossterm
- **Crypto**: argon2, chacha20poly1305, sha2, zeroize
- **Database**: rusqlite (bundled SQLite)
- **Platform**: directories, arboard (clipboard)

## License

MIT
