# Vault — Terminal Password Manager

A local-first, terminal-based password manager written in Rust. Lightweight, secure, and keyboard-driven.

## Features

- **AES-grade encryption** — XChaCha20-Poly1305 for all secrets (username, password, notes)
- **Argon2id key derivation** — 19 MB memory-hard password hashing
- **Tamper-evident audit logging** — Append-only hash-chained integrity log plus queryable SQLite audit table
- **Password history** — Retains current password + 3 previous (max 4 states)
- **Auto-lock** — Locks after configurable inactivity period (default 15 min)
- **Rate limiting** — 5 attempts/minute on master password
- **Clipboard security** — Auto-clears after configurable timeout (default 20s)
- **Soft delete** — Accounts are marked deleted, never truly gone
- **Encrypted backups** — `.vlt` format (encrypted tar with metadata)
- **Integrity verification** — `vault verify` checks the hash chain and database
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

On first launch, enter a strong master password to create your vault.  
On subsequent launches, enter the same password to unlock.

## TUI Keybindings

| Key | Action |
|-----|--------|
| `a` | Add account (guided: service → username → password → notes) |
| `e` | Edit selected account (Tab through fields, Enter to save) |
| `s` | Reveal password (auto-hides after 10s) |
| `c` | Copy password to clipboard (auto-clears after 20s) |
| `d` | Delete account — type `DELETE` to confirm |
| `/` | Search accounts by service name (case-insensitive substring) |
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

Edit `config.toml` in your vault directory:

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
- **KDF**: Argon2id (19 MB, 2 iterations, 1 parallelism)
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
