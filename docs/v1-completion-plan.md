# V1 Completion Plan

## Overview
Implement all remaining features from the requirements doc and README future-API list.
Each task is a self-contained TDD cycle with clear acceptance criteria.

## Tasks

### T1: Rate limit trigger logging
- **Goal**: Log `rate_limit_triggered` events when rate limiting fires
- **Context**: `auth::authenticate` returns `Failed("Rate limited")` but never logs. Req §11 says "All rate-limit triggers are logged."
- **Approach**: In `auth::authenticate`, before returning the rate-limited error, open `IntegrityLog` and append a `RateLimitTriggered` event. Also insert into SQLite audit_log via a helper.
- **AC**: When rate-limited, both audit.log and SQLite audit_log get a `rate_limit_triggered` entry with `remaining_attempts: 0` metadata
- **Spec**: none
- **Verify**: `cargo test` (add auth test that checks audit log line count after rate limit)

### T2: Startup integrity check with corruption warning
- **Goal**: On vault unlock, verify audit log hash chain. If broken, show warning in TUI.
- **Context**: `verify_integrity()` exists on Vault but is never called during normal operation. Req §19 says "display warning, continue application functionality."
- **Approach**: In `try_unlock()` and `confirm_password()`, after creating the Vault, call `vault.verify_integrity()`. If issues found, set a warning message shown on the main screen.
- **AC**: Broken audit.log produces a warning banner on main screen. Clean vault produces no banner.
- **Spec**: none
- **Verify**: `cargo test` (add test: tamper audit.log, unlock, check issues returned)

### T3: Show/hide deleted accounts toggle
- **Goal**: Toggle to include soft-deleted accounts in search results
- **Context**: Req §13 says future toggle `[d] show deleted` but `d` is taken. Use `t` for toggle. Uses `search_all_accounts()`.
- **Approach**: Add `show_deleted: bool` field to `App`. Key `t` in unlocked mode toggles it. Search calls `search_all_accounts()` when true. Show indicator in help bar.
- **AC**: Pressing `t` toggles between showing/hiding deleted accounts. Deleted accounts shown with strikethrough or dim style.
- **Spec**: none
- **Verify**: `cargo test`; manual: create account, delete it, press `t`, verify it appears

### T4: Password history viewer
- **Goal**: View password history for a selected account
- **Context**: `get_password_history_decrypted()` exists. Req §15 specifies 3 history entries.
- **Approach**: Key `h` on selected account opens a history viewer screen showing passwords with change timestamps. Press Esc to close.
- **AC**: Shows up to 3 previous passwords with timestamps. Current password excluded.
- **Spec**: none
- **Verify**: `cargo test` (services test already covers history, add TUI rendering test if feasible)

### T5: Settings screen
- **Goal**: Edit `config.toml` from within the TUI
- **Context**: `config()` and `config_mut()` exist. Req §12 references "future TUI settings menu."
- **Approach**: Key `F2` opens settings screen. Navigate fields with up/down, edit with Enter, save with Ctrl+S, cancel with Esc. On save, write config.toml and log ConfigChange event.
- **AC**: Can view and edit all config values. Saved config persists across restart. ConfigChange logged.
- **Spec**: short
- **Verify**: `cargo test`; manual: open settings, change auto_lock_minutes, save, quit, reopen, verify change persisted

### T6: Status bar
- **Goal**: Show vault status and session info on main screen
- **Context**: `session_id()` exists. Req §10 describes session model.
- **Approach**: Add a bottom status bar showing: vault path, session uptime, auto-lock countdown, deleted filter indicator, integrity status.
- **AC**: Status bar visible on main screen with relevant info. Updates each frame.
- **Spec**: none
- **Verify**: `cargo test` (build check); manual: verify status bar appearance

### T7: CLI verify uses Vault service
- **Goal**: `vault verify` uses `Vault::verify_integrity()` instead of manual checks
- **Context**: CLI currently duplicates integrity check code. `verify_integrity()` is the canonical path.
- **Approach**: Rewrite `cmd_verify` to unlock vault and call `vault.verify_integrity()`. Also call `vault.log_unlock_failure()` for failed auth attempts in `unlock_interactive`.
- **AC**: `vault verify` output matches current format but uses Vault service internally. Unlock failures logged via vault method.
- **Spec**: none
- **Verify**: `cargo test`; manual: `cargo run -- verify`

### T8: Backup export includes audit log
- **Goal**: `.vlt` archive includes `audit.log` data
- **Context**: Req §22 says "Exports include active accounts, soft-deleted accounts, audit history." Current export only has accounts.
- **Approach**: In `export_vault()`, read `audit.log` file and include as `audit.log` in the tar archive. On import, optionally restore audit log (append to existing).
- **AC**: Export contains audit.log entry. Import restores it alongside accounts.
- **Spec**: none
- **Verify**: `cargo test` (update storage test); check tar contents

## Dependency Order
T1 (independent) → T2 (independent) → T3 (independent) → T4 (independent) → T5 (needs Vault config APIs) → T6 (independent) → T7 (needs T2 verify support) → T8 (independent)

## Implementation Order
Use TDD for each: write failing test → implement → verify tests pass → commit.
