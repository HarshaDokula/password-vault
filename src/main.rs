mod audit;
mod auth;
mod cli;
mod config;
mod crypto;
mod db;
mod models;
mod services;
mod storage;
mod tui;
mod utils;

use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // If CLI arguments provided, run CLI mode
    if args.len() > 1 {
        match cli::run_cli(&args) {
            Ok(()) => process::exit(0),
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        }
    }

    // Otherwise run TUI mode
    let vault_dir = config::get_vault_dir();
    
    // Ensure vault directory exists
    if let Err(e) = config::ensure_vault_dir(&vault_dir) {
        eprintln!("Error: {}", e);
        process::exit(1);
    }

    // Load config
    let _config = config::load_config(&vault_dir);

    let mut app = tui::App::new(vault_dir);
    if let Err(e) = app.run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
