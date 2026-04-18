//! Thin CLI shim. All logic is in the `secret_proxy_ca` library crate
//! (`src/lib.rs`) — this file exists only to spell out the binary entry
//! and wire env_logger. See `secret_proxy_ca::cli::run` for the actual
//! argv dispatch.

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    if let Err(e) = secret_proxy_ca::cli::run() {
        log::error!("{e}");
        std::process::exit(1);
    }
}
