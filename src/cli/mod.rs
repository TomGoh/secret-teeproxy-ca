//! CLI argv dispatch + subcommand handlers.
//!
//! `main()` (in `src/main.rs`) calls [`run`] with `std::env::args()`;
//! this module does everything else: parse the subcommand, open
//! `RealTeec` when needed, dispatch to a subcommand fn, print usage.
//!
//! Step 10 refactor: this was inlined in `main.rs::run()`. Moved
//! here so the binary entry is a few lines of env_logger init + one
//! `cli::run()` call, and all subcommand logic lives next to its
//! usage text.

pub mod diagnostics;

use log::error;

use crate::constants::TA_UUID;
use crate::teec::ops::{
    teec_add_whitelist, teec_list_slots, teec_provision_key, teec_remove_key,
};
use crate::teec::{RealTeec, Teec};
use crate::wire::ProvisionKeyPayload;

/// Top-level CLI entry. Dispatches on `argv[1]` to a subcommand,
/// opens/drops a `RealTeec` when the subcommand needs TA access, and
/// defers `serve` to [`crate::server::run`].
///
/// Returns `Err` only for subcommand failures; an unknown subcommand
/// prints usage and returns `Ok(())` (matches pre-refactor behavior,
/// so `secret_proxy_ca --help` exits 0).
pub fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0]);
        return Ok(());
    }

    // `serve` manages its own TEEC lifecycle (long-lived session).
    if args[1] == "serve" {
        return crate::server::run(&args[2..]);
    }

    // TEEC-free diagnostics — no RealTeec needed.
    if args[1] == "dns-test" {
        let host = args.get(2).ok_or("dns-test requires <hostname>")?;
        return diagnostics::cmd_dns_test(host);
    }
    if args[1] == "vsock-test" {
        let cid: u32 = args
            .get(2)
            .ok_or("vsock-test requires <cid> [port]")?
            .parse()
            .map_err(|e| format!("invalid cid: {e}"))?;
        let port: u32 = match args.get(3) {
            Some(s) => s.parse().map_err(|e| format!("invalid port: {e}"))?,
            None => 9999,
        };
        return diagnostics::cmd_vsock_test(cid, port);
    }

    // All remaining subcommands need a TEE session.
    let mut teec = RealTeec::open(TA_UUID)?;

    match args[1].as_str() {
        "list-slots" => cmd_list_slots(&mut teec),
        "provision-key" => cmd_provision_key(&mut teec, &args[2..]),
        "remove-key" => cmd_remove_key(&mut teec, &args[2..]),
        "add-whitelist" => cmd_add_whitelist(&mut teec, &args[2..]),
        other => {
            error!("unknown command: {other}");
            print_usage(&args[0]);
            Ok(())
        }
    }
    // `teec` drops here — closes session + finalizes context.
}

// --- Subcommand handlers -----------------------------------------------

fn cmd_list_slots(teec: &mut dyn Teec) -> Result<(), String> {
    let slots = teec_list_slots(teec)?;
    let count = slots.len();
    println!("Slots ({count} total): {slots:?}");
    Ok(())
}

fn cmd_provision_key(teec: &mut dyn Teec, args: &[String]) -> Result<(), String> {
    let slot = parse_arg_u32(args, "--slot")?;
    let key = parse_arg_str(args, "--key")?;
    let provider = parse_arg_str(args, "--provider")?;

    let payload = ProvisionKeyPayload { slot, key, provider };
    teec_provision_key(teec, &payload)?;
    println!("Key provisioned in slot {slot}");
    Ok(())
}

fn cmd_remove_key(teec: &mut dyn Teec, args: &[String]) -> Result<(), String> {
    let slot = parse_arg_u32(args, "--slot")?;
    teec_remove_key(teec, slot)?;
    println!("Slot {slot} removed");
    Ok(())
}

fn cmd_add_whitelist(teec: &mut dyn Teec, args: &[String]) -> Result<(), String> {
    let pattern = parse_arg_str(args, "--pattern")?;
    teec_add_whitelist(teec, &pattern)?;
    println!("Whitelist entry added: {pattern}");
    Ok(())
}

// --- Argument parsing (kept here, not in clap: the 6 flags we have ---
//                       don't justify the ~200KB of clap binary weight)

/// Extract a string argument value following a flag (e.g.
/// `--slot 0` → `"0"`). Scans `args` for the `[flag, value]` window.
fn parse_arg_str(args: &[String], flag: &str) -> Result<String, String> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
        .ok_or_else(|| format!("missing argument: {flag}"))
}

/// Extract a u32 argument value following a flag (e.g. `--slot 0` → 0u32).
pub(crate) fn parse_arg_u32(args: &[String], flag: &str) -> Result<u32, String> {
    let s = parse_arg_str(args, flag)?;
    s.parse::<u32>()
        .map_err(|e| format!("{flag} parse error: {e}"))
}

fn print_usage(prog: &str) {
    eprintln!("Usage:");
    eprintln!("  {prog} list-slots");
    eprintln!("  {prog} provision-key --slot <N> --key <sk-...> --provider <name>");
    eprintln!("  {prog} remove-key --slot <N>");
    eprintln!("  {prog} add-whitelist --pattern <url-prefix>");
    eprintln!("  {prog} serve [--port 19030]");
    eprintln!("  {prog} dns-test <hostname>");
    eprintln!("  {prog} vsock-test <cid> [port]");
    eprintln!();
    eprintln!("HTTP proxy requests are served only via `serve` mode (the `proxy`");
    eprintln!("CLI subcommand was removed in the Step 8 refactor — it had no");
    eprintln!("external callers). Clients should POST SecretProxyRequest JSON");
    eprintln!("to the port configured with --port.");
    eprintln!();
    eprintln!("dns-test is a TEEC-free diagnostic: resolves <hostname>:443 via the");
    eprintln!("platform's getaddrinfo and prints the result. Use it on Android to");
    eprintln!("verify Bionic/dnsproxyd works before exercising the full proxy.");
    eprintln!();
    eprintln!("vsock-test is a TEEC-free diagnostic that exercises the raw vsock");
    eprintln!("socket + connect path to a given (cid, port). Errors come back as");
    eprintln!("raw errno values from the kernel — useful on Android bring-up to");
    eprintln!("distinguish SELinux denials (EACCES) from missing VM peers (ENODEV)");
    eprintln!("or missing kernel support (EAFNOSUPPORT). Default port is 9999.");
    eprintln!();
    eprintln!("Logging: set RUST_LOG=debug for verbose relay details.");
    eprintln!();
    eprintln!("serve: GET /health (TEEC+TA probe, no auth); admin API: set SECRET_PROXY_CA_ADMIN_TOKEN");
    eprintln!("  X-Admin-Token for GET /admin/keys/slots and POST /admin/keys/provision");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_arg_str_finds_value_after_flag() {
        let args = vec!["--foo".into(), "bar".into()];
        assert_eq!(parse_arg_str(&args, "--foo").unwrap(), "bar");
    }

    #[test]
    fn parse_arg_str_missing_flag_errors() {
        let args: Vec<String> = vec![];
        let err = parse_arg_str(&args, "--foo").unwrap_err();
        assert!(err.contains("missing argument: --foo"));
    }

    #[test]
    fn parse_arg_u32_parses_numeric_values() {
        let args = vec!["--n".into(), "42".into()];
        assert_eq!(parse_arg_u32(&args, "--n").unwrap(), 42);
    }

    #[test]
    fn parse_arg_u32_non_numeric_errors() {
        let args = vec!["--n".into(), "abc".into()];
        let err = parse_arg_u32(&args, "--n").unwrap_err();
        assert!(err.contains("parse error"));
    }
}
