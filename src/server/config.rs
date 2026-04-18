//! Serve-mode configuration.
//!
//! Tiny for now: just the listening port parsed from `--port`. Kept as
//! a dedicated module so future options (bind address, idle timeout,
//! max-connections from the Phase-2 plan) land in a predictable place
//! instead of growing `cmd_serve`'s argument spaghetti.

use crate::cli::parse_arg_u32;

/// Parsed serve-mode arguments.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// TCP port to bind the HTTP server on (via `--port <N>`).
    pub port: u16,
}

impl ServerConfig {
    /// Default port — matches what `scripts/deploy-teeproxyd.sh` and
    /// `tools/teeproxyd/` start the CA with, so `secret_proxy_ca serve`
    /// with no `--port` flag binds the same port the production
    /// pipeline uses.
    pub const DEFAULT_PORT: u16 = 19030;

    /// Parse serve-mode CLI arguments (the slice after `serve`).
    /// Unknown flags are silently ignored — [`parse_arg_u32`] only
    /// matches the `[flag, value]` window it's asked about.
    pub fn from_args(args: &[String]) -> Self {
        let port = parse_arg_u32(args, "--port")
            .map(|p| p as u16)
            .unwrap_or(Self::DEFAULT_PORT);
        Self { port }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_args_yield_default_port() {
        let cfg = ServerConfig::from_args(&[]);
        assert_eq!(cfg.port, ServerConfig::DEFAULT_PORT);
    }

    #[test]
    fn port_flag_overrides_default() {
        let args = vec!["--port".into(), "19030".into()];
        let cfg = ServerConfig::from_args(&args);
        assert_eq!(cfg.port, 19030);
    }

    #[test]
    fn unknown_flags_are_ignored() {
        // `parse_arg_u32` only matches the specific flag it's asked
        // about; stray flags don't abort startup.
        let args = vec![
            "--unknown".into(),
            "garbage".into(),
            "--port".into(),
            "12345".into(),
        ];
        let cfg = ServerConfig::from_args(&args);
        assert_eq!(cfg.port, 12345);
    }

    #[test]
    fn malformed_port_falls_back_to_default() {
        // `parse_arg_u32` returns Err on non-numeric values, which
        // `from_args` maps to `unwrap_or(DEFAULT_PORT)`. Operator sees
        // the server start on the default port instead of crashing.
        let args = vec!["--port".into(), "not-a-number".into()];
        let cfg = ServerConfig::from_args(&args);
        assert_eq!(cfg.port, ServerConfig::DEFAULT_PORT);
    }
}
