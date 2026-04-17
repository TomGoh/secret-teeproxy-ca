//! Protocol constants shared across the CA.
//!
//! These values are defined by the secret_proxy_ta wire protocol. Any change
//! here requires a matching change in `secret_proxy_ta/src/main.rs`.
//!
//! Keep everything in one module so a single file diff surfaces any version
//! drift against the TA side; do not split by command/biz/admin because that
//! makes cross-cutting grep harder.

// ---------------------------------------------------------------------------
// TA identity
// ---------------------------------------------------------------------------

/// TA UUID — must match `TA_UUID` in `secret_proxy_ta/src/main.rs`.
/// The `teec_cc_bridge` uses this to locate the TA's Unix socket at
/// `/tmp/{uuid}.sock`.
pub const TA_UUID: &str = "a3f79c15-72d0-4e3a-b8d1-9f2ca3e81054";

// ---------------------------------------------------------------------------
// GP TEE command IDs — passed as `cmd_id` to `TEEC_InvokeCommand()`.
// Must match the constants in `secret_proxy_ta/src/main.rs`.
// ---------------------------------------------------------------------------

pub const CMD_PROXY_REQUEST:   u32 = 0x0001;
pub const CMD_PROVISION_KEY:   u32 = 0x0002;
pub const CMD_REMOVE_KEY:      u32 = 0x0003;
pub const CMD_LIST_SLOTS:      u32 = 0x0004;
pub const CMD_ADD_WHITELIST:   u32 = 0x0005;
pub const CMD_RELAY_DATA:      u32 = 0x0006;
pub const CMD_LIST_SLOTS_META: u32 = 0x0007;

// ---------------------------------------------------------------------------
// Business result codes returned in `params[1].value.a` by the TA.
// Must match constants in `secret_proxy_ta/src/main.rs`.
// ---------------------------------------------------------------------------

pub const BIZ_SUCCESS:           u32 = 0x900D;
pub const BIZ_RELAY_START:       u32 = 0x9001;
pub const BIZ_RELAY_CONTINUE:    u32 = 0x9002;
pub const BIZ_RELAY_DONE:        u32 = 0x9003;
pub const BIZ_RELAY_STREAMING:   u32 = 0x9004;
pub const BIZ_ERR_BAD_JSON:      u32 = 0xE001;
pub const BIZ_ERR_KEY_NOT_FOUND: u32 = 0xE004;
pub const BIZ_ERR_FORBIDDEN:     u32 = 0xE005;
pub const BIZ_ERR_TRANSPORT:     u32 = 0xE006;

// ---------------------------------------------------------------------------
// Admin API constants (serve mode HTTP headers + env vars)
// ---------------------------------------------------------------------------

/// Env var: shared secret required for `GET/POST /admin/*`
/// (HTTP header `X-Admin-Token`).
pub const ADMIN_TOKEN_ENV: &str = "SECRET_PROXY_CA_ADMIN_TOKEN";
/// Optional previous token during rotation window (accepted in parallel
/// with `SECRET_PROXY_CA_ADMIN_TOKEN` so operators can rotate without
/// breaking in-flight callers).
pub const ADMIN_TOKEN_PREV_ENV: &str = "SECRET_PROXY_CA_ADMIN_TOKEN_PREV";
/// Minimum admin token length (bytes). Enforced with constant-time
/// compare so short tokens cannot be brute-forced byte-at-a-time.
pub const ADMIN_TOKEN_MIN_LEN: usize = 32;
pub const ADMIN_ACTOR_HEADER: &str = "x-openclaw-actor";
pub const ADMIN_REQUEST_ID_HEADER: &str = "x-request-id";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ta_uuid_is_rfc4122_form() {
        // If the UUID string format ever drifts, the CA's parse_uuid()
        // helper fails at startup — catching it here gives a clearer signal.
        assert!(uuid::Uuid::parse_str(TA_UUID).is_ok());
    }

    #[test]
    fn biz_codes_are_distinct() {
        // A collision between, say, BIZ_RELAY_DONE and BIZ_ERR_TRANSPORT
        // would silently misroute in the relay state machine. Guard against
        // copy-paste bugs during future TA protocol edits.
        let codes = [
            BIZ_SUCCESS, BIZ_RELAY_START, BIZ_RELAY_CONTINUE,
            BIZ_RELAY_DONE, BIZ_RELAY_STREAMING,
            BIZ_ERR_BAD_JSON, BIZ_ERR_KEY_NOT_FOUND,
            BIZ_ERR_FORBIDDEN, BIZ_ERR_TRANSPORT,
        ];
        let mut seen = std::collections::HashSet::new();
        for c in codes {
            assert!(seen.insert(c), "duplicate biz code: {:#x}", c);
        }
    }

    #[test]
    fn cmd_ids_are_contiguous_from_1() {
        // Defensive: the TA indexes commands by id, so a gap would indicate
        // a removed command still referenced somewhere.
        let mut cmds = vec![
            CMD_PROXY_REQUEST, CMD_PROVISION_KEY, CMD_REMOVE_KEY,
            CMD_LIST_SLOTS, CMD_ADD_WHITELIST, CMD_RELAY_DATA,
            CMD_LIST_SLOTS_META,
        ];
        cmds.sort();
        assert_eq!(cmds, (0x0001..=0x0007).collect::<Vec<u32>>());
    }
}
