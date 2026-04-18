# secret_proxy_ca

Client Application (CA) half of the **secret-proxy** TEE stack. Runs on the
Android host, talks to the **SecretProxyTA** Trusted Application over GP TEE
Client API (rust-libteec → TLS-over-vsock → `teec_cc_bridge` inside a protected
VM → TA). The TA holds API keys and drives the outgoing TLS session (rustls
inside the TEE); this CA is what LLM client apps (OpenClaw et al.) actually
connect to.

```text
openclaw (HTTP POST)
  ↓
secret_proxy_ca  ← this crate
  ↓ TEEC (vsock/TLS)
teec_cc_bridge (inside protected VM)
  ↓ Unix socket
secret_proxy_ta — holds keys, drives rustls
  ↓ plaintext request
(TA's internal TLS stack → upstream LLM API)
```

The CA never sees the plaintext API key — the TA injects
`Authorization: Bearer <key>` before encrypting with rustls.

## Binary modes

```bash
secret_proxy_ca serve [--port 19030]          # HTTP server for openclaw (SSE streaming)
secret_proxy_ca list-slots                    # admin: list provisioned key slots
secret_proxy_ca provision-key --slot N --key sk-... --provider <name>
secret_proxy_ca remove-key --slot N
secret_proxy_ca add-whitelist --pattern <url-prefix>
secret_proxy_ca dns-test <hostname>           # TEEC-free diagnostic
secret_proxy_ca vsock-test <cid> [port]       # TEEC-free diagnostic
```

In production the daemon
([`teeproxyd`](https://github.com/TomGoh/teeproxyd)) supervises the CA —
it spawns `secret_proxy_ca serve` with the right env vars after the TEE VM is
ready, restarts on crash, exposes `/health` and the admin API. Clients POST
`SecretProxyRequest` JSON; the CA forwards through the TA and streams the
upstream SSE back.

### `serve` mode HTTP surface

| method+path                      | auth                      | purpose |
|----------------------------------|---------------------------|---------|
| `GET  /health`                   | none                      | TEEC session + TA `list_slots` probe |
| `GET  /admin/keys/slots`         | `X-Admin-Token`           | list provisioned slots |
| `POST /admin/keys/provision`     | `X-Admin-Token`           | store API key into a TA slot |
| `POST /admin/keys/remove`        | `X-Admin-Token`           | clear a TA slot |
| `POST /`  (or `/proxy`, or anything else) | none             | proxy: LLM request → TA → upstream → SSE back |

Admin endpoints are **disabled by default**. Set the env var
`SECRET_PROXY_CA_ADMIN_TOKEN` (≥32 chars) to enable them; optional
`SECRET_PROXY_CA_ADMIN_TOKEN_PREV` is the rotation window — both tokens accepted
until `_PREV` is cleared.

## Architecture

```text
src/
├── main.rs             env_logger init + cli::run
├── cli/                argv dispatch, subcommand handlers, diagnostics
├── server/             HTTP serve mode (health, admin, proxy)
│   ├── config.rs       ServerConfig (port parsing)
│   ├── connection.rs   per-connection HTTP handler
│   ├── router.rs       pure (method, path) → RouteAction
│   └── admin.rs        X-Admin-Token validation (with EnvSource trait)
├── relay/              TEEC relay state machine + I/O adapter
│   ├── core.rs         pure state machine (step() on BIZ_RELAY_* codes)
│   ├── session.rs      adapter: Teec + Upstream + client writer
│   └── upstream.rs     trait Upstream + TcpUpstream + MockUpstream
├── teec/               TEEC gateway
│   ├── mod.rs          trait Teec (invoke seam)
│   ├── real.rs         RealTeec (live TEE session, Drop closes)
│   ├── mock.rs         MockTeec (scripted responses, test-only)
│   └── ops.rs          TA command wrappers (list_slots, provision_key, ...)
├── http/               pure HTTP parser/response helpers
│   ├── headers.rs      header_value, constant_time_equal, etc.
│   ├── chunked.rs      stateful ChunkedDecoder (RFC 7230 §4.1, Lenient mode)
│   ├── request.rs      parse_request<R: BufRead>
│   └── response.rs     HttpResponse builder
├── sse/
│   ├── encoder.rs      sse_response_headers(status) — fixed preamble
│   └── parser.rs       Anthropic SSE event parser + logger
├── wire.rs             CA ↔ TA JSON DTOs (protocol-critical: field names are wire contract)
├── constants.rs        TA_UUID, CMD_* IDs, BIZ_* codes, env var names
├── error.rs            thiserror Error enum + From<Error> for String bridge
└── clock.rs            Clock trait (unused by production, ready for timeouts)
```

The `relay::` split (pure `core` + I/O `session` + trait `upstream`) is the
key architectural win — the BIZ_RELAY_* dispatch is now fully unit-testable
with 26 hand-crafted state-machine tests, plus 9 adapter tests driving
`MockTeec` + `MockUpstream`.

## Load-bearing invariants (don't break these casually)

1. **TCP_NODELAY on the client socket** — without it the kernel batches the
   40-byte `data: ...\n\n` SSE lines and openclaw's token-by-token rendering
   stalls until the next MTU accumulates. Set at the top of
   `server::connection::relay_and_stream`.

2. **`Box<TEEC_Context>` pointer stability** — `TEEC_OpenSession` stores a raw
   pointer to the context inside the session handle. If the backing storage
   moves (e.g. returning `Self { ctx, session }` by value when `ctx` is not
   boxed), that stored pointer dangles and every subsequent
   `TEEC_InvokeCommand` fails with `0xFFFF0000` (TEEC_ERROR_GENERIC, origin
   TEEC_ORIGIN_API). See `src/teec/real.rs` module docs.

3. **Pump semantics** — `BIZ_RELAY_CONTINUE` with empty `decrypted` triggers
   **exactly one** extra TA invoke with empty input. Cascading pumps deadlock
   when rustls genuinely has nothing to send. Enforced by
   `RelayState::waiting_for_pump` in `relay::core`.

4. **`"Post"` is case-sensitive in the wire** — `HttpMethod::Post` serializes
   to the literal string `"Post"`; wrappers sending `"post"` get 400-rejected.
   Regression-pinned by `format/test_proxy_format.py::test_method_lowercase_rejected`
   in the parent repo's pytest harness.

5. **ChunkedDecoder Lenient fallback** — if framing parse fails (bad hex size
   line, missing CRLF, etc.), dump the whole pending buffer as raw bytes.
   "Garbage in → garbage out" beats dropping user-visible content when
   openclaw is waiting for an SSE frame.

6. **SSE response preamble** is four fixed headers — `Content-Type:
   text/event-stream; charset=utf-8`, `Cache-Control: no-cache`,
   `Connection: close`. Anthropic SDK sniffs on the media type; `Connection:
   close` is the EOF signal (no Content-Length, no chunked).

7. **Admin error-string prefix contract** — the handler greps returned error
   strings: `"admin API disabled …"` → 503, `"invalid admin token"` → 401.
   Pytest depends on these exact prefixes.

## Build

### For Android (aarch64-linux-android, Bionic libc)

The production target. Run from the parent `openclaw-security-enhanced` repo:

```bash
bash scripts/build-ca-android.sh
# → tools/secret_proxy_ca/target/aarch64-linux-android/release/secret_proxy_ca
# Also installs into tools/tee-proxy-app/app/src/main/jniLibs/arm64-v8a/
# as libsecret_proxy_ca.so (stripped).
```

Requires `ANDROID_NDK_HOME`, `rustup target add aarch64-linux-android`, and
`cargo install cargo-ndk`. See `scripts/build-ca-android.sh` for details.

Bionic libc is required (not musl): `getaddrinfo` must go through Android's
dnsproxyd → netd path (musl reading `/etc/resolv.conf` fails on stripped
Android filesystems).

### For unit tests (Linux arm64, via orb on macOS)

```bash
# From the parent repo root
rsync -a --delete --exclude target --exclude .git \
  tools/secret_proxy_ca/ haoze@ubuntu@orb:~/openclaw-security-enhanced/tools/secret_proxy_ca/
orb -m ubuntu bash -c 'cd ~/openclaw-security-enhanced/tools/secret_proxy_ca && cargo test'
```

**Native macOS `cargo test` does not work** — `mbedtls-smx` (transitive dep
of `rust-libteec`) fails to compile on Darwin. The orb ubuntu VM is the unit
test host; device pytest is the integration gate.

## Dependency note

`Cargo.toml` pulls `cc_teec` (the `rust-libteec` crate) via relative path:

```toml
cc_teec = { package = "rust-libteec", path = "../../rust-libteec" }
```

That `../../` resolves to `<parent>/rust-libteec` — which is where
`rust-libteec` lives as a sibling submodule in the parent
`openclaw-security-enhanced` repo. **Standalone clone of just this CA repo
will not build** until that path is switched to a git dep. Non-urgent; fix
when someone needs to build the CA outside the parent repo.

## Testing

- **Rust unit tests**: 166 tests covering every pure module. Run on orb
  ubuntu as above.
- **Rust integration**: `relay::session` adapter tests + `relay::core` state
  machine tests exercise the full dispatch with `MockTeec` + `MockUpstream`.
- **Python/device harness**: lives in the **parent repo** under `tests/`.
  Smoke / format / recovery / stress suites run against a real device over
  adb. See `tests/run.sh --help` in the parent repo.

The parent repo's device pytest is the final acceptance gate for any change
that touches serve-mode wire behavior.

## Relation to parent repo

This repo is included as a **git submodule** at
`tools/secret_proxy_ca/` in
[openclaw-security-enhanced](https://gitee.com/jose47/openclaw-security-enhanced)
(the pKVM host + TEE pipeline repo). The full TEE stack (x-kernel, pvmfw,
pvm-manage, teec_cc_bridge, secret_proxy_ta, teeproxyd, this CA) lives
there; this repo is just the CA crate.

## License

Apache-2.0
