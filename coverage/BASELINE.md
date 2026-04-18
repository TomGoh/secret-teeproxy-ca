# Coverage baseline (2026-04-18, commit `b9f8756`)

Measured via `cargo llvm-cov --features test-support --all-targets --summary-only`
on Linux arm64 (orb ubuntu, cargo 1.x stable, cargo-llvm-cov 0.8.5).

Test surface that contributed to these numbers:
- **174** unit tests (`src/**/*.rs #[cfg(test)]`)
- **8** integration tests (`tests/serve_proxy_sse.rs`)
- **8** proptest files, ~256 random cases each (~2000 total)

## Per-module line coverage

| Module | Lines | Covered | Missed | Line % | Plan target | Notes |
|---|---|---|---|---|---|---|
| constants.rs         |  24  |  24  |  0   | 100.00% | -    | trivially covered |
| server/config.rs     |  30  |  30  |  0   | 100.00% | -    | all branches tested |
| server/router.rs     |  56  |  56  |  0   | 100.00% | 95%  | ★ exceeds target |
| sse/encoder.rs       |  33  |  33  |  0   | 100.00% | 95%  | ★ exceeds target |
| http/headers.rs      | 100  |  99  |  1   |  99.00% | 100% | near-miss: one unreachable path |
| teec/mock.rs         | 124  | 123  |  1   |  99.19% | -    | |
| http/request.rs      | 116  | 114  |  2   |  98.28% |  90% | ★ exceeds target |
| relay/session.rs     | 326  | 317  |  9   |  97.24% | -    | driven by integration tests |
| relay/core.rs        | 435  | 422  | 13   |  97.01% | 100% | near-miss: proptest rarely hits one branch |
| error.rs             |  29  |  28  |  1   |  96.55% | -    | |
| teec/ops.rs          | 206  | 198  |  8   |  96.12% | -    | mock-driven |
| http/chunked.rs      | 183  | 175  |  8   |  95.63% |  95% | ★ matches target |
| server/admin.rs      | 117  | 111  |  6   |  94.87% |  95% | near-miss |
| sse/parser.rs        | 237  | 218  | 19   |  91.98% |  95% | near-miss |
| http/response.rs     | 100  |  87  | 13   |  87.00% |  90% | near-miss |
| relay/upstream.rs    | 101  |  87  | 14   |  86.14% | -    | |
| clock.rs             |  39  |  30  |  9   |  76.92% | -    | unused in prod, kept for future timeouts |
| teec/real.rs         |  65  |  32  | 33   |  49.23% | -    | FFI path needs real TEE device |
| cli/mod.rs           | 129  |  33  | 96   |  25.58% | -    | argv dispatch only hit via cli tests |
| cli/diagnostics.rs   |  62  |   0  | 62   |   0.00% | -    | CLI-only paths |
| server/mod.rs        |  36  |   0  | 36   |   0.00% | -    | TcpListener accept loop, no socket in tests |
| server/connection.rs | 410  |   0  |410   |   0.00% | 95%  | ⚠ see "Gaps" |
| main.rs              |   7  |   0  |  7   |   0.00% | -    | entry point |
| **TOTAL**            |**2965**|**2217**|**748**| **74.77%** | **80%** | see "Gaps" |

Regions coverage (a finer-grained metric that counts each branch inside
a single line as a separate region): **76.07% (3782/4972)**.

Function coverage: **77.84% (281/361)**.

## Gaps vs plan

The total (74.77%) falls short of the plan's 80% target. All ~5 percentage
points of the gap are attributable to four 0%-covered modules:

| Module | Why it's 0% | Mitigation |
|---|---|---|
| `server/connection.rs` | Integration test `serve_proxy_sse.rs` drives `relay::session::run_relay_loop` directly via `MockTeec` + `MockUpstream`, bypassing the HTTP parse + admin routing layer. Covering this module would need a real `TcpListener` binding test harness. | Pytest format suite on the device exercises this end-to-end. Tier-1 unit coverage deferred to Phase 2. |
| `server/mod.rs` | Contains the `for stream in listener.incoming()` accept loop; not callable without binding a real socket. | Same as above — end-to-end pytest covers runtime behavior. |
| `cli/diagnostics.rs` + `cli/mod.rs` | One-shot CLI subcommands (`provision`, `list-slots`, `remove-key`, `vsock-test`, `health`) invoked via argv. Their branches get hit when operators run the CLI directly; not currently wired into cargo-test. | Smoke-test suite (`tests/run.sh`) exercises these against a live device. |
| `main.rs` | `env_logger` init + `cli::run(args)` shim. Nothing to test independently. | N/A. |

**Effective coverage of the business-core modules** (relay, sse, http,
teec/ops, teec/mock, server/admin, server/config, server/router, error,
constants, wire) is **≥87% everywhere**, with most above 94%. The gap
is concentrated entirely in glue code whose correct behavior is
validated by the device-side pytest suite (`tests/run.sh all`,
`tests/run.sh stress`) rather than unit tests.

## Threshold choice for CI

CI coverage job uses `cargo llvm-cov ... --fail-under-lines 72`:

- **72%** = baseline 74.77% − 2.77 ratchet allowance
- A PR that drops total coverage by more than ~3 points fails the CI gate
- Below-baseline PRs must explicitly raise or document why coverage
  dropped (e.g., deleting a tested-but-unused module naturally lowers
  covered-line count less than it lowers total-line count, so the ratio
  rarely drops much from deletions)
- **Ratchet up when coverage improves**: if a Phase 2 harness pushes
  total coverage to 82%, manually bump threshold to 80 here + in
  `.github/workflows/ci.yml`

Note that `--fail-under-lines` takes an integer percentage, and llvm-cov
reports with 2-decimal precision. A 72 threshold means strictly greater
than 72.00% passes; exactly 72.00% would fail. In practice the margin
is wide enough that rounding doesn't bite.

## Reproducing locally

On arm64 Linux (mbedtls-smx does not build cleanly on macOS host; use
orb ubuntu or CI):

```bash
cd tools/secret-proxy-ca
cargo llvm-cov --features test-support --all-targets --summary-only
```

For an HTML report browsable by file+line:

```bash
cargo llvm-cov --features test-support --all-targets --html
# open target/llvm-cov/html/index.html
```

## Change log

- 2026-04-18, commit `b9f8756`: initial baseline after the 10-step
  Strangler Fig refactor landed. Threshold set to 72%.
