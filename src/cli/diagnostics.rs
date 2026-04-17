//! TEEC-free diagnostic subcommands: `dns-test`, `vsock-test`.
//!
//! Both are ways to isolate a layer of the TEE stack without needing
//! a full TA / VM round trip:
//!
//! - `dns-test <host>` — resolves `host:443` via the platform's
//!   `getaddrinfo`. On Android, this verifies Bionic + dnsproxyd
//!   works before exercising the proxy. On musl builds, it catches
//!   `/etc/resolv.conf` being missing (a well-documented footgun on
//!   stripped Android filesystems).
//! - `vsock-test <cid> [port]` — `socket(AF_VSOCK) + connect((cid, port))`
//!   then close. Output is the raw errno (with a human hint) so the
//!   operator can tell apart SELinux denials from missing peers from
//!   "kernel has no vsock at all" during bring-up.
//!
//! Step 10 refactor: moved here from `main.rs` (SockaddrVm struct,
//! vsock_test/errno_hint helpers, inline dns-test block).

use std::net::ToSocketAddrs;

/// Raw `sockaddr_vm` as defined in `<linux/vm_sockets.h>`.
///
/// Not re-exported by every `libc` version on every target, so we
/// declare it locally to keep this diagnostic self-contained. Layout
/// matches the kernel ABI exactly — do not reorder fields.
#[repr(C)]
#[derive(Default)]
#[allow(non_camel_case_types)]
struct SockaddrVm {
    svm_family: libc::sa_family_t,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

/// `dns-test <host>` subcommand. Resolves `host:443` and prints the
/// result (or the error). TEEC-free.
pub(crate) fn cmd_dns_test(host: &str) -> Result<(), String> {
    let target = format!("{host}:443");
    match target.to_socket_addrs() {
        Ok(iter) => {
            let addrs: Vec<_> = iter.collect();
            if addrs.is_empty() {
                println!("{host} -> (no addresses)");
            } else {
                println!("{host} ->");
                for a in addrs {
                    println!("  {a}");
                }
            }
            Ok(())
        }
        Err(e) => Err(format!("resolve {host}: {e}")),
    }
}

/// `vsock-test <cid> [port]` subcommand. Attempts a minimal
/// `socket(AF_VSOCK) + connect((cid, port))` handshake and prints
/// exactly what the kernel returned.
pub(crate) fn cmd_vsock_test(cid: u32, port: u32) -> Result<(), String> {
    // Step 1: create the socket.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return Err(format!(
            "socket(AF_VSOCK, SOCK_STREAM, 0) failed: {e}{}",
            errno_hint(e.raw_os_error().unwrap_or(0)),
        ));
    }
    println!("✓ socket(AF_VSOCK, SOCK_STREAM, 0) → fd={fd}");

    // Step 2: connect to (cid, port). On failure we still need to
    // close the socket — capture the error first, close, then report.
    let addr = SockaddrVm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_port: port,
        svm_cid: cid,
        ..SockaddrVm::default()
    };
    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const SockaddrVm as *const libc::sockaddr,
            std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
        )
    };
    let connect_err = if rc < 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    unsafe { libc::close(fd) };

    match connect_err {
        None => {
            println!("✓ connect(cid={cid}, port={port}) → success");
            Ok(())
        }
        Some(e) => {
            let errno = e.raw_os_error().unwrap_or(0);
            Err(format!(
                "connect(cid={cid}, port={port}) failed: {e} (errno={errno}){}",
                errno_hint(errno),
            ))
        }
    }
}

/// Short human-readable hint for the most common errno values on the
/// vsock path. Keeps output actionable without grep-for-man-pages.
fn errno_hint(errno: i32) -> &'static str {
    match errno {
        libc::EACCES       => "  (SELinux denial on vsock_socket; check `dmesg | grep avc` or `logcat | grep avc`)",
        libc::EAFNOSUPPORT => "  (kernel has no AF_VSOCK support; CONFIG_VSOCKETS is missing)",
        libc::ENODEV       => "  (no vsock peer at this CID; the host VM is probably not running)",
        libc::ECONNREFUSED => "  (peer is there but nothing is listening on that port)",
        libc::ECONNRESET   => "  (peer exists and reset the connection; on VMADDR_CID_LOCAL this means kernel vsock loopback is working but no one is listening on that port — a GOOD signal about kernel support)",
        libc::ETIMEDOUT    => "  (SYN dispatched to peer but no answer — peer vsock stack is probably up and CID is registered, but no socket is in LISTEN state on that port and the peer's vsock driver is not sending RSTs for unknown destinations; in our pipeline this is the expected error when the x-kernel VM is booted but no teec_cc_bridge is running inside it)",
        libc::EPERM        => "  (operation not permitted; check process uid/capabilities)",
        libc::ENETUNREACH  => "  (network unreachable; kernel vsock configuration may be incomplete)",
        _                  => "",
    }
}
