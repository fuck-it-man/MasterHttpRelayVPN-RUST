//! Desktop TUN-mode VPN.
//!
//! Creates a virtual TUN network adapter that captures **all** IP traffic on
//! the machine and funnels it through the local SOCKS5 proxy. Unlike the
//! system-proxy approach, TUN mode works with every application — including
//! those that ignore OS proxy settings — because the interception happens at
//! the IP layer before the app's network stack even sees a packet.
//!
//! Implementation
//! --------------
//! Uses `tun2proxy` (the same crate as the Android VpnService path) with its
//! built-in `--setup` flag that:
//!   1. Creates a named TUN/TAP adapter (`mhrv_tun` on Windows / macOS /
//!      Linux).
//!   2. Installs the necessary routing-table rules so that all traffic flows
//!      through the adapter.
//!   3. Restores the original routing state when the adapter is torn down
//!      (implemented via the `TproxyState` drop guard inside tun2proxy).
//!
//! On **Windows** the WinTun kernel driver (`wintun.dll`) must be present in
//! the same directory as the binary or on `PATH`. Download it from
//! <https://www.wintun.net/>. The app will show an actionable error if the
//! DLL is missing.
//!
//! Privilege requirements
//! -----------------------
//! * Windows — the process must be running as Administrator.
//! * macOS / Linux — the process must be running as root (or have
//!   `CAP_NET_ADMIN`).
//!
//! The `is_elevated()` helper lets callers check before attempting to start.

#![cfg(not(target_os = "android"))]

use std::net::{IpAddr, SocketAddr};

use tokio_util::sync::CancellationToken;
use tun2proxy::{ArgDns, ArgProxy, ArgVerbosity, Args, ProxyType, general_run_async};
use tproxy_config::IpCidr;

/// A running TUN session.
///
/// Dropping this value does **not** stop the TUN — call [`TunSession::stop`]
/// to cancel the underlying task and wait for cleanup to complete.
pub struct TunSession {
    token: CancellationToken,
    /// Stored so the caller can `.await` clean shutdown.
    pub handle: tokio::task::JoinHandle<Result<(), String>>,
}

impl TunSession {
    /// Cancel the TUN task and wait (with a short timeout) for it to finish
    /// cleaning up routing state.
    pub async fn stop(self) {
        self.token.cancel();
        // Allow up to 3 s for tproxy cleanup (route removal) before giving up.
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            self.handle,
        )
        .await;
    }
}

/// Name of the TUN adapter created by mhrv-rs.
pub const TUN_NAME: &str = "mhrv_tun";

/// Start the TUN-mode VPN.
///
/// * `socks5_addr` — the local SOCKS5 proxy that tun2proxy should forward
///   captured traffic into.
/// * `bypass_ip` — an optional remote IP that should **not** be tunnelled
///   (typically the `google_ip` that our SOCKS5 proxy connects to directly,
///   to avoid a routing loop).
///
/// Returns a [`TunSession`] whose `handle` is a Tokio task that runs until
/// cancelled or until tun2proxy exits on its own (error path).
///
/// # Errors
/// Returns `Err` if the TUN adapter could not be created (e.g. missing
/// `wintun.dll` on Windows, or insufficient privileges).
pub fn start_tun(
    socks5_addr: SocketAddr,
    bypass_ip: Option<IpAddr>,
) -> TunSession {
    let token = CancellationToken::new();
    let token_clone = token.clone();

    let handle = tokio::spawn(async move {
        run_tun_inner(socks5_addr, bypass_ip, token_clone).await
    });

    TunSession { token, handle }
}

async fn run_tun_inner(
    socks5_addr: SocketAddr,
    bypass_ip: Option<IpAddr>,
    shutdown_token: CancellationToken,
) -> Result<(), String> {
    let proxy = ArgProxy {
        proxy_type: ProxyType::Socks5,
        addr: socks5_addr,
        credentials: None,
    };

    let mut args = Args::default();
    args.proxy(proxy)
        .dns(ArgDns::OverTcp)
        .verbosity(ArgVerbosity::Warn)
        .tun(TUN_NAME.to_string())
        .setup(true);

    // Bypass private / loopback ranges so our SOCKS5 proxy can reach them
    // directly without being re-tunnelled, and so LAN traffic isn't disrupted.
    for cidr_str in [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
    ] {
        if let Ok(cidr) = cidr_str.parse::<IpCidr>() {
            args.bypass(cidr);
        }
    }

    // Bypass the explicit upstream IP (e.g. google_ip) that our SOCKS5 proxy
    // connects to — tunnelling it again would create a routing loop.
    if let Some(ip) = bypass_ip {
        let cidr_str = format!("{ip}/32");
        if let Ok(cidr) = cidr_str.parse::<IpCidr>() {
            args.bypass(cidr);
        }
    }

    general_run_async(args, tun2proxy::DEFAULT_MTU, false, shutdown_token)
        .await
        .map(|_sessions| ())
        .map_err(|e| e.to_string())
}

/// Returns `true` if the process appears to be running with the privileges
/// required to create TUN devices and modify routing tables.
///
/// This is a best-effort heuristic — it does not guarantee that TUN will
/// succeed (e.g. `wintun.dll` missing on Windows would still cause an error
/// even when elevated).
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        is_elevated_windows()
    }
    #[cfg(unix)]
    {
        // SAFETY: getuid() is always safe to call.
        unsafe { libc::getuid() == 0 }
    }
    #[cfg(not(any(windows, unix)))]
    {
        false
    }
}

#[cfg(windows)]
fn is_elevated_windows() -> bool {
    // Attempt to open a protected registry key for writing. If we can, we are
    // running as an Administrator. Avoids pulling in extra crates for a token
    // check.
    use winreg::RegKey;
    use winreg::enums::*;
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(
            "SYSTEM\\CurrentControlSet\\Services",
            KEY_WRITE,
        )
        .is_ok()
}
