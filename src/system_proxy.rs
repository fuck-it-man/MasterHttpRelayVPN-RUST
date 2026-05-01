//! System-level proxy configuration.
//!
//! Sets (or clears) the OS-wide proxy so every application on the machine
//! routes its HTTP/HTTPS/SOCKS5 traffic through the running mhrv-rs proxy
//! automatically — no per-app proxy configuration needed.
//!
//! Platform support:
//! * **Windows** — writes `ProxyServer` / `ProxyEnable` into
//!   `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` and
//!   broadcasts `WM_SETTINGCHANGE` so Chrome, Edge, and WinInet-based apps
//!   pick up the new settings without a restart.
//! * **macOS** — calls `networksetup` on every active network service to set
//!   the web proxy, secure web proxy, and SOCKS firewall proxy.
//! * **Linux (GNOME)** — calls `gsettings` to configure
//!   `org.gnome.system.proxy` (manual mode + per-protocol host/port).
//!
//! On unsupported platforms the set/clear functions return an `Err` string
//! rather than panicking, and `is_supported()` returns `false` so callers
//! can hide the UI control gracefully.

// ── Windows ──────────────────────────────────────────────────────────────────

#[cfg(windows)]
mod platform {
    use winreg::RegKey;
    use winreg::enums::*;

    const INET_SETTINGS: &str =
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

    pub fn set(
        http_host: &str,
        http_port: u16,
        socks_host: &str,
        socks_port: u16,
    ) -> Result<(), String> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu
            .create_subkey(INET_SETTINGS)
            .map_err(|e| format!("registry open failed: {e}"))?;

        // Format understood by WinInet / Chrome / Edge:
        // "http=host:port;https=host:port;socks=host:port"
        let proxy_str = format!(
            "http={http_host}:{http_port};https={http_host}:{http_port};socks={socks_host}:{socks_port}"
        );
        key.set_value("ProxyServer", &proxy_str)
            .map_err(|e| format!("ProxyServer write failed: {e}"))?;
        key.set_value("ProxyEnable", &1u32)
            .map_err(|e| format!("ProxyEnable write failed: {e}"))?;

        // Best-effort: notify running applications that WinInet settings changed.
        // SendMessageTimeout with WM_SETTINGCHANGE causes Chrome/Edge/IE and
        // most WinInet-based apps to reload proxy settings immediately.
        unsafe { broadcast_settings_change() };
        Ok(())
    }

    pub fn clear() -> Result<(), String> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu
            .create_subkey(INET_SETTINGS)
            .map_err(|e| format!("registry open failed: {e}"))?;
        key.set_value("ProxyEnable", &0u32)
            .map_err(|e| format!("ProxyEnable clear failed: {e}"))?;
        unsafe { broadcast_settings_change() };
        Ok(())
    }

    pub fn is_supported() -> bool {
        true
    }

    /// Broadcast `WM_SETTINGCHANGE` to `HWND_BROADCAST` so that running
    /// applications (Chrome, Edge, WinInet-based) pick up the registry change
    /// without needing a restart.
    ///
    /// SAFETY: the call is a pure Win32 message broadcast with a static string
    /// parameter. `SMTO_ABORTIFHUNG` prevents blocking for more than `timeout`
    /// milliseconds on hung windows.
    unsafe fn broadcast_settings_change() {
        #[link(name = "user32")]
        extern "system" {
            fn SendMessageTimeoutW(
                hwnd: isize,
                msg: u32,
                w_param: usize,
                l_param: isize,
                flags: u32,
                timeout: u32,
                result: *mut usize,
            ) -> isize;
        }
        const HWND_BROADCAST: isize = 0xFFFF;
        const WM_SETTINGCHANGE: u32 = 0x001A;
        const SMTO_ABORTIFHUNG: u32 = 0x0002;

        // The lParam for WM_SETTINGCHANGE is an LPCWSTR pointing at the
        // settings category that changed.
        let key: Vec<u16> = "Internet Settings\0".encode_utf16().collect();
        let mut result: usize = 0;
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            key.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            2000,
            &mut result,
        );
    }
}

// ── macOS ─────────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod platform {
    use std::process::Command;

    /// Returns the list of active network service names from `networksetup`.
    fn network_services() -> Vec<String> {
        let Ok(out) = Command::new("networksetup")
            .arg("-listallnetworkservices")
            .output()
        else {
            return Vec::new();
        };
        String::from_utf8_lossy(&out.stdout)
            .lines()
            // First line is an informational header. Lines starting with `*`
            // are disabled services — skip both.
            .filter(|l| !l.starts_with('*') && !l.contains("asterisk"))
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    }

    pub fn set(
        http_host: &str,
        http_port: u16,
        socks_host: &str,
        socks_port: u16,
    ) -> Result<(), String> {
        let services = network_services();
        if services.is_empty() {
            return Err("no active network services found via networksetup".into());
        }
        let mut errors: Vec<String> = Vec::new();
        for svc in &services {
            for (flag, host, port) in [
                ("-setwebproxy", http_host, http_port),
                ("-setsecurewebproxy", http_host, http_port),
                ("-setsocksfirewallproxy", socks_host, socks_port),
            ] {
                let status = Command::new("networksetup")
                    .args([flag, svc, host, &port.to_string()])
                    .status();
                match status {
                    Ok(s) if s.success() => {}
                    Ok(s) => errors.push(format!(
                        "networksetup {flag} on '{svc}' exited {s}"
                    )),
                    Err(e) => errors.push(format!(
                        "networksetup {flag} on '{svc}' failed: {e}"
                    )),
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    pub fn clear() -> Result<(), String> {
        let services = network_services();
        if services.is_empty() {
            return Err("no active network services found via networksetup".into());
        }
        let mut errors: Vec<String> = Vec::new();
        for svc in &services {
            for flag in [
                "-setwebproxystate",
                "-setsecurewebproxystate",
                "-setsocksfirewallproxystate",
            ] {
                let status = Command::new("networksetup")
                    .args([flag, svc, "off"])
                    .status();
                match status {
                    Ok(s) if s.success() => {}
                    Ok(s) => errors.push(format!(
                        "networksetup {flag} on '{svc}' exited {s}"
                    )),
                    Err(e) => errors.push(format!(
                        "networksetup {flag} on '{svc}' failed: {e}"
                    )),
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    pub fn is_supported() -> bool {
        // networksetup ships with macOS, always present
        true
    }
}

// ── Linux ─────────────────────────────────────────────────────────────────────

#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(target_os = "android"),
    not(target_os = "ios")
))]
mod platform {
    use std::process::Command;

    pub fn set(
        http_host: &str,
        http_port: u16,
        socks_host: &str,
        socks_port: u16,
    ) -> Result<(), String> {
        // GNOME gsettings: set manual proxy mode, then per-protocol host/port.
        let ok = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "manual"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            return Err(
                "gsettings is not available — set the proxy manually or install a GNOME desktop."
                    .into(),
            );
        }
        for (schema, key, val) in [
            (
                "org.gnome.system.proxy.http",
                "host",
                http_host.to_string(),
            ),
            (
                "org.gnome.system.proxy.http",
                "port",
                http_port.to_string(),
            ),
            (
                "org.gnome.system.proxy.https",
                "host",
                http_host.to_string(),
            ),
            (
                "org.gnome.system.proxy.https",
                "port",
                http_port.to_string(),
            ),
            (
                "org.gnome.system.proxy.socks",
                "host",
                socks_host.to_string(),
            ),
            (
                "org.gnome.system.proxy.socks",
                "port",
                socks_port.to_string(),
            ),
        ] {
            // Best-effort — if individual keys fail, the mode was already
            // set to manual so partial config is better than nothing.
            let _ = Command::new("gsettings")
                .args(["set", schema, key, &val])
                .status();
        }
        Ok(())
    }

    pub fn clear() -> Result<(), String> {
        Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "none"])
            .status()
            .map(|s| {
                if s.success() {
                    Ok(())
                } else {
                    Err(format!("gsettings exited {s}"))
                }
            })
            .unwrap_or_else(|e| Err(e.to_string()))
    }

    pub fn is_supported() -> bool {
        // Only available if gsettings is in PATH (i.e. GNOME session).
        Command::new("gsettings")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

// ── Fallback (Android, iOS, unknown) ─────────────────────────────────────────

#[cfg(not(any(
    windows,
    target_os = "macos",
    all(
        unix,
        not(target_os = "macos"),
        not(target_os = "android"),
        not(target_os = "ios")
    )
)))]
mod platform {
    pub fn set(_: &str, _: u16, _: &str, _: u16) -> Result<(), String> {
        Err("system proxy auto-set is not supported on this platform".into())
    }
    pub fn clear() -> Result<(), String> {
        Err("system proxy auto-set is not supported on this platform".into())
    }
    pub fn is_supported() -> bool {
        false
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Configure the OS system proxy so HTTP/HTTPS traffic is routed through
/// `http_host:http_port` and SOCKS5 through `socks_host:socks_port`.
///
/// This only affects applications that honour the OS proxy settings
/// (browsers, curl, etc.). Applications that ignore system settings (e.g.
/// most Electron apps) need to be configured separately, or use TUN mode.
pub fn set_system_proxy(
    http_host: &str,
    http_port: u16,
    socks_host: &str,
    socks_port: u16,
) -> Result<(), String> {
    platform::set(http_host, http_port, socks_host, socks_port)
}

/// Disable the OS system proxy that was previously set by [`set_system_proxy`].
pub fn clear_system_proxy() -> Result<(), String> {
    platform::clear()
}

/// Returns `true` if [`set_system_proxy`] / [`clear_system_proxy`] are
/// supported on this platform. The UI uses this to decide whether to show
/// the "Auto-set system proxy" checkbox.
pub fn is_supported() -> bool {
    platform::is_supported()
}
