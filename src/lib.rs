#![allow(dead_code)]

pub mod cache;
pub mod cert_installer;
pub mod config;
pub mod data_dir;
pub mod domain_fronter;
pub mod mitm;
pub mod proxy_server;
pub mod rlimit;
pub mod system_proxy;
pub mod tunnel_client;
pub mod scan_ips;
pub mod scan_sni;
pub mod test_cmd;
pub mod update_check;

/// Desktop TUN-mode VPN (not compiled for Android — Android uses VpnService).
#[cfg(not(target_os = "android"))]
pub mod tun_mode;

#[cfg(target_os = "android")]
pub mod android_jni;
