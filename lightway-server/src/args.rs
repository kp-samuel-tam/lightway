use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use clap::Parser;
use ipnet::Ipv4Net;
use twelf::config;

use lightway_app_utils::args::{ConnectionType, Duration, LogFormat, LogLevel};

#[config]
#[derive(Parser, Debug)]
#[clap(about = "A lightway server")]
pub struct Config {
    /// Config File to load
    #[clap(short, long)]
    pub config_file: PathBuf,

    /// Connection mode
    #[clap(short, long, value_enum, default_value_t=ConnectionType::Tcp)]
    pub mode: ConnectionType,

    /// Username for auth
    #[clap(long, default_value_t)]
    pub user: String,

    /// Password for auth
    #[clap(long, default_value_t)]
    pub password: String,

    /// Server certificate
    #[clap(long, default_value = "./server.crt")]
    pub server_cert: PathBuf,

    /// Server key
    #[clap(long, default_value = "./server.key")]
    pub server_key: PathBuf,

    /// Tun device name to use
    #[clap(long, default_value = "lightway")]
    pub tun_name: String,

    /// IP pool to assign clients
    #[clap(long, default_value = "10.125.0.0/16")]
    pub ip_pool: Ipv4Net,

    /// The IP assigned to the Tun device. This must be within
    /// `ip_pool`. Default is to use the first address in `ip_pool`.
    #[clap(long)]
    pub tun_ip: Option<Ipv4Addr>,

    /// Server IP to send in network_config message
    #[clap(long, default_value = "10.125.0.6")]
    pub lightway_server_ip: Ipv4Addr,

    /// Client IP to send in network_config message
    #[clap(long, default_value = "10.125.0.5")]
    pub lightway_client_ip: Ipv4Addr,

    /// DNS IP to send in network_config message
    #[clap(long, default_value = "10.125.0.1")]
    pub lightway_dns_ip: Ipv4Addr,

    /// Enable Post Quantum Crypto
    #[clap(long, default_value_t)]
    pub enable_pqc: bool,

    /// Enable IO-uring interface for Tunnel
    #[clap(long, default_value_t)]
    pub enable_tun_iouring: bool,

    /// IO-uring submission queue count. Only applicable when
    /// `enable_tun_iouring` is `true`
    // Any value more than 1024 negatively impact the throughput
    #[clap(long, default_value_t = 1024)]
    pub iouring_entry_count: usize,

    /// Log format
    #[clap(long, value_enum, default_value_t = LogFormat::Full)]
    pub log_format: LogFormat,

    /// Log level to use
    #[clap(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    /// The key update interval for DTLS/TLS 1.3 connections
    #[clap(long, default_value = "15m")]
    pub key_update_interval: Duration,

    /// Address to listen to
    #[clap(long, default_value = "0.0.0.0:27690")]
    pub bind_address: SocketAddr,

    /// Enable WolfSSL debug logging
    #[cfg(feature = "debug")]
    #[clap(long)]
    pub tls_debug: bool,
}
