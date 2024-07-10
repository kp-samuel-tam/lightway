use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::CommandFactory;
use lightway_core::{Event, EventCallback};
use twelf::reexports::log::error;
use twelf::Layer;

use lightway_app_utils::{args::ConnectionType, is_file_path_valid, TunConfig};
use lightway_client::*;

mod args;
use args::Config;

struct EventHandler;

impl EventCallback for EventHandler {
    fn event(&self, event: lightway_core::Event) {
        if let Event::StateChanged(state) = event {
            tracing::debug!("State changed to {:?}", state);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Config::command().get_matches();

    // Fetch the config filepath from CLI and load it as config
    let Some(config_file) = matches.get_one::<PathBuf>("config_file") else {
        return Err(anyhow!("Config file not present"));
    };

    if !is_file_path_valid(config_file) {
        let error_string = format!("Config file {:?} not present", &config_file);
        error!("{}", &error_string);
        return Err(anyhow!(error_string));
    }

    let config = Config::with_layers(&[
        Layer::Yaml(config_file.to_owned()),
        Layer::Env(Some(String::from("LW_CLIENT_"))),
        Layer::Clap(matches),
    ])?;

    tracing_subscriber::fmt()
        .with_max_level(config.log_level)
        .init();

    let auth = AuthMethod::UserPass {
        user: config.user,
        password: config.password,
    };

    let mode = match config.mode {
        ConnectionType::Tcp => ClientConnectionType::Stream(None),
        ConnectionType::Udp => ClientConnectionType::Datagram(None),
    };

    let root_ca_cert = RootCertificate::PemFileOrDirectory(&config.ca_cert);

    let tun = TunConfig::Name(config.tun_name);

    let config = ClientConfig {
        mode,
        auth,
        root_ca_cert,
        outside_mtu: config.outside_mtu,
        inside_mtu: config.inside_mtu,
        tun,
        tun_local_ip: config.tun_local_ip,
        tun_peer_ip: config.tun_peer_ip,
        tun_dns_ip: config.tun_dns_ip,
        cipher: config.cipher,
        #[cfg(feature = "postquantum")]
        enable_pqc: config.enable_pqc,
        keepalive_interval: config.keepalive_interval.into(),
        keepalive_timeout: config.keepalive_timeout.into(),
        sndbuf: config.sndbuf,
        rcvbuf: config.rcvbuf,
        enable_pmtud: config.enable_pmtud,
        #[cfg(feature = "io-uring")]
        enable_tun_iouring: config.enable_tun_iouring,
        #[cfg(feature = "io-uring")]
        iouring_entry_count: config.iouring_entry_count,
        server_dn: config.server_dn,
        server: config.server,
        inside_plugins: Default::default(),
        outside_plugins: Default::default(),
        exit_on_ctrlc: true,
        event_handler: Some(EventHandler),
        #[cfg(feature = "debug")]
        keylog: config.keylog,
    };

    client(config).await
}
