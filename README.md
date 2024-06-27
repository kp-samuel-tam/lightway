# Lightway

Lightway is a modern VPN protocol in Rust, to deliver a VPN experience that’s faster, more secure, and more reliable.

## Structure

This repository contains multiple crates as follows:

 - lightway-core - Core VPN protocol library
 - lightway-client - Client application
 - lightway-server - Server application

In addition there is:

 - tests - dev and e2e test infrastructure

## Documentation

Protocol and design documentation can be found in the
[`docs`](docs/README.md) folder.


## Supported platforms

Lightway rust implementation currently supports Linux OS. Both x86_64 and arm64 platforms are
supported and built as part of CI.

Support for other platforms will be added soon.

## Development steps

Lightway core and reference applications can be built using [Earthly](https://github.com/earthly/earthly)
without setting up the complete development environment locally.

Refer to [Earthly](https://docs.earthly.dev/) documentation on how to install earthly.

```bash
earthly +build
```

For running unit-tests,

```bash
earthly +test
```

To format code:
```bash
cargo fmt
```

For more information about the different Earthly targets available, run:
```bash
earthly doc
```

Note: Lightway can also be built using standard cargo tools

## Configuration

### Lightway-server

`Lightway-server` can be configured using config-file as follows:

```bash
lightway-server --config-file './tests/server/server_config.yaml'
```

[Example config file](./tests/server/server_config.yaml):

We can also override configs (except config-file), either by using env variables or by using cli arguments.
Env variables should have the prefix `LW_SERVER_`.
Cli arguments has the highest priority.

Please note that when providing env variables it should be in upper case and using "_" as a word separator,
while using as cli config, it should be in lower case with "-" as the word separator.

#### Example:

```bash
LW_SERVER_LOG_LEVEL=trace lightway-server --config-file './tests/server/server_config.yaml'
```
The above command loads the config file and then overrides the log_level from env variable to `trace` level.

```bash
LW_SERVER_LOG_LEVEL=trace lightway-server --config-file './tests/server/server_config.yaml' --log-level=off
```
The above command loads the config file and then overrides the log_level from cli args to `off` level.
Since cli arguments have the highest priority, env variable config will be ignored.

### Lightway-client

`Lightway-client` can also be configured using config-file similar to `Lightway-server` as follows:

```bash
lightway-client --config-file './tests/client/client_config.yaml'
```

[Example config file](./tests/client/client_config.yaml):

Lightway-client also supports overriding the config using either env variables or cli arguments.
Env variables should have the prefix `LW_CLIENT_`.

By default the client will use the existing MTU on the tunnel device, this can be overridden with
the `--inside-mtu` option but note that this requires additional privileges, specifically the
`CAP_SYS_ADMIN` capability.

## E2E Testing

To run all e2e tests:
```bash
earthly --allow-privileged +e2e
```

Or to run a single e2e test:
```bash
earthly --allow-privileged ./tests+run-tcp-test
```

Check `tests/Earthfile` or `earthly doc ./tests` for other `run-*-test` targets.

To start the stack for your own testing:
```bash
earthly -P ./tests/+save-all-test-containers  && SERVER_ARGS="--config-file server_config.yaml" CLIENT_ARGS="--config-file client_config.yaml" docker compose -f tests/e2e/docker-compose.yml up
```

Then you can use e.g.

```
docker compose -f tests/e2e/docker-compose.yml exec client bash
```

To run things within the containers

## Contributing

We appreciate feedback and contribution to this repository! Before you get started, please see link:

[CONTRIBUTING](./CONTRIBUTING.adoc)

## Reporting a vulnerability

To report security vulnerabilities, please see section on link:

[Reporting a vulnerability](SECURITY.adoc#reporting-a-vulnerability)

## Dev-Testing

For running both client and server in the same machine and test end to end, follow this steps:

```bash
sudo ./tests/setup.sh
```

The above script by default creates four network namespaces:
    - lightway-server
    - lightway-middle
    - lightway-client
    - lightway-remote

The lightway-remote namespace simulates "The Internet". Run any services which you'd like the client to access over the tunnel here.

The lightway-middle namespace facilitates a multi-hop network path: client <-> middle <-> server. Settings can be modified in the middle namespace to simulate interesting network conditions (e.g. lower path MTU, see below)

Start server using this command,
```bash
cargo build --bin lightway-server && sudo -E ip netns exec lightway-server ./target/debug/lightway-server --config-file './tests/server_config.yaml'
```

Start client using this command,
```bash
cargo build --bin lightway-client && sudo -E ip netns exec lightway-client ./target/debug/lightway-client --config-file './tests/client_config.yaml' --server server:27690
```

Then enter into `lightway-client` namespace and trying pinging google.com
```bash
sudo ip netns exec lightway-client bash
ping google.com -c 3
```

Verify `wan` interface in `lightway-remote` namespace receiving the packet and replying:
```bash
sudo ip netns exec lightway-remote bash
tcpdump -i wan -nvvl
```

Run `wireshark` within a network namespace:
```bash
sudo -E ip netns exec lightway-client su -c wireshark $USER
```

Change the client's source address:
```bash
sudo ip netns exec lightway-client ip addr add 192.168.0.3/24 dev veth
sudo ip netns exec lightway-client ip addr del 192.168.0.2/24 dev veth
```

To cleanup the test setup after testing, use
```bash
sudo ./tests/setup.sh delete
```
> Note: This will work only on linux machine with kernel supporting network namespaces.
> And sudo permission is required to run all netns commands

To setup multiple additional namespaces:
```bash
sudo env EXTRA_CLIENTS=3 ./tests/setup.sh
```

Will create `lightway-client1`, `lightway-client2` and
`lightway-client3` in addition to the base `lightway-client`.

To test Path MTU Discovery (UDP only) you can set the second hop MTU
with e.g.

```bash
sudo ip netns exec lightway-middle ip link set mtu 1300 dev veth-s2m
sudo ip netns exec lightway-server ip link set mtu 1300 dev veth-s2m
```

## Speeding up development with Earthly Satellites

Please refer to [official documentation for Earthly Satellites](https://docs.earthly.dev/earthly-cloud/satellites).

If you are a member of ExpressVPN, you can get access to the same Earthly organization used in our CI. The organization is named `expressvpn`, inside which contains a satellite named `lightway`.

If you are not a member of ExpressVPN, you may set up your own Earthly satellite according the official instructions above.

## Debugging

### Decrypting TLS1.3 data packets

`Lightway-client` supports creating a keylog file, which can be used in Wireshark for decrypting the TLS1.3 data traffic.
Note that this is supported only with feature `debug` enabled.

For example:

```bash
cargo run --features debug --bin lightway-client
./target/debug/lightway-client --config-file=tests/client_conf.yaml --keylog "/tmp/client.log"

```

The resulting file can then be exported to Wireshark to decrypt data traffic. The following wireshark documentations explains about exporting keylog file:

https://www.wireshark.org/docs/wsug_html_chunked/ChIOExportSection.html#ChIOExportTLSSessionKeys
https://wiki.wireshark.org/TLS#using-the-pre-master-secret
