# Lightway Wireshark Plugin

`Lightway` is a lightweight VPN protocol from `ExpressVPN` that can use both UDP and TCP as underlying transport.

In Lightway/TCP mode it is a pure TLS stream and as such, Wireshark does not need any special decoding support.
Simply selecting the port the Helium server is running on and decoding it as TLS is sufficient.

Although Lightway/UDP protocol is based on D/TLS (TLS adapted for datagrams), Lightway adds its own headers to support additional features.

This means that Wireshark cannot decode Lightway/UDP traffic natively and custom plugin support is needed.

## Install steps:
1. Copy `lightway.lua` file to `~/.local/lib/wireshark/plugins` directory
1. Inside Wireshark, the packet decode as, select `LIGHTWAY-UDP` protocol.

### Note:
Wireshark's plugins directory can be found in Wireshark UI at `Help->About->Folders`

## Auto decode:
If `Lightway` server is running in a different port, update the port number in the plugin file.
Wireshark will then decode the Lightway packets automatically.

```lua
udp_port:add(40890, lightway_protocol)
```

> **Warning**
> Using this plugin on a huge packet capture file, might take long time to decode