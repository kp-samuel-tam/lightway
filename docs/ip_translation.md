# IP Address translation

Lightway client/server supports an interesting feature called IP translation.
It helps to decouple the IP address binding between client and server.
i.e Client tunnel's IP address can be different from server tunnel's IP address.

The main advantage of this translation is to use the same tunnel IP address across
all clients connected to the server. Without the translation, each client's tunnel
IP has to be in the same network and cannot overlap.

## Implementation detail

Lightway server has following CLI config (Ref: [lightway-server/src/args.rs](../lightway-server/src/args.rs)):
- `ip_pool` - internal IP network used by server to communicate with different clients.
    - If the the tunnel IP is within the pool then it can be configured with the `tun_ip` configuration option.
    - The `ip_map` option can be use to reserve specific subranges to clients connecting to a specific incoming IP
- `lightway_server_ip`, `lightway_client_ip`, `lightway_dns_ip`- These are the values which will be sent to the client in the network config message.


Lightway client has following CLI configs (Ref: [lightway-client/src/args.rs](../lightway-client/src/args.rs)):
- `tun_local_ip` - This IP address will be configured on the client tunnel interface
- `tun_peer_ip` - Virtual peer IP used as default route
- `tun_dns_ip` - Virtual DNS IP to use. This will be changed to actual DNS IP address inside the client


Due to this IP translation, even though client and server tunnel will be in different IP network, it still behaves as it is on the same network.

###   Steps during connection: 
1. Client on startup sets the configured tun_local_ip as tunnel interface IP and uses tun_peer_ip as default route (100.64.0.6)
1. Client then connects to the server, and authenticate itself
1. Once the authentication succeeded, server allocates one internal IP address to the client from its ip_pool (10.125.68.123)
1. Server then sends the static network config message based on server configuration (ex: 10.125.0.6)  Note: So essentially all clients will receive the same network config message. But each client will be mapped to a unique internal IP, which is visible only inside the server
1. Client after receiving this network config message, stores it. But it does not use it to configure the tunnel interface.   

```mermaid
block-beta
    columns 3

    block:client:1
        columns 2
        c_head["Client"]:2
        c_ping(["ping 1.2.3.4"]):2
        space:2
        c_ip("100.64.100.6"):2
        c_tun[("TUN interface")]:2
        c_pkt1[["SrcIp: 100.64.100.6
        DstIP: 1.2.3.4"]] step1(("1"))
        c_client(["lightway client"]):2
        c_pkt2[["SrcIp: 10.125.0.6
        DstIP: 1.2.3.4"]] step2(("2"))
        c_core(["lightway core"]):2
        c_pkt3[["SrcIp: 10.125.0.6
        DstIP: 1.2.3.4"]] step3(("3"))
        c_wan[("WAN interface")]:2
        space c_pkt4[["SrcIp: 10.125.0.6
        DstIP: 1.2.3.4"]]
    end

    space

    block:server:1
        columns 2
        s_head["Server"]:2
        s_nat(["SNAT"]):2
        space:2
        s_ip("10.125.0.1"):2
        s_tun[("TUN interface")]:2
        step6(("6")) s_pkt1[["SrcIp: 10.125.68.123
        DstIP: 1.2.3.4"]]
        s_server(["lightway server"]):2
        step5(("5")) s_pkt2[["SrcIp: 10.125.0.6
        DstIP: 1.2.3.4"]]
        s_core(["lightway core"]):2
        step4(("4")) s_pkt3[["SrcIp: 10.125.0.6
        DstIP: 1.2.3.4"]]
        s_wan[("WAN interface")]:2
        s_pkt4[["SrcIp: 10.125.0.6
        DstIP: 1.2.3.4"]] space
    end


    c_ping-->c_ip
    c_tun-->c_client
    c_client-->c_core
    c_core-->c_wan

    s_wan-->s_core
    s_core-->s_server
    s_server-->s_tun
    s_ip-->s_nat

    c_wan<-- "WAN" -->s_wan
    s_wan<-- "WAN" -->c_wan

    style c_tun fill:teal,,color:silver,stroke:silver
    style s_tun fill:teal,,color:silver,stroke:silver
    style c_pkt3 fill:green,color:gainsboro,stroke:gainsboro
    style c_pkt4 fill:green,color:gainsboro,stroke:gainsboro
    style s_pkt3 fill:green,color:gainsboro,stroke:gainsboro
    style s_pkt4 fill:green,color:gainsboro,stroke:gainsboro
    style c_head fill:transparent
    style s_head fill:transparent
    style c_ip fill:transparent,stroke:transparent
    style s_ip fill:transparent,stroke:transparent
    style step1 fill:yellow,color:black
    style step2 fill:yellow,color:black
    style step3 fill:yellow,color:black
    style step4 fill:yellow,color:black
    style step5 fill:yellow,color:black
    style step6 fill:yellow,color:black

```

### Packet flow steps (as marked yellow in above picture):
1. When we start a ping from the client device to an IP say 1.2.3.4, client OS creates a ICMP packet with src IP as tunnel IP and destination IP as actual desctination (since default route will be pointing towards tunnel) and sends the packet to the tunel interface.
1. ICMP packet will then be received by the LightwayClient. It then updates the source IP of the ICMP packet to tun_local_ip from server's network config message. The packet is then passed to lightway-core
1. Lightway-core then encapsulates the ICMP packet inside TLS/DTLS connection and forwards it to Lightway-server device
1. Lightway-core on receiving the packet, decapsulates the packet and try to forward the packet to server's tunnel interface
1. Server which provides the tun_write modifies the source IP address of ICMP packet to internal IP assigned to this client
1. The source IP of the ICMP is now within the server tunnel IP network. So the packet will be SNATted to the internet


Note: The steps will be reversed in the return packet flow from server to client.
