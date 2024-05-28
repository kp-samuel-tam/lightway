# Path MTU Discovery

`Lightway` protocol supports calculating the Path MTU between server and client dynamically.

`Lightway` implements the following RFC to Path MTU calculation:

[`Packetization Layer Path MTU Discovery for Datagram Transports (RFC 8899)`](https://datatracker.ietf.org/doc/html/rfc8899)

Please refer the above RFC for the state machine.

The implementation can be found here: [dplpmtud.rs](../lightway-core/src/connection/dplpmtud.rs)


The following are the things which is notable in Lightway's implementation:

- `Lightway` uses Ping/Pong message with id != 0 as PLPMTU probe message
- `Packetization Layer` defined in the RFC is `Lightway` itself (not including DTLS or lower layers)

After calculating Path MTU, `Lightway` uses it for handling inside packets (from tunnel):

1. Update TCP MSS value in TCP SYN packets based on the PMTU value
1. Fragment UDP packets inside lightway protocol if the size is larger than PMTU,
   which will be reassembled at the other end. Ref: `lightway_core::wire::DataFrag`

At present, PMTU discovery is only enabled on client side. In future, we may enable
it in Server.

