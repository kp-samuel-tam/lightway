# UDP Session ID Rotation

The Lightway UDP protocol includes a wire header which contains
Session ID in order to support clients floating between networks.

To improve privacy and security for users an application may choose to
rotate that UDP session ID by calling
`Connection::rotate_session_id()`.

Interesting opportunities to do so are:

* After recovering a floated session i.e. after a client network
  change.
* After updating TLS keys.

### Case 1: Rotation with no network change

The simple case where the client address does not change.

```mermaid
sequenceDiagram
    participant Server
    participant Client

    Note over Client: Address: 192.168.100.43
    Client->>Server: Src: 192.168.100.43, Session: A
    Note over Server: Lookup Connection by peer addr 192.168.100.43 ✅<br/>---------<br/>Begin Rotation<br/>Pending Session ← B
    activate Server
    Server->>+Client: Dst: 192.168.100.43, Session: B
    deactivate Client
    Note over Client: Accept new Session:<br/>Session ← B
    Client->>Server: Src: 192.168.100.43, Session: B
    Note over Server: Lookup Connection by peer addr 192.168.100.43 ✅<br/>---------<br/>Since "B = Pending Session B" finalize rotation:<br/>Session ← B<br/>Pending Session ← None
    deactivate Server
    Server->>Client: Dst: 192.168.100.43, Session: B
```

### Case 2: Rotate after client network change

The case where the client network change precipitates the session
rotation.

```mermaid
sequenceDiagram
    participant Server
    participant Client

    Note over Client: Address: 192.168.100.43
    Client->>Server: Src: 192.168.100.43, Session: A
    Note over Client: Network Change:<br/>Address ← 10.1.2.3
    Client->>Server: Src: 10.1.2.3, Session: A
    Note over Server: Lookup Connection by peer addr 10.1.2.3 ❌
    Note over Server: Lookup Connection by Session A ✅<br/>Peer Addr ← 10.1.2.3<br/>---------<br/>Begin Rotation<br/>Pending Session ← B
    activate Server
    Server->>+Client: Dst: 10.1.2.3, Session: B
    deactivate Client
    Note over Client: Accept new Session:<br/>Session ← B
    Client->>Server: Src: 10.1.2.3, Session: B
    Note over Server: Lookup Connection by peer addr 10.1.2.3 ✅<br/>---------<br/>Since "B = Pending Session B" finalize rotation:<br/>Session ← B<br/>Pending Session ← None
    deactivate Server
    Server->>Client: Dst: 10.1.2.3, Session: B
```

### Case 3: Client network change in middle of rotation

A session rotation is in flight (case 1 or 2) but a client network
change happens in the middle.

```mermaid
sequenceDiagram
    participant Server
    participant Client

    Note over Client: Address: 192.168.100.43
    Client->>Server: Src: 192.168.100.43, Session: A
    Note over Server: Lookup Connection by peer addr 192.168.100.43 ✅<br/>---------<br/>Begin Rotation<br/>Pending Session ← B
    activate Server
    Server->>+Client: Dst: 192.168.100.43, Session: B
    deactivate Client
    Note over Client: Accept new Session:<br/>Session ← B
    Note over Client: Network Change:<br/>Address ← 10.1.2.3
    Client->>Server: Src: 10.1.2.3, Session: B
    Note over Server: Lookup Connection by peer addr 10.1.2.3 ❌
    Note over Server: Lookup Connection by Session B ❌
    Note over Server: Lookup Connection by Pending Session B ✅<br/>Peer Addr ← 10.1.2.3<br/>---------<br/>Since "B = Pending Session B" finalize rotation:<br/>Session ← B<br/>Pending Session ← None
    deactivate Server
    Server->>Client: Dst: 10.1.2.3, Session: B
```

### Case 4: Raciness

Client generates new traffic before observing a rotation.

```mermaid
sequenceDiagram
    participant Server
    participant Client

    Note over Client: Address: 192.168.100.43
    Client->>Server: Src: 192.168.100.43, Session: A
    Note over Server: Lookup Connection by peer addr 192.168.100.43 ✅
    activate Server
    note over Server: Begin Rotation<br/>Pending Session ← B
    Server->>+Client: Dst: 192.168.100.43, Session: B
    Client->>Server: Src: 192.168.100.43, Session: A
    Note over Server: Lookup Connection by peer addr 192.168.100.43 ✅<br/>---------<br/>Since "A ≠ Pending Session B" do not finalize rotation
    Note over Client: Accept new Session:<br/>Session ← B
    deactivate Client
    Client->>Server: Src: 192.168.100.43, Session: B
    Note over Server: Lookup Connection by peer addr 192.168.100.43 ✅<br/>---------<br/>Since "B = Pending Session B" finalize rotation:<br/>Session ← B<br/>Pending Session ← None
    deactivate Server
    Server->>Client: Dst: 192.168.100.43, Session: B
```

### Case 5: Raciness + Network change

Client generates new traffic before observing a rotation but after a
network change.

```mermaid
sequenceDiagram
    participant Server
    participant Client

    Note over Client: Address: 192.168.100.43
    Client->>Server: Src: 192.168.100.43, Session: A
    Note over Server: Lookup Connection by peer addr 192.168.100.43 ✅
    activate Server
    note over Server: Begin Rotation<br/>Pending Session ← B
    Server->>+Client: Dst: 192.168.100.43, Session: B
    Note over Client: Network Change:<br/>Address ← 10.1.2.3
    Client->>Server: Src: 10.1.2.3, Session: A
    Note over Server: Lookup Connection by peer addr 10.1.2.3 ❌
    Note over Server: Lookup Connection by Session A ✅<br/>---------<br/>Since "A ≠ Pending Session B" do not finalize rotation
    Note over Client: Accept new Session:<br/>Session ← B
    deactivate Client
    Client->>Server: Src: 10.1.2.3, Session: B
    Note over Server: Lookup Connection by peer addr 10.1.2.3 ❌
    Note over Server: Lookup Connection by Session B ❌
    Note over Server: Lookup Connection by Pending Session B ✅<br/>Peer Addr ← 10.1.2.3<br/>---------<br/>Since "B = Pending Session B" finalize rotation:<br/>Session ← B<br/>Pending Session ← None
    deactivate Server
    Server->>Client: Dst: 10.1.2.3, Session: B
```


