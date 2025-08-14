# Parallel Connect

Parallel connect allows the client to connect to multiple servers simultaneously and select the best one, improving reliability and reducing connection time.

## Overview

The client:
1. Launches connections to all servers simultaneously
2. Waits for first connection to reach `State::Online`
3. Optionally waits for more connections (`preferred_connection_wait_interval`)
4. Selects best connection by priority order
5. Terminates unused connections

## Configuration

### Multiple Server Configuration

Servers are configured as an array in the client configuration file:

```yaml
servers:
  - server: primary.example.com:443
    mode: tcp
    server_dn: primary.example.com
    cipher: aes256
  - server: backup.example.com:443
    mode: tcp
    server_dn: backup.example.com
    cipher: aes256
```

Server options:
- `server`: Address (`hostname:port`)
- `mode`: `tcp` or `udp`
- `server_dn`: Domain name for TLS validation
- `cipher`: Encryption cipher

### Backward Compatibility

The parallel connect feature is fully backward compatible with existing configurations:

#### Single Server Fallback

If the `servers` array is empty or not provided, the client automatically falls back to using the legacy single-server configuration parameters:

```yaml
# Legacy single-server configuration (still supported)
server: example.com:443
mode: tcp
server_dn: example.com
cipher: aes256
tun_name: lightway
tun_local_ip: 100.64.0.6
tun_peer_ip: 100.64.0.5
tun_dns_ip: 100.64.0.1
```

This ensures existing deployments continue to work without modification.

#### Mixed Configuration Handling

The client prioritizes the `servers` array when present. If both `servers` and legacy parameters are provided, the legacy parameters are ignored:

```yaml
# This configuration uses only the servers array
servers:
  - server: primary.example.com:443
    mode: tcp
    server_dn: primary.example.com
    cipher: aes256

# These legacy parameters are ignored when servers array is present
server: ignored.example.com:443
mode: udp
server_dn: ignored.example.com
```


### Preferred Connection Wait Interval

The `preferred_connection_wait_interval` setting controls how long to wait for preferred (or first connection in servers array) connection, before selecting the best connection:

```yaml
preferred_connection_wait_interval: 2s  # Wait 2 seconds for preferred connection
```

- **0s** (default): Select the first connection that comes online immediately
- **> 0s**: Wait for up to the specified duration for the preferred connection to connect, and select the best connection that came online during the duration if the preferred connection did not come up

## Connection Selection Algorithm

Selection algorithm:
- Start wait timer immediately when connections begin
- Collect connections that come online during timeout period
- Select connection with lowest array index when timer expires
- Exception: Preferred connection always wins immediately

### Selection Example

Given this server configuration:
```yaml
servers:
  - server: primary.example.com:443    # Index 0 (preferred connection)
  - server: secondary.example.com:443  # Index 1
  - server: tertiary.example.com:443   # Index 2 (lowest priority)
preferred_connection_wait_interval: 1s
```

**Scenario 1**: Preferred connection connects first
1. All connections start
2. Preferred connection (index 0) comes online first
3. Preferred connection selected immediately
4. Other connections terminated

**Scenario 2**: Secondary connects first, preferred connection follows
1. All connections start, wait timer starts (1s)
2. Secondary (index 1) comes online at 200ms
3. Preferred connection (index 0) comes online at 700ms
4. Preferred connection selected immediately (no more waiting)
5. Secondary and tertiary terminated

**Scenario 3**: Tertiary connects first, then secondary
1. All connections start, wait timer starts (1s)
2. Tertiary (index 2) comes online at 300ms
3. Secondary (index 1) comes online at 800ms
4. Timer expires at 1000ms, secondary selected (lower index)
5. Tertiary terminated

**Scenario 4**: Only tertiary connects within timeout
1. All connections start, wait timer starts (1s)
2. Tertiary (index 2) comes online at 400ms
3. Timer expires at 1000ms, no other connections online
4. Tertiary selected (only available)

## Implementation Details

### Connection Lifecycle

Each connection manages their own [Connection State Machine](./connection_state_machine.md).

When the best connection is chosen, all other connections will be sent a stop signal. The connections will then gracefully terminate their own connection and release their resources.

### Error Handling

#### Connection Failures

- **Individual failures**: Others continue
- **All failures**: Returns error
- **Partial success**: One success = operation succeeds

#### Signal Handling

- **Stop signals**: Propagated to all connections
- **Network changes**: Handled per-connection by type
- **Timeouts**: Independent keepalive handling

## Configuration Migration

### From Single Server

**Before** (single server configuration):
```yaml
server: example.com:443
mode: tcp
server_dn: example.com
cipher: aes256
```

**After** (parallel connect):
```yaml
servers:
  - server: example.com:443
    mode: tcp 
    server_dn: example.com
    cipher: aes256
```


## Performance Considerations

### Resource Usage

- **Memory**: Each connection maintains its own state, buffers, and crypto contexts
- **Network**: All connections attempt to establish simultaneously, increasing initial bandwidth usage
- **CPU**: Crypto operations run in parallel for all connections
