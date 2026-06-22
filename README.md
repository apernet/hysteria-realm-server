# Hysteria Realm Server

A rendezvous server for **Hysteria Realms**, the P2P feature of [Hysteria 2](https://github.com/apernet/hysteria).

It coordinates UDP hole punching between Hysteria servers and clients so users can host Hysteria servers from behind NAT or firewalls. No port forwarding, no public IP required.

## How it works

1. A Hysteria server registers a realm with the rendezvous server, advertising its STUN-discovered UDP address(es).
2. A Hysteria client looks up the realm. The rendezvous pushes the client's address(es), punch nonce, and punch obfuscation key to the server over its SSE stream, and waits.
3. The Hysteria server runs a fresh STUN, posts the just-discovered addresses, and the rendezvous returns those to the client. If the server doesn't post within a few seconds, the rendezvous falls back to the addresses cached at registration time.
4. Both sides simultaneously send UDP packets toward each other, punching holes in their respective NATs.
5. Once a hole is open, Hysteria's regular QUIC handshake proceeds over the direct connection.

The rendezvous server only mediates introductions. **No traffic is relayed.** Once peers are connected, the rendezvous is out of the loop.

## Build

```bash
go build -o hysteria-realm-server
```

## Run

```bash
HYSTERIA_REALM_TOKEN=your-secret-token \
HYSTERIA_REALM_LISTEN=:8443 \
HYSTERIA_REALM_CERT=/path/to/cert.pem \
HYSTERIA_REALM_KEY=/path/to/key.pem \
./hysteria-realm-server
```

Equivalent CLI flags are also supported:

```bash
./hysteria-realm-server \
  --token your-secret-token \
  --listen :8443 \
  --cert /path/to/cert.pem \
  --key /path/to/key.pem
```

If `HYSTERIA_REALM_CERT` and `HYSTERIA_REALM_KEY` are unset, the server runs over plain HTTP.

## Configuration

| Variable                              | Default                            | Description                                                                                                                                                            |
| ------------------------------------- | ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `HYSTERIA_REALM_LISTEN`               | `:8443`                            | Address to listen on                                                                                                                                                   |
| `HYSTERIA_REALM_TOKEN`                | _REQUIRED_                         | Shared bearer token for realm registration and connection                                                                                                              |
| `HYSTERIA_REALM_CERT`                 | _(none)_                           | Path to TLS certificate                                                                                                                                                |
| `HYSTERIA_REALM_KEY`                  | _(none)_                           | Path to TLS private key                                                                                                                                                |
| `HYSTERIA_REALM_DEBUG`                | `false`                            | Enable debug logs for registration, sessions, and punches                                                                                                              |
| `HYSTERIA_REALM_MAX_REALMS`           | `65536`                            | Maximum total number of registered realms. `0` disables the limit.                                                                                                     |
| `HYSTERIA_REALM_MAX_REALMS_PER_IP`    | `4`                                | Maximum realms per client IP. `0` disables the limit.                                                                                                                  |
| `HYSTERIA_REALM_TRUSTED_PROXY_HEADER` | _(none)_                           | Header to read the real client IP from when behind a reverse proxy or CDN (e.g. `X-Forwarded-For`, `CF-Connecting-IP`). Empty means use the connecting socket address. |
| `HYSTERIA_REALM_NAME_PATTERN`         | `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$` | Regex realm names must match.                                                                                                                                          |
| `HYSTERIA_REALM_METRICS_LISTEN`       | _(none)_                           | Address to expose Prometheus metrics on (e.g. `:9090`). Empty disables metrics.                                                                                        |

CLI flags with the same meaning are available: `--listen`, `--token`, `--cert`, `--key`, `--debug`, `--max-realms`, `--max-realms-per-ip`, `--trusted-proxy-header`, `--realm-name-pattern`, and `--metrics-listen`. Flags override environment variables.

When `HYSTERIA_REALM_TRUSTED_PROXY_HEADER` is set, the server takes the leftmost comma-separated value of that header as the client IP, falling back to the socket address if the header is missing or unparseable. Only enable this when the server is actually behind a trusted proxy that strips/sets the header — otherwise clients can spoof their IP and bypass the per-IP limit.

## Limitations

- **In-memory only.** All state is lost on restart. Active realms must re-register.
- **Single shared token.** Every realm uses the same token. Only suitable for self-hosted, trusted-group deployments. More sophisticated third-party implementations are welcome.

## API

All endpoints use `Authorization: Bearer ...`. Realm names in `{id}` must match `HYSTERIA_REALM_NAME_PATTERN`; an invalid name returns `400 bad_request`.

Errors are returned as JSON: `{"error": "<code>", "message": "<human-readable>"}`. Notable codes:

| Status | Code                  | Cause                                                       |
| ------ | --------------------- | ----------------------------------------------------------- |
| 400    | `bad_request`         | Invalid JSON, invalid addresses/nonce/obfs, bad name        |
| 401    | `invalid_token`       | Missing or wrong bearer token                               |
| 404    | `realm_not_found`     | `connect` to a realm that is not registered                 |
| 404    | `attempt_not_found`   | `connects/{nonce}` post for an unknown / expired nonce      |
| 409    | `realm_taken`         | Registering a realm name that is already in use             |
| 429    | `realm_limit_reached` | Global realm limit reached                                  |
| 429    | `ip_limit_reached`    | Per-IP realm limit reached                                  |
| 503    | `rate_limited`        | Server's punch event buffer or pending-attempts cap is full |

### `POST /v1/{id}`

Register a Realm. Uses `HYSTERIA_REALM_TOKEN`.

Request:

```json
{
  "addresses": ["203.0.113.10:4433"]
}
```

Response:

```json
{
  "session_id": "session-token",
  "ttl": 60
}
```

### `GET /v1/{id}/events`

Open the Realm server's SSE stream. Uses `session_id`.

Events:

```text
event: punch
data: {"addresses":["198.51.100.20:4433"],"nonce":"...","obfs":"..."}
```

```text
event: heartbeat_ack
data: {"ttl":60}
```

`punch` is emitted on every `connect` request for this realm. `heartbeat_ack` is emitted on every successful `heartbeat` and lets clients confirm the SSE stream is still healthy.

### `POST /v1/{id}/heartbeat`

Refresh the session TTL. Uses `session_id`. It may also include replacement Realm addresses:

```json
{
  "addresses": ["203.0.113.11:4433"]
}
```

If `addresses` is omitted, only the TTL is refreshed. If present, the Hysteria Realm Server validates and replaces the stored addresses for that Realm.

Response:

```json
{
  "ttl": 60
}
```

### `DELETE /v1/{id}`

Deregister a Realm immediately. Uses `session_id`.

Response: `204 No Content`.

### `POST /v1/{id}/connect`

Request a connection to a Realm. Uses `HYSTERIA_REALM_TOKEN`.

```json
{
  "addresses": ["198.51.100.20:4433"],
  "nonce": "00112233445566778899aabbccddeeff",
  "obfs": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
}
```

- `nonce` is 16 random bytes encoded as 32 lowercase or uppercase hex characters.
- `obfs` is a 32-byte random key encoded as 64 lowercase or uppercase hex characters, used by peers to obfuscate UDP punch packets.

The Hysteria Realm Server forwards `addresses`, `nonce`, and `obfs` unchanged in the Realm server's `punch` SSE event, then **blocks the request for up to 10 seconds** waiting for the Realm server to post fresh addresses via `/v1/{id}/connects/{nonce}`. If the post arrives, those fresh addresses are returned to the client; if it doesn't (legacy server, STUN failure, etc.), the registered cached addresses are returned instead. The response always echoes `nonce` and `obfs`:

```json
{
  "addresses": ["203.0.113.10:4433"],
  "nonce": "00112233445566778899aabbccddeeff",
  "obfs": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
}
```

### `POST /v1/{id}/connects/{nonce}`

Posted by the Realm server in response to a `punch` SSE event, with the addresses it just discovered via a fresh STUN. Uses `session_id`. The `{nonce}` path segment must match the `nonce` from the SSE event.

```json
{
  "addresses": ["203.0.113.10:4433"]
}
```

Response: `204 No Content`. Returns `404 attempt_not_found` if the rendezvous has no in-flight `connect` for this nonce.
