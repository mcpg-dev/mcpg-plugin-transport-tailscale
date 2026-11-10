# Tailscale Transport (`dev.mcpg.transport.tailscale`)

A **transport** plugin that joins the gateway to a tailnet as its own
Tailscale node. The node is embedded (Tailscale's `tsnet`), so the machine
needs no `tailscaled`, no inbound port and no public IP.

It is an `http`-wire transport: it hands every HTTP request to the gateway's
own router. For each tailnet connection it also asks the node **who owns the
peer** and attests that identity on every request of the connection. A caller
on the tailnet is then authenticated with no token.

## Listeners

- **Tailnet** (always): HTTPS with the node's tailnet certificate
  (`https://<hostname>.<tailnet>.ts.net`), or plain HTTP. HTTPS needs MagicDNS
  and HTTPS certificates turned on in the Tailscale admin console. On the
  tailnet, WireGuard encrypts plain HTTP too.
- **Funnel** (optional): HTTPS from the public internet on port 443, 8443 or
  10000. Funnel callers come from the internet: they carry **no** tailnet
  identity, and the gateway's own authentication applies to them.

## Identity

| Peer | Attested subject | Issuer |
|---|---|---|
| A user's device | the owner's login, e.g. `alice@example.com` | `tailscale:<tailnet>` |
| A tagged device (a server) | the node name, e.g. `ci.example.ts.net` | `tailscale:<tailnet>` |

The identity is `verified` by default: WireGuard authenticated the peer node,
and the tailnet's control server names its owner. The gateway records it under
the source `transport:dev.mcpg.transport.tailscale`. A request that carries a
verified credential of its own (a bearer token) keeps that identity instead.

**App capabilities.** Name one with `identity.capability`. The `roles`,
`groups` and `scopes` arrays of every grant value become the caller's:

```json
{
  "grants": [
    {
      "src": ["group:eng"],
      "dst": ["tag:mcp"],
      "app": { "example.com/cap/mcpg": [{ "roles": ["developer"], "scopes": ["tools:call"] }] }
    }
  ]
}
```

With `identity.require_capability: true`, a tailnet device that the policy
grants no such capability gets HTTP 403 from the plugin, and its requests
never reach the gateway.

The identity also carries the attributes `tailscale.login`,
`tailscale.display_name`, `tailscale.user_id`, `tailscale.node`,
`tailscale.node_id`, `tailscale.tags` and `tailscale.tailnet`.

To admit only tailnet members, set
`governance.access.require_authentication: true`.

## Configuration

Put the keys in the `config:` of the `gateway.server.transports[]` entry. If
that entry has no `config:`, the plugin uses the `config:` of its `plugins[]`
entry.

| Field | Default | Description |
|---|---|---|
| `hostname` | `mcpg` | The node's name; its MagicDNS name is `<hostname>.<tailnet>.ts.net`. |
| `state_dir` | *(required unless `ephemeral`)* | Where the node keeps its keys. Each gateway replica needs its own. |
| `auth_key` | none | An auth key, from `${env.TS_AUTHKEY}`. Used only when the node has no state yet. |
| `client_secret` | none | An OAuth client secret that mints the auth key. Needs `advertise_tags`. |
| `client_id` + `id_token` / `audience` | none | Workload identity federation. |
| `advertise_tags` | `[]` | Tags the node asks for, e.g. `tag:mcp`. |
| `control_url` | Tailscale | Another coordination server, e.g. Headscale. |
| `ephemeral` | `false` | The node leaves the tailnet when the gateway stops. |
| `upload_logs` | `false` | Upload the node's logs to Tailscale (log.tailscale.com). |
| `wireguard_port` | any | The UDP port for WireGuard. |
| `listen.mode` | `https` | `https` or `http`. |
| `listen.port` | 443 / 80 | The tailnet port. |
| `funnel.enabled` | `false` | Also serve the public internet through Funnel. |
| `funnel.port` | `443` | 443, 8443 or 10000. |
| `identity.trust_level` | `verified` | `verified`, `header_asserted` or `none` (attest nothing). |
| `identity.capability` | none | The app capability that carries roles, groups and scopes. |
| `identity.require_capability` | `false` | Refuse devices that the policy grants no capability. |
| `identity.tagged_nodes` | `allow` | `allow` or `refuse` tagged devices. |
| `connect_timeout_secs` | `60` | How long boot waits for the node to come up. |
| `max_request_body_bytes` | `4194304` | The largest request body; a larger one gets HTTP 413. |

Set only one of `auth_key`, `client_secret` and `client_id`. With none of
them, a node that has no state logs a login URL at WARN; open it to add the
node to the tailnet.

```yaml
plugins:
  - id: dev.mcpg.transport.tailscale
    kind: native
    class: transport
    source:
      oci: ghcr.io/mcpg-dev/plugins/transport-tailscale
    granted_capabilities:
      - network_outbound
      - transport_listen

gateway:
  server:
    bind_address: "127.0.0.1:8787"
    transports:
      - kind: dev.mcpg.transport.tailscale
        config:
          hostname: mcp
          state_dir: /var/lib/mcpg/tailscale
          auth_key: ${env.TS_AUTHKEY}
          identity:
            capability: example.com/cap/mcpg
            require_capability: true

governance:
  access:
    require_authentication: true
```

## Behaviour to know

- **Platforms:** Linux (glibc) amd64 and arm64, and macOS arm64. The node is
  Go code inside the plugin; musl cannot load a Go runtime into a plugin, and
  the plugin hands connections over as Unix socket pairs, which Windows does
  not have.
- **Boot fails on a node that does not come up** within `connect_timeout_secs`.
  The error names the cause; auth keys and secrets never appear in it.
- **Listen address:** with Funnel on, the public URL, which the gateway also
  uses as its public address for webhook callbacks. Without Funnel,
  `tailnet:https://<name>`, which is not a public address.
- **Replicas:** each replica is its own node with its own `state_dir` and
  `hostname`. Clients on the `2025-11-25` wire keep a session on one node.
- **Building from source** needs Go (the version in `tsshim/go.mod`); the
  crate's build script builds the node as a C archive.

## License

Apache-2.0 — see [LICENSE](LICENSE).
