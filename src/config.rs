//! `dev.mcpg.transport.tailscale` configuration.
//!
//! ```yaml
//! gateway:
//!   server:
//!     transports:
//!       - kind: dev.mcpg.transport.tailscale
//!         config:
//!           hostname: mcp
//!           state_dir: /var/lib/mcpg/tailscale
//!           auth_key: ${env.TS_AUTHKEY}
//!           identity:
//!             capability: example.com/cap/mcpg
//! ```

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The largest request body the plugin reads from a client.
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;
/// How long the plugin waits for the node to come up.
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 60;
/// The ports Funnel accepts.
pub const FUNNEL_PORTS: [u16; 3] = [443, 8443, 10000];

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailscaleConfig {
    /// The node's name on the tailnet; its MagicDNS name is
    /// `<hostname>.<tailnet>.ts.net`.
    #[serde(default = "default_hostname")]
    pub hostname: String,
    /// Where the node keeps its keys and state. Required unless the node is
    /// ephemeral; each gateway replica needs its own.
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    /// An auth key (`tskey-auth-…`). Set it from `${env.TS_AUTHKEY}`. Used
    /// only when the node has no state yet.
    #[serde(default)]
    pub auth_key: Option<String>,
    /// An OAuth client secret (`tskey-client-…`) that mints the node's auth
    /// key. Needs `advertise_tags`.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// The OAuth client id for workload identity federation, with
    /// `id_token` or `audience`.
    #[serde(default)]
    pub client_id: Option<String>,
    /// An ID token from your identity provider, exchanged with the control
    /// server for workload identity federation.
    #[serde(default)]
    pub id_token: Option<String>,
    /// The audience to request an ID token for from a well-known identity
    /// provider (GitHub Actions, cloud metadata) for workload identity
    /// federation.
    #[serde(default)]
    pub audience: Option<String>,
    /// Tags the node asks for, e.g. `tag:mcp`. The tailnet policy decides
    /// whether it gets them.
    #[serde(default)]
    pub advertise_tags: Vec<String>,
    /// A coordination server other than Tailscale's, e.g. Headscale.
    #[serde(default)]
    pub control_url: Option<String>,
    /// Register as an ephemeral node: it leaves the tailnet when the
    /// gateway stops.
    #[serde(default)]
    pub ephemeral: bool,
    /// Upload the node's logs to Tailscale (log.tailscale.com). Off by
    /// default; Tailscale support asks for them.
    #[serde(default)]
    pub upload_logs: bool,
    /// The UDP port for WireGuard; unset picks one.
    #[serde(default)]
    pub wireguard_port: Option<u16>,
    /// The tailnet listener.
    #[serde(default)]
    pub listen: ListenConfig,
    /// The public listener through Tailscale Funnel.
    #[serde(default)]
    pub funnel: FunnelConfig,
    /// How the tailnet identity of a caller becomes the gateway's.
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ListenMode {
    /// HTTPS with the node's tailnet certificate (needs MagicDNS and HTTPS
    /// certificates on in the tailnet).
    #[default]
    Https,
    /// Plain HTTP; WireGuard still encrypts it on the tailnet.
    Http,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
    #[serde(default)]
    pub mode: ListenMode,
    /// Default: 443 for HTTPS, 80 for HTTP.
    #[serde(default)]
    pub port: Option<u16>,
}

impl ListenConfig {
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(match self.mode {
            ListenMode::Https => 443,
            ListenMode::Http => 80,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunnelConfig {
    #[serde(default)]
    pub enabled: bool,
    /// 443, 8443 or 10000.
    #[serde(default = "default_funnel_port")]
    pub port: u16,
}

impl Default for FunnelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: default_funnel_port(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// WireGuard authenticated the peer node; the control server names its
    /// owner.
    #[default]
    Verified,
    /// The name counts as an assertion only.
    HeaderAsserted,
    /// The plugin attests no identity; the gateway's own credentials decide.
    None,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaggedNodes {
    /// A tagged device (a server, no user) is named by its node name.
    #[default]
    Allow,
    /// A tagged device gets HTTP 403.
    Refuse,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    #[serde(default)]
    pub trust_level: TrustLevel,
    /// A Tailscale app capability, e.g. `example.com/cap/mcpg`. The
    /// `roles`, `groups` and `scopes` arrays of its grant values become the
    /// caller's.
    #[serde(default)]
    pub capability: Option<String>,
    /// Refuse (HTTP 403) a tailnet caller that the policy grants no
    /// `capability`.
    #[serde(default)]
    pub require_capability: bool,
    #[serde(default)]
    pub tagged_nodes: TaggedNodes,
}

fn default_hostname() -> String {
    "mcpg".into()
}

fn default_funnel_port() -> u16 {
    443
}

fn default_connect_timeout_secs() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_SECS
}

fn default_max_request_body_bytes() -> usize {
    DEFAULT_MAX_REQUEST_BODY_BYTES
}

fn shown(secret: &Option<String>) -> &'static str {
    if secret.is_some() {
        "<redacted>"
    } else {
        "<unset>"
    }
}

impl std::fmt::Debug for TailscaleConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TailscaleConfig")
            .field("hostname", &self.hostname)
            .field("state_dir", &self.state_dir)
            .field("auth_key", &shown(&self.auth_key))
            .field("client_secret", &shown(&self.client_secret))
            .field("client_id", &self.client_id)
            .field("id_token", &shown(&self.id_token))
            .field("audience", &self.audience)
            .field("advertise_tags", &self.advertise_tags)
            .field("control_url", &self.control_url)
            .field("ephemeral", &self.ephemeral)
            .field("listen", &self.listen)
            .field("funnel", &self.funnel)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

/// The node settings the Go shim takes.
#[derive(Serialize)]
pub struct NodeSettings<'a> {
    pub dir: String,
    pub hostname: &'a str,
    pub auth_key: &'a str,
    pub client_secret: &'a str,
    pub client_id: &'a str,
    pub id_token: &'a str,
    pub audience: &'a str,
    pub control_url: &'a str,
    pub ephemeral: bool,
    pub advertise_tags: &'a [String],
    pub upload_logs: bool,
    pub port: u16,
}

impl TailscaleConfig {
    /// Parse and check a config value.
    pub fn from_value(value: &serde_json::Value) -> Result<Self, String> {
        let cfg: Self =
            serde_json::from_value(value.clone()).map_err(|e| format!("tailscale config: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), String> {
        let bad = |message: String| Err(format!("tailscale config: {message}"));
        if !is_dns_label(&self.hostname) {
            return bad(format!(
                "`hostname` is {:?}; use one DNS label: letters, digits and `-`",
                self.hostname
            ));
        }
        if self.state_dir.is_none() && !self.ephemeral {
            return bad(
                "set `state_dir` (where the node keeps its keys), or `ephemeral: true`".into(),
            );
        }
        for (field, value) in [
            ("auth_key", &self.auth_key),
            ("client_secret", &self.client_secret),
            ("client_id", &self.client_id),
            ("id_token", &self.id_token),
            ("audience", &self.audience),
        ] {
            if let Some(v) = value {
                if v.trim().is_empty() {
                    return bad(format!("`{field}` is empty"));
                }
                if v.contains("${") {
                    return bad(format!(
                        "`{field}` still holds a `${{...}}` reference; the variable is not set"
                    ));
                }
            }
        }
        let methods = [
            self.auth_key.is_some(),
            self.client_secret.is_some(),
            self.client_id.is_some(),
        ]
        .iter()
        .filter(|set| **set)
        .count();
        if methods > 1 {
            return bad("set one of `auth_key`, `client_secret` and `client_id`".into());
        }
        if self.client_secret.is_some() && self.advertise_tags.is_empty() {
            return bad(
                "`client_secret` creates a tagged node; set `advertise_tags`, e.g. [\"tag:mcp\"]"
                    .into(),
            );
        }
        if self.client_id.is_some() && self.id_token.is_none() && self.audience.is_none() {
            return bad("`client_id` needs `id_token` or `audience`".into());
        }
        if (self.id_token.is_some() || self.audience.is_some()) && self.client_id.is_none() {
            return bad("`id_token` and `audience` need `client_id`".into());
        }
        if let Some(tag) = self
            .advertise_tags
            .iter()
            .find(|t| !t.starts_with("tag:") || t.len() <= 4)
        {
            return bad(format!(
                "`advertise_tags` entry {tag:?} must look like `tag:name`"
            ));
        }
        if let Some(url) = &self.control_url
            && !(url.starts_with("https://") || url.starts_with("http://"))
        {
            return bad(format!("`control_url` {url:?} is not an http(s) URL"));
        }
        if self.listen.port() == 0 {
            return bad("`listen.port` must be at least 1".into());
        }
        if self.funnel.enabled && !FUNNEL_PORTS.contains(&self.funnel.port) {
            return bad(format!(
                "`funnel.port` is {}; Funnel accepts 443, 8443 or 10000",
                self.funnel.port
            ));
        }
        if self.identity.require_capability && self.identity.capability.is_none() {
            return bad("`identity.require_capability` needs `identity.capability`".into());
        }
        if self.connect_timeout_secs == 0 {
            return bad("`connect_timeout_secs` must be at least 1".into());
        }
        if self.max_request_body_bytes == 0 {
            return bad("`max_request_body_bytes` must be at least 1".into());
        }
        Ok(())
    }

    #[must_use]
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_secs)
    }

    /// The state directory: the configured one, else a fresh one for an
    /// ephemeral node.
    pub fn state_dir(&self) -> std::io::Result<PathBuf> {
        match &self.state_dir {
            Some(dir) => {
                std::fs::create_dir_all(dir)?;
                Ok(dir.clone())
            }
            None => {
                let dir = std::env::temp_dir().join(format!(
                    "mcpg-tailscale-{}-{}",
                    self.hostname,
                    std::process::id()
                ));
                std::fs::create_dir_all(&dir)?;
                Ok(dir)
            }
        }
    }

    /// The node settings, with `dir` the state directory.
    #[must_use]
    pub fn node_settings(&self, dir: &std::path::Path) -> NodeSettings<'_> {
        fn s(v: &Option<String>) -> &str {
            v.as_deref().unwrap_or("")
        }
        NodeSettings {
            dir: dir.display().to_string(),
            hostname: &self.hostname,
            auth_key: s(&self.auth_key),
            client_secret: s(&self.client_secret),
            client_id: s(&self.client_id),
            id_token: s(&self.id_token),
            audience: s(&self.audience),
            control_url: s(&self.control_url),
            ephemeral: self.ephemeral,
            advertise_tags: &self.advertise_tags,
            upload_logs: self.upload_logs,
            port: self.wireguard_port.unwrap_or(0),
        }
    }

    /// Every secret value, for scrubbing error text.
    pub fn secrets(&self) -> impl Iterator<Item = &str> {
        [&self.auth_key, &self.client_secret, &self.id_token]
            .into_iter()
            .filter_map(|v| v.as_deref())
    }
}

fn is_dns_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base() -> serde_json::Value {
        json!({"state_dir": "/tmp/ts"})
    }

    fn with(extra: serde_json::Value) -> serde_json::Value {
        let mut v = base();
        v.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        v
    }

    #[test]
    fn a_minimal_config_serves_https_on_443_and_trusts_the_tailnet_identity() {
        let cfg = TailscaleConfig::from_value(&base()).unwrap();
        assert_eq!(cfg.hostname, "mcpg");
        assert_eq!(cfg.listen.mode, ListenMode::Https);
        assert_eq!(cfg.listen.port(), 443);
        assert!(!cfg.funnel.enabled);
        assert!(!cfg.upload_logs);
        assert_eq!(cfg.identity.trust_level, TrustLevel::Verified);
        assert_eq!(cfg.identity.tagged_nodes, TaggedNodes::Allow);
        assert_eq!(cfg.connect_timeout(), Duration::from_secs(60));
    }

    #[test]
    fn plain_http_defaults_to_port_80() {
        let cfg = TailscaleConfig::from_value(&with(json!({"listen": {"mode": "http"}}))).unwrap();
        assert_eq!(cfg.listen.port(), 80);
    }

    #[test]
    fn the_debug_form_hides_every_secret() {
        let cfg =
            TailscaleConfig::from_value(&with(json!({"auth_key": "tskey-auth-SECRET"}))).unwrap();
        let shown = format!("{cfg:?}");
        assert!(!shown.contains("SECRET"), "{shown}");
        assert!(shown.contains("<redacted>"));
        let wif = TailscaleConfig::from_value(&with(json!({
            "client_id": "cid", "id_token": "eyJ.SECRET.x"
        })))
        .unwrap();
        assert!(!format!("{wif:?}").contains("SECRET"));
        assert_eq!(wif.secrets().collect::<Vec<_>>(), ["eyJ.SECRET.x"]);
    }

    #[test]
    fn bad_values_are_refused_with_the_field_name() {
        for (value, field) in [
            (json!({}), "state_dir"),
            (with(json!({"hostname": "my host"})), "hostname"),
            (with(json!({"auth_key": ""})), "auth_key"),
            (with(json!({"auth_key": "${env.TS_AUTHKEY}"})), "auth_key"),
            (
                with(json!({"auth_key": "a", "client_secret": "b"})),
                "one of",
            ),
            (
                with(json!({"client_secret": "tskey-client-x"})),
                "advertise_tags",
            ),
            (with(json!({"client_id": "c"})), "id_token"),
            (with(json!({"audience": "a"})), "client_id"),
            (with(json!({"advertise_tags": ["mcp"]})), "advertise_tags"),
            (
                with(json!({"control_url": "headscale.example"})),
                "control_url",
            ),
            (with(json!({"listen": {"port": 0}})), "listen.port"),
            (
                with(json!({"funnel": {"enabled": true, "port": 80}})),
                "funnel.port",
            ),
            (
                with(json!({"identity": {"require_capability": true}})),
                "identity.capability",
            ),
            (
                with(json!({"connect_timeout_secs": 0})),
                "connect_timeout_secs",
            ),
            (
                with(json!({"max_request_body_bytes": 0})),
                "max_request_body_bytes",
            ),
            (
                with(json!({"identity": {"trust_level": "root"}})),
                "unknown variant `root`",
            ),
            (with(json!({"unknown": 1})), "unknown"),
        ] {
            let err = TailscaleConfig::from_value(&value).unwrap_err();
            assert!(err.contains(field), "{value}: {err}");
        }
    }

    #[test]
    fn every_auth_method_and_an_ephemeral_node_without_state_are_accepted() {
        for extra in [
            json!({"auth_key": "tskey-auth-x"}),
            json!({"client_secret": "tskey-client-x", "advertise_tags": ["tag:mcp"]}),
            json!({"client_id": "c", "id_token": "t"}),
            json!({"client_id": "c", "audience": "api.tailscale.com"}),
            json!({"funnel": {"enabled": true, "port": 8443}}),
        ] {
            TailscaleConfig::from_value(&with(extra.clone()))
                .unwrap_or_else(|e| panic!("{extra}: {e}"));
        }
        let ephemeral = TailscaleConfig::from_value(&json!({"ephemeral": true})).unwrap();
        let dir = ephemeral.state_dir().unwrap();
        assert!(dir.is_dir());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_node_settings_carry_the_config_to_the_shim() {
        let cfg = TailscaleConfig::from_value(&with(json!({
            "hostname": "gw",
            "auth_key": "tskey-auth-x",
            "advertise_tags": ["tag:mcp"],
            "control_url": "https://headscale.example",
            "ephemeral": true,
            "wireguard_port": 41641
        })))
        .unwrap();
        let settings = serde_json::to_value(cfg.node_settings(std::path::Path::new("/s"))).unwrap();
        assert_eq!(
            settings,
            json!({
                "dir": "/s", "hostname": "gw", "auth_key": "tskey-auth-x",
                "client_secret": "", "client_id": "", "id_token": "", "audience": "",
                "control_url": "https://headscale.example", "ephemeral": true,
                "advertise_tags": ["tag:mcp"], "upload_logs": false, "port": 41641
            })
        );
    }
}
