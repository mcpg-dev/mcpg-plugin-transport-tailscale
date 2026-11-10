//! From a tailnet peer's whois to the identity the plugin attests.
//!
//! A user's device is named by its owner's login; a tagged device (a server
//! with no user) by its node name. An app capability's grant values carry
//! `roles`, `groups` and `scopes` arrays, merged across every grant that
//! matches the caller.

use std::collections::{BTreeMap, BTreeSet};

use mcpg_plugin_http_ingress::Refusal;
use mcpg_plugin_protocol::transport::TransportPeer;
use serde::Deserialize;

use crate::config::{IdentityConfig, TaggedNodes, TrustLevel};

/// The shim's whois answer.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Whois {
    #[serde(default)]
    pub login: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub user_id: i64,
    #[serde(default)]
    pub node_name: String,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// Capability name → the grant values that apply to the caller. A
    /// capability granted with no values arrives as `null`.
    #[serde(default)]
    pub caps: BTreeMap<String, Option<Vec<serde_json::Value>>>,
}

impl Whois {
    fn tags(&self) -> &[String] {
        self.tags.as_deref().unwrap_or_default()
    }

    fn is_tagged(&self) -> bool {
        !self.tags().is_empty()
    }
}

/// What a connection gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Serve it; `Some` is the identity attested on every request.
    Serve(Option<TransportPeer>),
    /// Answer every request on it with this.
    Refuse(Refusal),
}

fn forbidden(message: impl Into<String>) -> Verdict {
    Verdict::Refuse(Refusal {
        status: 403,
        message: message.into(),
    })
}

/// The verdict for a tailnet peer. `tailnet` names the tailnet for the
/// identity's issuer.
#[must_use]
pub fn judge(whois: &Whois, policy: &IdentityConfig, tailnet: &str) -> Verdict {
    if whois.is_tagged() && policy.tagged_nodes == TaggedNodes::Refuse {
        return forbidden("tagged devices may not call this gateway");
    }
    let mut grants = Grants::default();
    if let Some(capability) = &policy.capability {
        match whois.caps.get(capability) {
            Some(values) => grants.collect(values.as_deref().unwrap_or_default()),
            None if policy.require_capability => {
                return forbidden(format!(
                    "the tailnet policy grants this device no {capability} capability"
                ));
            }
            None => {}
        }
    }
    let trust_level = match policy.trust_level {
        TrustLevel::None => return Verdict::Serve(None),
        TrustLevel::Verified => "verified",
        TrustLevel::HeaderAsserted => "header_asserted",
    };
    let subject_id = if whois.is_tagged() {
        whois.node_name.clone()
    } else {
        whois.login.clone()
    };
    if subject_id.trim().is_empty() {
        return Verdict::Serve(None);
    }
    let mut attributes = BTreeMap::new();
    let mut put = |key: &str, value: String| {
        if !value.is_empty() {
            attributes.insert(format!("tailscale.{key}"), value);
        }
    };
    if !whois.is_tagged() {
        put("login", whois.login.clone());
        put("display_name", whois.display_name.clone());
        if whois.user_id != 0 {
            put("user_id", whois.user_id.to_string());
        }
    }
    put("node", whois.node_name.clone());
    put("node_id", whois.node_id.clone());
    put("tags", whois.tags().join(","));
    put("tailnet", tailnet.to_owned());
    Verdict::Serve(Some(TransportPeer {
        provider: "tailscale".into(),
        trust_level: trust_level.into(),
        subject_id,
        issuer: Some(if tailnet.is_empty() {
            "tailscale".into()
        } else {
            format!("tailscale:{tailnet}")
        }),
        roles: grants.roles.into_iter().collect(),
        groups: grants.groups.into_iter().collect(),
        scopes: grants.scopes.into_iter().collect(),
        attributes,
    }))
}

/// The verdict when the whois itself failed: refuse when a capability is
/// required, else serve with no identity.
#[must_use]
pub fn judge_unknown(policy: &IdentityConfig) -> Verdict {
    if policy.require_capability {
        forbidden("the gateway could not tell who this device belongs to")
    } else {
        Verdict::Serve(None)
    }
}

#[derive(Default)]
struct Grants {
    roles: BTreeSet<String>,
    groups: BTreeSet<String>,
    scopes: BTreeSet<String>,
}

impl Grants {
    fn collect(&mut self, values: &[serde_json::Value]) {
        for value in values {
            for (key, set) in [
                ("roles", &mut self.roles),
                ("groups", &mut self.groups),
                ("scopes", &mut self.scopes),
            ] {
                if let Some(items) = value.get(key).and_then(|v| v.as_array()) {
                    set.extend(
                        items
                            .iter()
                            .filter_map(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CAP: &str = "example.com/cap/mcpg";

    fn user() -> Whois {
        serde_json::from_value(json!({
            "login": "alice@example.com",
            "display_name": "Alice",
            "user_id": 42,
            "node_name": "laptop.tail1234.ts.net",
            "node_id": "nXYZ",
            "tags": null,
            "caps": {
                CAP: [{"roles": ["admin"], "scopes": ["tools:call"]}, {"roles": ["reader", "admin"], "groups": ["eng"]}],
                "https://tailscale.com/cap/ingress": null
            }
        }))
        .unwrap()
    }

    fn server() -> Whois {
        serde_json::from_value(json!({
            "login": "tagged-devices",
            "node_name": "ci-runner.tail1234.ts.net",
            "node_id": "nCI",
            "tags": ["tag:ci"],
            "caps": {}
        }))
        .unwrap()
    }

    fn policy(capability: Option<&str>, require: bool) -> IdentityConfig {
        IdentityConfig {
            capability: capability.map(str::to_owned),
            require_capability: require,
            ..Default::default()
        }
    }

    fn peer(v: Verdict) -> TransportPeer {
        match v {
            Verdict::Serve(Some(p)) => p,
            other => panic!("expected an attested peer, got {other:?}"),
        }
    }

    #[test]
    fn a_users_device_is_named_by_the_login_with_the_capability_grants_merged() {
        let p = peer(judge(&user(), &policy(Some(CAP), false), "example.com"));
        assert_eq!(p.provider, "tailscale");
        assert_eq!(p.trust_level, "verified");
        assert_eq!(p.subject_id, "alice@example.com");
        assert_eq!(p.issuer.as_deref(), Some("tailscale:example.com"));
        assert_eq!(p.roles, ["admin", "reader"]);
        assert_eq!(p.groups, ["eng"]);
        assert_eq!(p.scopes, ["tools:call"]);
        assert_eq!(p.attributes["tailscale.login"], "alice@example.com");
        assert_eq!(p.attributes["tailscale.display_name"], "Alice");
        assert_eq!(p.attributes["tailscale.user_id"], "42");
        assert_eq!(p.attributes["tailscale.node"], "laptop.tail1234.ts.net");
        assert_eq!(p.attributes["tailscale.node_id"], "nXYZ");
        assert_eq!(p.attributes["tailscale.tailnet"], "example.com");
        assert!(!p.attributes.contains_key("tailscale.tags"));
    }

    #[test]
    fn a_tagged_device_is_named_by_its_node_or_refused() {
        let p = peer(judge(&server(), &policy(None, false), "example.com"));
        assert_eq!(p.subject_id, "ci-runner.tail1234.ts.net");
        assert_eq!(p.attributes["tailscale.tags"], "tag:ci");
        assert!(
            !p.attributes.contains_key("tailscale.login"),
            "the pseudo-user is not a login"
        );
        let refuse = IdentityConfig {
            tagged_nodes: TaggedNodes::Refuse,
            ..Default::default()
        };
        assert!(matches!(judge(&server(), &refuse, ""), Verdict::Refuse(r) if r.status == 403));
        assert!(matches!(
            judge(&user(), &refuse, ""),
            Verdict::Serve(Some(_))
        ));
    }

    #[test]
    fn a_capability_granted_with_no_values_counts_as_granted() {
        let mut whois = user();
        whois.caps.insert(CAP.into(), None);
        let p = peer(judge(&whois, &policy(Some(CAP), true), ""));
        assert!(p.roles.is_empty());
    }

    #[test]
    fn a_required_capability_refuses_a_device_without_it() {
        let v = judge(&server(), &policy(Some(CAP), true), "");
        let Verdict::Refuse(r) = v else {
            panic!("expected a refusal");
        };
        assert_eq!(r.status, 403);
        assert!(r.message.contains(CAP), "{}", r.message);
        let p = peer(judge(&server(), &policy(Some(CAP), false), ""));
        assert!(p.roles.is_empty());
        assert_eq!(p.issuer.as_deref(), Some("tailscale"));
    }

    #[test]
    fn the_trust_level_decides_what_is_attested() {
        let asserted = IdentityConfig {
            trust_level: TrustLevel::HeaderAsserted,
            ..Default::default()
        };
        assert_eq!(
            peer(judge(&user(), &asserted, "")).trust_level,
            "header_asserted"
        );
        let none = IdentityConfig {
            trust_level: TrustLevel::None,
            ..Default::default()
        };
        assert_eq!(judge(&user(), &none, ""), Verdict::Serve(None));
        let required_none = IdentityConfig {
            trust_level: TrustLevel::None,
            capability: Some(CAP.into()),
            require_capability: true,
            ..Default::default()
        };
        assert!(matches!(
            judge(&server(), &required_none, ""),
            Verdict::Refuse(_)
        ));
    }

    #[test]
    fn a_failed_whois_refuses_only_when_a_capability_is_required() {
        assert_eq!(judge_unknown(&policy(None, false)), Verdict::Serve(None));
        assert!(matches!(
            judge_unknown(&policy(Some(CAP), true)),
            Verdict::Refuse(_)
        ));
        assert_eq!(
            judge(&Whois::default(), &policy(None, false), ""),
            Verdict::Serve(None),
            "no name, no identity"
        );
    }
}
