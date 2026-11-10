//! `dev.mcpg.transport.tailscale` — the gateway joins a tailnet as its own
//! node.
//!
//! An `http`-wire transport: the plugin embeds a Tailscale node (tsnet,
//! through the Go shim in `tsshim/`), listens on the tailnet (HTTPS with the
//! node's certificate, or plain HTTP) and optionally on the public internet
//! through Funnel, and hands every request to the gateway's own router.
//!
//! For each tailnet connection the plugin asks the node who owns the peer
//! (whois) and attests that identity on every request of the connection: a
//! user's login, or a tagged device's node name, with roles, groups and
//! scopes from an app capability the tailnet policy grants. Funnel
//! connections come from the internet and carry no identity.
//!
//! The library holds a Go runtime, which cannot be unloaded, so the plugin
//! pins itself in memory when it is first made.

use std::ffi::{CStr, c_char, c_int};
use std::os::fd::OwnedFd;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, Once};
use std::thread::JoinHandle;
use std::time::Duration;

use mcpg_plugin_http_ingress::{Connection, serve_connection};
use mcpg_plugin_protocol::transport::{TransportError, TransportWire};
use mcpg_plugin_protocol::{PluginClass, PluginManifest};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::{
    SyncMessageDispatcher, SyncTransport, SyncTransportHandle, WatchHandleBox,
};
use mcpg_plugin_sdk::http_ingress::HttpIngressServer;
use serde::Deserialize;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

mod config;
mod identity;
mod shim;

pub use config::TailscaleConfig;

use config::ListenMode;
use identity::Verdict;

const PLUGIN_ID: &str = "dev.mcpg.transport.tailscale";

/// How long dropping the transport waits for its connections to end.
const DRAIN_LIMIT: Duration = Duration::from_secs(5);
/// The first pause after a failed accept; it doubles up to
/// [`ACCEPT_RETRY_MAX`], so a broken listener neither spins nor floods the
/// log.
const ACCEPT_RETRY: Duration = Duration::from_millis(200);
const ACCEPT_RETRY_MAX: Duration = Duration::from_secs(5);

pub struct TailscaleTransport {
    manifest: PluginManifest,
    /// The `plugins[]` entry config; used when the `transports[]` entry has
    /// none.
    plugin_config: serde_json::Value,
    runtime: Option<Runtime>,
}

impl TailscaleTransport {
    fn new(plugin_config: &str) -> Self {
        pin_in_memory();
        route_shim_logs();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("mcpg-tailscale")
            .enable_all()
            .build()
            .expect("transport.tailscale: failed to build tokio runtime");
        Self {
            manifest: PluginManifest {
                id: PLUGIN_ID.into(),
                version: env!("CARGO_PKG_VERSION").into(),
                name: "Tailscale Transport".into(),
                plugin_class: PluginClass::Transport,
                protocol_version: "1.0".into(),
                license: None,
                required_capabilities: Vec::new(),
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            plugin_config: serde_json::from_str(plugin_config).unwrap_or(serde_json::Value::Null),
            runtime: Some(runtime),
        }
    }

    fn runtime(&self) -> &tokio::runtime::Handle {
        self.runtime
            .as_ref()
            .expect("the runtime lives until the plugin drops")
            .handle()
    }

    /// The listener config, else the plugin entry's config.
    fn config_for(&self, listener_config: &serde_json::Value) -> Result<TailscaleConfig, String> {
        let empty = match listener_config {
            serde_json::Value::Null => true,
            serde_json::Value::Object(map) => map.is_empty(),
            _ => false,
        };
        TailscaleConfig::from_value(if empty {
            &self.plugin_config
        } else {
            listener_config
        })
    }
}

impl Drop for TailscaleTransport {
    fn drop(&mut self) {
        // The host may drop the plugin on one of its runtime threads, where
        // a blocking runtime drop panics.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// The node status the shim reports after `up`.
#[derive(Debug, Clone, Default, Deserialize)]
struct NodeStatus {
    #[serde(default)]
    dns_name: String,
    #[serde(default)]
    ips: Option<Vec<String>>,
    #[serde(default)]
    tailnet: String,
}

/// One running node: the state behind a transport handle.
struct Endpoint {
    /// Keeps the node up while the endpoint lives; the connection tasks
    /// hold it too, so it closes after the last one ends.
    _node: Arc<shim::Node>,
    status: NodeStatus,
    listeners: Vec<shim::Listener>,
    accept_threads: Mutex<Vec<JoinHandle<()>>>,
    /// Ends the connections still open.
    kill: CancellationToken,
    tasks: TaskTracker,
    runtime: tokio::runtime::Handle,
    listen_address: String,
}

impl Endpoint {
    fn stop_accepting(&self) {
        for listener in &self.listeners {
            listener.close();
        }
    }
}

/// The parts every accepted connection needs.
#[derive(Clone)]
struct Serving {
    node: Arc<shim::Node>,
    server: HttpIngressServer,
    config: Arc<TailscaleConfig>,
    tailnet: String,
    kill: CancellationToken,
    tasks: TaskTracker,
    runtime: tokio::runtime::Handle,
}

impl SyncTransport for TailscaleTransport {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn name(&self) -> &str {
        "tailscale-v1"
    }

    fn wire(&self) -> TransportWire {
        TransportWire::Http
    }

    fn start(
        &self,
        _listener_config: &serde_json::Value,
        _dispatcher: Arc<dyn SyncMessageDispatcher>,
    ) -> Result<SyncTransportHandle, TransportError> {
        Err(TransportError::InvalidConfig {
            message: format!("{PLUGIN_ID} hands the gateway HTTP requests, not JSON-RPC messages"),
        })
    }

    fn start_http(
        &self,
        listener_config: &serde_json::Value,
        server: HttpIngressServer,
    ) -> Result<SyncTransportHandle, TransportError> {
        let config = self
            .config_for(listener_config)
            .map_err(|message| TransportError::InvalidConfig { message })?;
        let endpoint = open(config, server, self.runtime().clone())
            .map_err(|reason| TransportError::BindFailed { reason })?;
        tracing::info!(
            plugin_id = PLUGIN_ID,
            node = %endpoint.status.dns_name,
            ips = ?endpoint.status.ips,
            listen = %endpoint.listen_address,
            "tailscale node up"
        );
        let listen_address = endpoint.listen_address.clone();
        Ok(SyncTransportHandle {
            handle: Box::into_raw(Box::new(endpoint)).cast(),
            listen_address: Some(listen_address),
        })
    }

    fn transport_handle_close(&self, transport_handle: WatchHandleBox) {
        // SAFETY: the host passes back the handle `start_http` returned, and
        // frees it only through `transport_handle_drop`.
        let endpoint = unsafe { &*(transport_handle.0 as *const Endpoint) };
        endpoint.stop_accepting();
    }

    fn transport_handle_drop(&self, transport_handle: WatchHandleBox) {
        // SAFETY: as in `transport_handle_close`; the host calls this once.
        let endpoint = unsafe { Box::from_raw(transport_handle.0.cast::<Endpoint>()) };
        endpoint.stop_accepting();
        for thread in endpoint
            .accept_threads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            let _ = thread.join();
        }
        endpoint.kill.cancel();
        endpoint.tasks.close();
        // The host frees its server once this returns, so every task that
        // can call it must be gone first.
        let (done_tx, done_rx) = mpsc::channel();
        let tasks = endpoint.tasks.clone();
        endpoint.runtime.spawn(async move {
            tasks.wait().await;
            let _ = done_tx.send(());
        });
        if done_rx.recv_timeout(DRAIN_LIMIT).is_err() {
            tracing::warn!(
                plugin_id = PLUGIN_ID,
                "tailscale connections did not end within 5 s of the transport drop"
            );
        }
        // Dropping the endpoint closes the node; an ephemeral one leaves the
        // tailnet.
    }

    fn transport_handle_listen_address(&self, transport_handle: WatchHandleBox) -> Option<String> {
        // SAFETY: as in `transport_handle_close`.
        let endpoint = unsafe { &*(transport_handle.0 as *const Endpoint) };
        Some(endpoint.listen_address.clone())
    }
}

/// Bring the node up and open its listeners.
fn open(
    config: TailscaleConfig,
    server: HttpIngressServer,
    runtime: tokio::runtime::Handle,
) -> Result<Endpoint, String> {
    let scrub = |text: String| -> String {
        config
            .secrets()
            .fold(text, |t, secret| t.replace(secret, "<redacted>"))
    };
    let dir = config
        .state_dir()
        .map_err(|e| format!("tailscale state_dir: {e}"))?;
    let settings = serde_json::to_string(&config.node_settings(&dir))
        .map_err(|e| format!("tailscale node settings: {e}"))?;
    let node = Arc::new(shim::Node::new(&settings).map_err(scrub)?);
    let status_json = node
        .up(config.connect_timeout())
        .map_err(|e| scrub(format!("the tailscale node did not come up: {e}")))?;
    let status: NodeStatus =
        serde_json::from_str(&status_json).map_err(|e| format!("tailscale node status: {e}"))?;

    let port = config.listen.port();
    let mode = match config.listen.mode {
        ListenMode::Https => "tls",
        ListenMode::Http => "tcp",
    };
    let tailnet_listener = node.listen(mode, port).map_err(scrub)?;
    let mut listeners = vec![tailnet_listener];
    let funnel_listener = if config.funnel.enabled {
        match node.listen("funnel", config.funnel.port) {
            Ok(listener) => {
                listeners.push(listener);
                Some(listener)
            }
            Err(e) => {
                tailnet_listener.close();
                return Err(scrub(format!("tailscale funnel: {e}")));
            }
        }
    } else {
        None
    };

    let scheme = match config.listen.mode {
        ListenMode::Https => "https",
        ListenMode::Http => "http",
    };
    let default_port = if scheme == "https" { 443 } else { 80 };
    let tailnet_url = if port == default_port {
        format!("{scheme}://{}", status.dns_name)
    } else {
        format!("{scheme}://{}:{port}", status.dns_name)
    };
    // Only a Funnel URL is reachable from the internet, so only it may be
    // the gateway's public address (an `http(s)://` listen address is).
    let listen_address = if config.funnel.enabled {
        if config.funnel.port == 443 {
            format!("https://{}", status.dns_name)
        } else {
            format!("https://{}:{}", status.dns_name, config.funnel.port)
        }
    } else {
        format!("tailnet:{tailnet_url}")
    };

    let serving = Serving {
        node: Arc::clone(&node),
        server,
        config: Arc::new(config),
        tailnet: status.tailnet.clone(),
        kill: CancellationToken::new(),
        tasks: TaskTracker::new(),
        runtime: runtime.clone(),
    };
    let mut threads = Vec::new();
    threads.push(spawn_accept(tailnet_listener, false, serving.clone())?);
    if let Some(listener) = funnel_listener {
        threads.push(spawn_accept(listener, true, serving.clone())?);
    }
    Ok(Endpoint {
        _node: node,
        status,
        listeners,
        accept_threads: Mutex::new(threads),
        kill: serving.kill,
        tasks: serving.tasks,
        runtime,
        listen_address,
    })
}

/// A thread that accepts on `listener` until it is closed; `mcpgts_accept`
/// blocks, so it cannot run on the async runtime.
fn spawn_accept(
    listener: shim::Listener,
    funnel: bool,
    serving: Serving,
) -> Result<JoinHandle<()>, String> {
    std::thread::Builder::new()
        .name(
            if funnel {
                "mcpg-ts-funnel"
            } else {
                "mcpg-ts-accept"
            }
            .into(),
        )
        .spawn(move || {
            let mut retry = ACCEPT_RETRY;
            loop {
                match listener.accept() {
                    Ok(shim::Accepted::Conn { fd, remote }) => {
                        retry = ACCEPT_RETRY;
                        accept_one(fd, remote, funnel, &serving);
                    }
                    Ok(shim::Accepted::Closed) => return,
                    Err(e) => {
                        tracing::warn!(
                            plugin_id = PLUGIN_ID,
                            funnel,
                            error = %e,
                            retry_ms = retry.as_millis(),
                            "tailscale accept failed"
                        );
                        std::thread::sleep(retry);
                        retry = (retry * 2).min(ACCEPT_RETRY_MAX);
                    }
                }
            }
        })
        .map_err(|e| format!("tailscale accept thread: {e}"))
}

fn accept_one(fd: OwnedFd, remote: String, funnel: bool, serving: &Serving) {
    let Ok(remote_addr) = remote.parse::<std::net::SocketAddr>() else {
        tracing::warn!(plugin_id = PLUGIN_ID, %remote, "tailscale peer address unreadable; closing");
        return;
    };
    let serving = serving.clone();
    let tasks = serving.tasks.clone();
    let runtime = serving.runtime.clone();
    tasks.spawn_on(
        async move {
            let stream = match unix_stream(fd) {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::warn!(plugin_id = PLUGIN_ID, error = %e, "tailscale connection unusable");
                    return;
                }
            };
            let verdict = if funnel {
                Verdict::Serve(None)
            } else {
                whois_verdict(&serving, remote_addr).await
            };
            let (peer, refusal) = match verdict {
                Verdict::Serve(peer) => (peer, None),
                Verdict::Refuse(refusal) => {
                    tracing::info!(
                        plugin_id = PLUGIN_ID,
                        remote = %remote_addr,
                        reason = %refusal.message,
                        "tailscale peer refused"
                    );
                    (None, Some(refusal))
                }
            };
            let connection = Connection {
                remote_addr,
                peer,
                refusal,
                max_body: serving.config.max_request_body_bytes,
            };
            tokio::select! {
                () = serve_connection(stream, serving.server, connection, "tailscale") => {}
                () = serving.kill.cancelled() => {}
            }
        },
        &runtime,
    );
}

async fn whois_verdict(serving: &Serving, remote: std::net::SocketAddr) -> Verdict {
    let node = Arc::clone(&serving.node);
    let answer = tokio::task::spawn_blocking(move || node.whois(&remote.to_string())).await;
    let policy = &serving.config.identity;
    match answer {
        Ok(Ok(json)) => match serde_json::from_str::<identity::Whois>(&json) {
            Ok(whois) => identity::judge(&whois, policy, &serving.tailnet),
            Err(e) => {
                tracing::warn!(plugin_id = PLUGIN_ID, error = %e, "tailscale whois unreadable");
                identity::judge_unknown(policy)
            }
        },
        Ok(Err(e)) => {
            tracing::warn!(plugin_id = PLUGIN_ID, %remote, error = %e, "tailscale whois failed");
            identity::judge_unknown(policy)
        }
        Err(e) => {
            tracing::warn!(plugin_id = PLUGIN_ID, error = %e, "tailscale whois task failed");
            identity::judge_unknown(policy)
        }
    }
}

fn unix_stream(fd: OwnedFd) -> std::io::Result<tokio::net::UnixStream> {
    let stream = std::os::unix::net::UnixStream::from(fd);
    stream.set_nonblocking(true)?;
    tokio::net::UnixStream::from_std(stream)
}

/// Keep this library mapped for the life of the process: it holds a Go
/// runtime whose threads keep running after the host would unload it.
fn pin_in_memory() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        let anchor = pin_in_memory as *const libc::c_void;
        // SAFETY: dladdr fills `info` for an address inside a loaded object.
        if unsafe { libc::dladdr(anchor, &mut info) } == 0 || info.dli_fname.is_null() {
            tracing::warn!(
                plugin_id = PLUGIN_ID,
                "could not locate the plugin library to pin it"
            );
            return;
        }
        // SAFETY: dli_fname names this already-loaded object; RTLD_NOLOAD
        // only adds the no-delete flag to it and takes a reference that is
        // never released.
        let handle = unsafe {
            libc::dlopen(
                info.dli_fname,
                libc::RTLD_NOW | libc::RTLD_NOLOAD | libc::RTLD_NODELETE,
            )
        };
        if handle.is_null() {
            tracing::warn!(
                plugin_id = PLUGIN_ID,
                "could not pin the plugin library in memory"
            );
        }
    });
}

/// Send the node's log lines to the host log: the backend's debug output at
/// DEBUG, the operator-facing lines (login URLs, state) at INFO, and a
/// request to log in at WARN.
fn route_shim_logs() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| shim::set_log(shim_log));
}

extern "C" fn shim_log(level: c_int, message: *const c_char) {
    if message.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(|| {
        // SAFETY: the shim passes a NUL-terminated string valid for the call.
        let line = unsafe { CStr::from_ptr(message) }.to_string_lossy();
        if level == 0 {
            tracing::debug!(target: "mcpg.plugin.tailscale", "{line}");
        } else if line.contains("To authenticate, visit") || line.contains("login.tailscale.com/a/")
        {
            tracing::warn!(target: "mcpg.plugin.tailscale", "{line}");
        } else {
            tracing::info!(target: "mcpg.plugin.tailscale", "{line}");
        }
    });
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[
        mcpg_plugin_protocol::capability::Capability::NetworkOutbound,
        mcpg_plugin_protocol::capability::Capability::TransportListen,
    ],
    entities: [
        transport as entity {
            inner_name: "",
            plugin_type: TailscaleTransport,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> TailscaleTransport {
                TailscaleTransport::new(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_transports_entry_config_wins_and_the_plugin_config_fills_an_empty_one() {
        let plugin = TailscaleTransport::new(r#"{"hostname":"from-plugin","ephemeral":true}"#);
        let own = plugin
            .config_for(&json!({"hostname": "from-transport", "ephemeral": true}))
            .unwrap();
        assert_eq!(own.hostname, "from-transport");
        for empty in [serde_json::Value::Null, json!({})] {
            assert_eq!(plugin.config_for(&empty).unwrap().hostname, "from-plugin");
        }
    }

    #[test]
    fn it_is_an_http_wire_transport_and_refuses_the_messages_wire() {
        let plugin = TailscaleTransport::new("{}");
        assert_eq!(plugin.wire(), TransportWire::Http);
        let dispatcher: Arc<dyn SyncMessageDispatcher> = Arc::new(NoDispatch);
        let err = plugin.start(&json!({}), dispatcher).err().unwrap();
        assert!(matches!(err, TransportError::InvalidConfig { .. }));
    }

    #[test]
    fn a_bad_config_is_refused_before_the_node_starts() {
        let plugin = TailscaleTransport::new("{}");
        let err = plugin.start_http(&json!({}), never_server()).err().unwrap();
        let TransportError::InvalidConfig { message } = err else {
            panic!("expected InvalidConfig");
        };
        assert!(message.contains("state_dir"), "{message}");
    }

    struct NoDispatch;
    impl SyncMessageDispatcher for NoDispatch {
        fn dispatch(
            &self,
            _session_id: &str,
            _message: &[u8],
        ) -> Result<Vec<u8>, mcpg_plugin_protocol::transport::DispatcherError> {
            unreachable!()
        }
    }

    fn never_server() -> HttpIngressServer {
        HttpIngressServer::from_ffi(mcpg_plugin_protocol::abi::HttpServerRef {
            ctx: 0,
            serve: never_serve,
            cancel: never_cancel,
        })
    }

    extern "C" fn never_serve(
        _: usize,
        _: mcpg_plugin_sdk::abi_stable::std_types::RString,
        _: mcpg_plugin_sdk::abi_stable::std_types::RVec<u8>,
        _: mcpg_plugin_protocol::abi::HttpResponderRef,
    ) -> u64 {
        unreachable!()
    }

    extern "C" fn never_cancel(_: usize, _: u64) {}
}

#[cfg(all(test, feature = "test-control"))]
mod tailnet_tests;
