//! Real tailnet tests: an in-process control server with DERP and STUN on
//! 127.0.0.1, the plugin's node, and a client node that dials it. No account
//! and no network.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use mcpg_plugin_protocol::abi::{HTTP_SINK_ACCEPTED, HttpResponderRef, HttpServerRef};
use mcpg_plugin_protocol::transport::{HttpIngressRequestHead, HttpIngressResponseHead};
use mcpg_plugin_sdk::abi_stable::std_types::{RString, RVec};
use serde_json::json;

use super::*;

const CAP: &str = "example.com/cap/mcpg";

/// Every request the fake gateway saw.
static SEEN: Mutex<Vec<HttpIngressRequestHead>> = Mutex::new(Vec::new());

/// The fake gateway: answers 200 with the attested subject, or `anonymous`.
extern "C" fn record_serve(
    _ctx: usize,
    head_json: RString,
    _body: RVec<u8>,
    r: HttpResponderRef,
) -> u64 {
    let head: HttpIngressRequestHead = serde_json::from_str(head_json.as_str()).unwrap();
    let who = head
        .peer
        .as_ref()
        .map_or_else(|| "anonymous".to_owned(), |p| p.subject_id.clone());
    SEEN.lock().unwrap().push(head);
    let reply = HttpIngressResponseHead {
        status: 200,
        headers: vec![("content-type".into(), "text/plain".into())],
    };
    assert_eq!(
        (r.head)(r.ctx, RString::from(serde_json::to_string(&reply).unwrap())),
        HTTP_SINK_ACCEPTED
    );
    (r.chunk)(r.ctx, RVec::from(who.into_bytes()));
    (r.end)(r.ctx, RString::new());
    1
}

extern "C" fn no_cancel(_ctx: usize, _id: u64) {}

fn fake_gateway() -> HttpIngressServer {
    HttpIngressServer::from_ffi(HttpServerRef {
        ctx: 0x1,
        serve: record_serve,
        cancel: no_cancel,
    })
}

fn endpoint(handle: &SyncTransportHandle) -> &Endpoint {
    // SAFETY: the handle `start_http` returned, alive until the test drops it.
    unsafe { &*(handle.handle as *const Endpoint) }
}

/// GET / from `client` to `addr` on the tailnet; status and body. Retries
/// the dial while the nodes still find each other.
fn get(rt: &tokio::runtime::Runtime, client: &shim::Node, addr: &str) -> (u16, String) {
    let deadline = Instant::now() + Duration::from_secs(60);
    let fd = loop {
        match shim::testing::dial(client, addr) {
            Ok(fd) => break fd,
            Err(e) if Instant::now() < deadline => {
                eprintln!("dial {addr}: {e}; retrying");
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(e) => panic!("dial {addr}: {e}"),
        }
    };
    rt.block_on(async move {
        let stream = unix_stream(fd).unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);
        let request = hyper::Request::get("/")
            .header("host", "gw")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(30), sender.send_request(request))
            .await
            .expect("the gateway answers in time")
            .unwrap();
        let status = response.status().as_u16();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    })
}

fn start(
    plugin: &TailscaleTransport,
    control_url: &str,
    hostname: &str,
    identity: serde_json::Value,
) -> SyncTransportHandle {
    plugin
        .start_http(
            &json!({
                "hostname": hostname,
                "ephemeral": true,
                "control_url": control_url,
                "listen": {"mode": "http"},
                "identity": identity,
            }),
            fake_gateway(),
        )
        .unwrap_or_else(|e| panic!("start_http {hostname}: {e}"))
}

#[test]
fn a_tailnet_peer_reaches_the_gateway_with_its_identity_and_capability_grants() {
    let control_url = shim::testing::start_control(
        &json!({
            "app_caps": {CAP: [{"roles": ["admin"], "scopes": ["tools:call"]}]},
            "magic_dns_domain": "tail-test.ts.net"
        })
        .to_string(),
    )
    .expect("test control starts");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let plugin = TailscaleTransport::new("{}");

    // Granted: the capability's roles and scopes ride on the attested peer.
    let open = start(&plugin, &control_url, "gw", json!({"capability": CAP}));
    let gw = endpoint(&open);
    assert_eq!(gw.listen_address, "tailnet:http://gw.tail-test.ts.net");
    let gw_ip = gw.status.ips.as_ref().unwrap()[0].clone();

    let client_dir = tempfile::tempdir().unwrap();
    let client = shim::Node::new(
        &json!({
            "dir": client_dir.path().display().to_string(),
            "hostname": "client",
            "control_url": control_url,
            "ephemeral": true
        })
        .to_string(),
    )
    .unwrap();
    client
        .up(Duration::from_secs(60))
        .expect("the client node comes up");

    let (status, body) = get(&rt, &client, &format!("{gw_ip}:80"));
    assert_eq!(status, 200, "{body}");
    let head = SEEN
        .lock()
        .unwrap()
        .last()
        .cloned()
        .expect("the gateway saw the request");
    let peer = head.peer.expect("the request carries the attested peer");
    assert_eq!(body, peer.subject_id);
    assert_eq!(peer.provider, "tailscale");
    assert_eq!(peer.trust_level, "verified");
    assert!(!peer.subject_id.is_empty() && peer.subject_id != "tagged-devices");
    assert_eq!(peer.roles, ["admin"]);
    assert_eq!(peer.scopes, ["tools:call"]);
    assert!(
        peer.attributes["tailscale.node"].starts_with("client"),
        "{:?}",
        peer.attributes
    );
    assert!(
        head.remote_addr.as_deref().unwrap().starts_with("100."),
        "the client's tailnet address keys the rate limit: {:?}",
        head.remote_addr
    );

    // Required but not granted: a local 403, the gateway never sees it.
    let refused = start(
        &plugin,
        &control_url,
        "gw2",
        json!({"capability": "example.com/cap/other", "require_capability": true}),
    );
    let gw2_ip = endpoint(&refused).status.ips.as_ref().unwrap()[0].clone();
    let before = SEEN.lock().unwrap().len();
    let (status, body) = get(&rt, &client, &format!("{gw2_ip}:80"));
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("example.com/cap/other"), "{body}");
    assert_eq!(SEEN.lock().unwrap().len(), before);

    // trust_level none: served, with no identity.
    let anonymous = start(&plugin, &control_url, "gw3", json!({"trust_level": "none"}));
    let gw3_ip = endpoint(&anonymous).status.ips.as_ref().unwrap()[0].clone();
    let (status, body) = get(&rt, &client, &format!("{gw3_ip}:80"));
    assert_eq!((status, body.as_str()), (200, "anonymous"));

    for handle in [open, refused, anonymous] {
        plugin.transport_handle_drop(WatchHandleBox(handle.handle));
    }
    drop(client);
    shim::testing::stop_control();
}
