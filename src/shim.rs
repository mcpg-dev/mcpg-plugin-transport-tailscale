//! The Go shim (`tsshim/`): a Tailscale node as C functions.
//!
//! The shim is linked into the same library as this code: the shipped build
//! of the archive, or with the `test-control` feature its test build.

use std::ffi::{CStr, CString, c_char, c_int};
use std::os::fd::{FromRawFd, OwnedFd};

unsafe extern "C" {
    fn mcpgts_set_log(callback: Option<extern "C" fn(c_int, *const c_char)>);
    fn mcpgts_new(config_json: *const c_char, err: *mut *mut c_char) -> i64;
    fn mcpgts_up(
        node: i64,
        timeout_ms: c_int,
        status: *mut *mut c_char,
        err: *mut *mut c_char,
    ) -> c_int;
    fn mcpgts_listen(node: i64, mode: *const c_char, port: c_int, err: *mut *mut c_char) -> i64;
    fn mcpgts_accept(
        listener: i64,
        fd: *mut c_int,
        remote: *mut *mut c_char,
        err: *mut *mut c_char,
    ) -> c_int;
    fn mcpgts_whois(
        node: i64,
        remote: *const c_char,
        out: *mut *mut c_char,
        err: *mut *mut c_char,
    ) -> c_int;
    fn mcpgts_close_listener(listener: i64);
    fn mcpgts_close(node: i64);
    fn mcpgts_free(p: *mut c_char);
}

/// Take a shim-allocated string.
fn take(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: the shim returns NUL-terminated malloc'd strings; this is the
    // only owner, and it frees the string with the shim's allocator.
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    unsafe { mcpgts_free(p) };
    Some(s)
}

fn cstring(s: &str) -> Result<CString, String> {
    CString::new(s).map_err(|_| "a NUL byte in a shim argument".to_owned())
}

fn shim_error(err: *mut c_char, what: &str) -> String {
    take(err).unwrap_or_else(|| format!("{what} failed"))
}

/// Route the shim's log lines to `callback` (level 0: backend debug,
/// level 1: operator-facing).
pub fn set_log(callback: extern "C" fn(c_int, *const c_char)) {
    // SAFETY: the callback is a plain function with the expected signature.
    unsafe { mcpgts_set_log(Some(callback)) };
}

/// One tailnet node. Dropping it closes the node; an ephemeral one leaves
/// the tailnet.
#[derive(Debug)]
pub struct Node(i64);

impl Node {
    /// A node from its JSON settings; it connects on [`Node::up`].
    pub fn new(settings_json: &str) -> Result<Self, String> {
        let cfg = cstring(settings_json)?;
        let mut err = std::ptr::null_mut();
        // SAFETY: valid C string; `err` receives a shim string or stays null.
        let handle = unsafe { mcpgts_new(cfg.as_ptr(), &mut err) };
        if handle == 0 {
            return Err(shim_error(err, "creating the node"));
        }
        Ok(Self(handle))
    }

    /// Connect and wait until the node runs; returns its status JSON.
    /// Blocks the calling thread.
    pub fn up(&self, timeout: std::time::Duration) -> Result<String, String> {
        let ms = c_int::try_from(timeout.as_millis()).unwrap_or(c_int::MAX);
        let (mut status, mut err) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: live handle; out-pointers receive shim strings.
        let rc = unsafe { mcpgts_up(self.0, ms, &mut status, &mut err) };
        if rc != 0 {
            return Err(shim_error(err, "bringing the node up"));
        }
        Ok(take(status).unwrap_or_default())
    }

    /// Open a listener: `mode` is `tcp`, `tls` or `funnel`.
    pub fn listen(&self, mode: &str, port: u16) -> Result<Listener, String> {
        let mode = cstring(mode)?;
        let mut err = std::ptr::null_mut();
        // SAFETY: live handle, valid C string.
        let handle = unsafe { mcpgts_listen(self.0, mode.as_ptr(), c_int::from(port), &mut err) };
        if handle == 0 {
            return Err(shim_error(err, "opening the listener"));
        }
        Ok(Listener(handle))
    }

    /// Who owns the tailnet peer at `remote` (`ip:port`); the whois JSON.
    /// Blocks the calling thread (at most 5 s).
    pub fn whois(&self, remote: &str) -> Result<String, String> {
        let remote = cstring(remote)?;
        let (mut out, mut err) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: live handle, valid C string, out-pointers as above.
        let rc = unsafe { mcpgts_whois(self.0, remote.as_ptr(), &mut out, &mut err) };
        if rc != 0 {
            return Err(shim_error(err, "whois"));
        }
        Ok(take(out).unwrap_or_default())
    }

    #[cfg(feature = "test-control")]
    pub(crate) fn handle(&self) -> i64 {
        self.0
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        // SAFETY: the handle came from mcpgts_new and is closed once.
        unsafe { mcpgts_close(self.0) };
    }
}

/// What a listener's [`Listener::accept`] yields.
pub enum Accepted {
    Conn { fd: OwnedFd, remote: String },
    Closed,
}

/// A listener on a node. [`Listener::close`] ends a waiting accept.
#[derive(Debug, Clone, Copy)]
pub struct Listener(i64);

impl Listener {
    /// The next connection; blocks the calling thread.
    pub fn accept(self) -> Result<Accepted, String> {
        let (mut fd, mut remote, mut err) = (-1, std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: the handle came from mcpgts_listen; out-pointers as above.
        let rc = unsafe { mcpgts_accept(self.0, &mut fd, &mut remote, &mut err) };
        match rc {
            0 => {
                // SAFETY: the shim hands this end of the socketpair over;
                // nothing else owns it.
                let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Ok(Accepted::Conn {
                    fd,
                    remote: take(remote).unwrap_or_default(),
                })
            }
            1 => Ok(Accepted::Closed),
            _ => Err(shim_error(err, "accept")),
        }
    }

    pub fn close(self) {
        // SAFETY: closing an unknown or closed handle is a no-op in the shim.
        unsafe { mcpgts_close_listener(self.0) };
    }
}

/// The test-only exports of the shim's `mcpgts_testing` build.
#[cfg(feature = "test-control")]
pub mod testing {
    use super::{cstring, shim_error, take};
    use std::ffi::{c_char, c_int};
    use std::os::fd::{FromRawFd, OwnedFd};

    unsafe extern "C" {
        fn mcpgts_test_control_start(
            config_json: *const c_char,
            url: *mut *mut c_char,
            err: *mut *mut c_char,
        ) -> c_int;
        fn mcpgts_test_control_stop();
        fn mcpgts_dial(
            node: i64,
            addr: *const c_char,
            fd: *mut c_int,
            err: *mut *mut c_char,
        ) -> c_int;
    }

    /// Start the in-process control server; returns its URL.
    pub fn start_control(config_json: &str) -> Result<String, String> {
        let cfg = cstring(config_json)?;
        let (mut url, mut err) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: valid C string; out-pointers receive shim strings.
        let rc = unsafe { mcpgts_test_control_start(cfg.as_ptr(), &mut url, &mut err) };
        if rc != 0 {
            return Err(shim_error(err, "starting the test control"));
        }
        Ok(take(url).unwrap_or_default())
    }

    pub fn stop_control() {
        // SAFETY: stopping a stopped control is a no-op.
        unsafe { mcpgts_test_control_stop() };
    }

    /// Dial `addr` on the tailnet from `node`.
    pub fn dial(node: &super::Node, addr: &str) -> Result<OwnedFd, String> {
        let addr = cstring(addr)?;
        let (mut fd, mut err) = (-1, std::ptr::null_mut());
        // SAFETY: live node handle, valid C string.
        let rc = unsafe { mcpgts_dial(node.handle(), addr.as_ptr(), &mut fd, &mut err) };
        if rc != 0 {
            return Err(shim_error(err, "dial"));
        }
        // SAFETY: the shim hands this end of the socketpair over.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}
