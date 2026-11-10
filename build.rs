//! Builds the Go shim (`tsshim/`) as a C archive and links it into the
//! crate.
//!
//! Needs `go` on PATH (or `GO`); a go.mod newer than the installed toolchain
//! is fetched by Go's own toolchain switching. A cross build names its C
//! compiler in `CC_<target>` (as the `cc` crate reads it).

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=tsshim");
    println!("cargo:rerun-if-env-changed=GO");
    let target = env::var("TARGET").expect("TARGET");
    let os = env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS");
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH");
    if os == "windows" {
        panic!(
            "dev.mcpg.transport.tailscale does not build for Windows: the shim hands connections over as socketpairs"
        );
    }
    if target_env == "musl" {
        panic!(
            "dev.mcpg.transport.tailscale does not build for musl: musl cannot dlopen the Go runtime's initial-exec TLS"
        );
    }
    let goos = match os.as_str() {
        "linux" => "linux",
        "macos" => "darwin",
        other => panic!("dev.mcpg.transport.tailscale: unsupported target OS {other}"),
    };
    let goarch = match arch.as_str() {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => panic!("dev.mcpg.transport.tailscale: unsupported target arch {other}"),
    };
    let testing = env::var_os("CARGO_FEATURE_TEST_CONTROL").is_some();
    let tags = if testing {
        "netgo,osusergo,mcpgts_testing"
    } else {
        "netgo,osusergo"
    };
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let go = env::var("GO").unwrap_or_else(|_| "go".into());
    let mut cmd = Command::new(&go);
    cmd.current_dir(manifest.join("tsshim"))
        // -buildvcs=false: the archive needs no VCS stamp, and git refuses a
        // checkout owned by another user (a build container's mounted
        // tree), which would fail the build.
        .args([
            "build",
            "-buildmode=c-archive",
            "-buildvcs=false",
            "-trimpath",
            "-tags",
            tags,
            "-o",
        ])
        .arg(out.join("libmcpgts.a"))
        .arg(".")
        .env("CGO_ENABLED", "1")
        .env("GOOS", goos)
        .env("GOARCH", goarch);
    let cc_var = format!("CC_{}", target.replace('-', "_"));
    println!("cargo:rerun-if-env-changed={cc_var}");
    if let Ok(cc) = env::var(&cc_var) {
        cmd.env("CC", cc);
    }
    let status = cmd.status().unwrap_or_else(|e| {
        panic!("dev.mcpg.transport.tailscale needs Go to build its shim ({go}): {e}")
    });
    assert!(status.success(), "building the Go shim failed: {status}");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=mcpgts");
    if goos == "darwin" {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
    } else {
        println!("cargo:rustc-link-lib=dylib=pthread");
    }
}
