//! Build script for `libdatachannel-rust`.
//!
//! Compiles the vendored usrsctp C library (0.9.5.0) via the `cc` crate
//! and generates Rust FFI bindings for `usrsctp.h` via `bindgen`. The
//! C sources live under
//! `native/libdatachannel/deps/usrsctp/usrsctplib/` and are NOT vendored
//! into this crate's git repo — they're referenced in place by relative
//! path. The generated bindings land in `OUT_DIR` (under `target/`, which
//! is gitignored), so nothing C enters version control.
//!
//! The compile defines and the per-OS flag selection mirror
//! `usrsctplib/CMakeLists.txt` exactly so the later x86_64-Linux
//! cross-compile keeps working.

use std::env;
use std::path::PathBuf;

fn main() {
    // Path to the vendored usrsctp sources, relative to this crate's
    // manifest dir (rust/libdatachannel-rust/). Three levels up reaches
    // the `native/` root.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let usrsctplib = manifest_dir
        .join("../../libdatachannel/deps/usrsctp/usrsctplib")
        .canonicalize()
        .expect("usrsctp usrsctplib dir not found");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    // The 23 source files listed as `usrsctp_sources` in
    // usrsctplib/CMakeLists.txt (lines 159-183). Kept in the same order
    // for parity; order is irrelevant to a static-lib build.
    let sources = [
        "netinet/sctp_asconf.c",
        "netinet/sctp_auth.c",
        "netinet/sctp_bsd_addr.c",
        "netinet/sctp_callout.c",
        "netinet/sctp_cc_functions.c",
        "netinet/sctp_crc32.c",
        "netinet/sctp_indata.c",
        "netinet/sctp_input.c",
        "netinet/sctp_output.c",
        "netinet/sctp_pcb.c",
        "netinet/sctp_peeloff.c",
        "netinet/sctp_sha1.c",
        "netinet/sctp_ss_functions.c",
        "netinet/sctp_sysctl.c",
        "netinet/sctp_timer.c",
        "netinet/sctp_userspace.c",
        "netinet/sctp_usrreq.c",
        "netinet/sctputil.c",
        "netinet6/sctp6_usrreq.c",
        "user_environment.c",
        "user_mbuf.c",
        "user_recv_thread.c",
        "user_socket.c",
    ];

    let mut build = cc::Build::new();
    build.include(&usrsctplib);

    // Defines for ALL targets (usrsctplib/CMakeLists.txt lines 58-60).
    //
    // NOTE: We deliberately do NOT define INET / INET6. libdatachannel builds
    // usrsctp with `sctp_inet OFF` / `sctp_inet6 OFF` (its top-level
    // CMakeLists.txt) so the stack operates in AF_CONN-only mode. With INET /
    // INET6 enabled, usrsctp tries to enumerate the host's real interfaces and
    // `usrsctp_bind` on a registered AF_CONN address fails with EADDRNOTAVAIL.
    // The defines must match exactly between the C compile and bindgen below.
    build
        .define("__Userspace__", None)
        .define("SCTP_SIMPLE_ALLOCATOR", None)
        .define("SCTP_PROCESS_LEVEL_LOCKS", None);

    // Feature defines from usrsctp's deps CMakeLists.txt (the
    // check_struct_has_member / check_include_files probes). These are
    // platform-stable for our targets, so we key them off CARGO_CFG_TARGET_OS
    // rather than re-running compiler probes. `HAVE_SCONN_LEN` in particular is
    // load-bearing: it adds the leading `sconn_len` byte to `struct
    // sockaddr_conn`, which both the C lib and `sockaddr_conn()` in
    // sctp_transport.rs assume on Apple targets.
    build
        .define("HAVE_SYS_QUEUE_H", None)
        .define("HAVE_NETINET_IP_ICMP_H", None)
        .define("HAVE_NET_ROUTE_H", None)
        .define("HAVE_STDATOMIC_H", None);

    // Per-OS defines (usrsctplib/CMakeLists.txt + deps/usrsctp/CMakeLists.txt).
    // Keying off CARGO_CFG_TARGET_OS keeps the x86_64-Linux cross-compile honest.
    match target_os.as_str() {
        "macos" | "ios" => {
            build
                .define("__APPLE_USE_RFC_2292", None)
                .define("HAVE_SA_LEN", None)
                .define("HAVE_SIN_LEN", None)
                .define("HAVE_SIN6_LEN", None)
                .define("HAVE_SCONN_LEN", None);
        }
        "linux" | "android" => {
            build
                .define("_GNU_SOURCE", None)
                .define("HAVE_LINUX_IF_ADDR_H", None)
                .define("HAVE_LINUX_RTNETLINK_H", None);
        }
        _ => {}
    }

    // usrsctp is extremely noisy (packed-member, deprecated-decl, sign
    // conversions, ...). Silence everything so the build log stays usable;
    // CMakeLists.txt selectively disables -Wno-address-of-packed-member /
    // -Wno-deprecated-declarations, but `-w` is a superset and harmless
    // for a vendored dependency.
    build.flag_if_supported("-w");

    for src in &sources {
        build.file(usrsctplib.join(src));
        println!("cargo:rerun-if-changed={}", usrsctplib.join(src).display());
    }

    build.compile("usrsctp");

    // --- bindgen -----------------------------------------------------------

    let header = usrsctplib.join("usrsctp.h");
    println!("cargo:rerun-if-changed={}", header.display());

    let mut builder = bindgen::Builder::default()
        .header(header.to_string_lossy())
        .clang_arg(format!("-I{}", usrsctplib.display()))
        .clang_arg("-D__Userspace__")
        .clang_arg("-DSCTP_SIMPLE_ALLOCATOR")
        .clang_arg("-DSCTP_PROCESS_LEVEL_LOCKS")
        // Must mirror the C compile defines above (no INET / INET6).
        // Functions: the whole usrsctp_ surface.
        .allowlist_function("usrsctp_.*")
        // Structs / unions used by the transport.
        .allowlist_type("sockaddr_conn")
        .allowlist_type("sctp_sendv_spa")
        .allowlist_type("sctp_sndinfo")
        .allowlist_type("sctp_prinfo")
        .allowlist_type("sctp_authinfo")
        .allowlist_type("sctp_rcvinfo")
        .allowlist_type("sctp_assoc_value")
        .allowlist_type("sctp_event")
        .allowlist_type("sctp_paddrparams")
        .allowlist_type("sctp_initmsg")
        .allowlist_type("sctp_reset_streams")
        .allowlist_type("sctp_status")
        .allowlist_type("sctp_notification")
        .allowlist_type("sctp_assoc_change")
        .allowlist_type("sctp_stream_reset_event")
        .allowlist_type("sctp_sender_dry_event")
        .allowlist_type("sctp_paddr_change")
        .allowlist_type("socket")
        .derive_default(true)
        .layout_tests(false)
        // The workspace uses edition 2024, where `unsafe-op-in-unsafe-fn`
        // is a hard error. bindgen's generated union accessors call
        // `transmute` inside `unsafe fn` bodies without an inner `unsafe`
        // block; `wrap_unsafe_ops` makes bindgen emit those blocks.
        .wrap_unsafe_ops(true)
        .generate_comments(false);

    // HAVE_SCONN_LEN changes the `sockaddr_conn` layout, so bindgen must see
    // the same per-OS defines as the C compile.
    match target_os.as_str() {
        "macos" | "ios" => {
            builder = builder
                .clang_arg("-D__APPLE_USE_RFC_2292")
                .clang_arg("-DHAVE_SA_LEN")
                .clang_arg("-DHAVE_SIN_LEN")
                .clang_arg("-DHAVE_SIN6_LEN")
                .clang_arg("-DHAVE_SCONN_LEN");
        }
        "linux" | "android" => {
            builder = builder.clang_arg("-D_GNU_SOURCE");
        }
        _ => {}
    }

    let bindings = builder.generate().expect("bindgen failed for usrsctp.h");

    // The workspace is edition 2024, which requires `unsafe extern` blocks.
    // bindgen 0.70 still emits bare `extern "C" { ... }`, so rewrite the
    // block headers to `unsafe extern "C"`. The bodies are FFI fn decls,
    // unaffected by the change.
    let src = bindings.to_string();
    let src = src.replace("extern \"C\" {", "unsafe extern \"C\" {");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    std::fs::write(out_dir.join("usrsctp_bindings.rs"), src)
        .expect("failed to write usrsctp bindings");
}
