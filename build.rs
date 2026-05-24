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
    build_usrsctp();
    build_libsrtp2();
}

fn build_usrsctp() {
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

/// Compile the vendored libsrtp2 (2.7.0) C library via the `cc` crate and
/// generate Rust FFI bindings for `srtp.h` via `bindgen`. Mirrors
/// [`build_usrsctp`] and the usrsctp precedent exactly.
///
/// ## Crypto backend: OpenSSL
///
/// libdatachannel builds libsrtp2 with `ENABLE_OPENSSL ON` by default (its
/// top-level CMakeLists picks OpenSSL unless `USE_GNUTLS`/`USE_MBEDTLS`), which
/// provides BOTH `SRTP_AES128_CM_SHA1_80` AND `SRTP_AEAD_AES_128_GCM` — the two
/// profiles the C++ `DtlsSrtpTransport` negotiates. OpenSSL is already an FFI
/// dependency of this crate (DTLS lives on it), so we reuse it rather than
/// vendoring libsrtp's builtin AES/SHA1 (which would only give CM_SHA1 and
/// couples us to a different profile list than the reference). `openssl-sys`
/// exports `DEP_OPENSSL_INCLUDE` to this build script, so the OpenSSL headers
/// resolve for both the native and the x86_64-linux cross build.
///
/// ## config.h
///
/// libsrtp2 is normally cmake-built from `config_in_cmake.h`. We generate the
/// equivalent `config.h` into `OUT_DIR` with the knobs the CMake template
/// computes: `OPENSSL`/`GCM` (backend), `CPU_CISC` (all our targets are CISC —
/// x86_64 and arm64 both do cheap unaligned byte access), the `HAVE_*_H`
/// header probes (stable for our Unix targets), and `WORDS_BIGENDIAN`/`HAVE_X86`
/// gated on `CARGO_CFG_TARGET_*` so the cross build stays honest.
fn build_libsrtp2() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let libsrtp = manifest_dir
        .join("../../libdatachannel/deps/libsrtp")
        .canonicalize()
        .expect("libsrtp deps dir not found");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_endian = env::var("CARGO_CFG_TARGET_ENDIAN").unwrap_or_default();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // OpenSSL include dir, exported by the `openssl-sys` build script to its
    // dependents (us). Falls back to nothing if unset (system headers on PATH).
    let openssl_include = env::var("DEP_OPENSSL_INCLUDE").ok();

    // --- generate config.h -------------------------------------------------
    //
    // Mirrors `configure_file(config_in_cmake.h -> config.h)` with the values
    // the CMake probes resolve to for our targets.
    let mut config = String::new();
    config.push_str("/* Generated by build.rs — libsrtp2 config (OpenSSL backend). */\n");
    config.push_str("#define PACKAGE_VERSION \"2.7.0\"\n");
    config.push_str("#define PACKAGE_STRING \"libsrtp2 2.7.0\"\n");
    // OpenSSL crypto backend + GCM (CMake sets GCM = ENABLE_OPENSSL).
    config.push_str("#define OPENSSL 1\n");
    config.push_str("#define GCM 1\n");
    // All targets we build for (x86_64, aarch64) are CISC-style: cheap
    // unaligned access. libsrtp only uses CPU_RISC to force byte-wise loads.
    config.push_str("#define CPU_CISC 1\n");
    // Inlined x86 asm only on x86 (matches CMake: HAVE_X86 on non-Apple x86).
    if target_arch == "x86_64" || target_arch == "x86" {
        config.push_str("#define HAVE_X86 1\n");
    }
    if target_endian == "big" {
        config.push_str("#define WORDS_BIGENDIAN 1\n");
    }
    // Header probes — stable across our Unix (macOS/Linux) targets.
    for def in [
        "HAVE_ARPA_INET_H",
        "HAVE_INTTYPES_H",
        "HAVE_NETINET_IN_H",
        "HAVE_STDINT_H",
        "HAVE_STDLIB_H",
        "HAVE_SYS_TYPES_H",
        "HAVE_SYS_SOCKET_H",
        "HAVE_UNISTD_H",
        "HAVE_INT32_T",
        "HAVE_UINT8_T",
        "HAVE_UINT16_T",
        "HAVE_UINT32_T",
        "HAVE_UINT64_T",
        "HAVE_INET_ATON",
        "HAVE_INET_PTON",
        "HAVE_SIGACTION",
        "HAVE_USLEEP",
        "HAVE_INLINE",
    ] {
        config.push_str(&format!("#define {def} 1\n"));
    }
    // macOS provides <machine/types.h>; Linux provides <byteswap.h>.
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match target_os.as_str() {
        "macos" | "ios" => config.push_str("#define HAVE_MACHINE_TYPES_H 1\n"),
        "linux" | "android" => config.push_str("#define HAVE_BYTESWAP_H 1\n"),
        _ => {}
    }
    let config_path = out_dir.join("srtp-config");
    std::fs::create_dir_all(&config_path).expect("create srtp-config dir");
    std::fs::write(config_path.join("config.h"), &config)
        .expect("failed to write libsrtp config.h");

    // --- source list (mirrors deps/libsrtp/CMakeLists.txt, OpenSSL branch) --
    let sources = [
        "srtp/srtp.c",
        "crypto/cipher/cipher.c",
        "crypto/cipher/null_cipher.c",
        // Self-test vectors (factored out of the cipher/hash impls in
        // libsrtp 2.6+; the OpenSSL backends reference these symbols).
        "crypto/cipher/cipher_test_cases.c",
        "crypto/hash/auth_test_cases.c",
        // OpenSSL cipher backend.
        "crypto/cipher/aes_icm_ossl.c",
        "crypto/cipher/aes_gcm_ossl.c",
        "crypto/hash/auth.c",
        "crypto/hash/null_auth.c",
        // OpenSSL hash backend.
        "crypto/hash/hmac_ossl.c",
        "crypto/kernel/alloc.c",
        "crypto/kernel/crypto_kernel.c",
        "crypto/kernel/err.c",
        "crypto/kernel/key.c",
        "crypto/math/datatypes.c",
        "crypto/replay/rdb.c",
        "crypto/replay/rdbx.c",
    ];

    let mut build = cc::Build::new();
    build
        .include(&config_path) // config.h
        .include(libsrtp.join("include"))
        .include(libsrtp.join("crypto/include"))
        .define("HAVE_CONFIG_H", None);
    if let Some(inc) = &openssl_include {
        // OpenSSL may export several include dirs separated by the platform
        // path separator; add each.
        for p in env::split_paths(inc) {
            build.include(p);
        }
    }
    // libsrtp is warning-clean under its own flags but noisy under ours; the
    // CMake build treats warnings as errors with a curated set. `-w` keeps the
    // vendored compile quiet, matching the usrsctp treatment above.
    build.flag_if_supported("-w");

    for src in &sources {
        build.file(libsrtp.join(src));
        println!("cargo:rerun-if-changed={}", libsrtp.join(src).display());
    }

    build.compile("srtp2");

    // --- bindgen -----------------------------------------------------------

    let header = libsrtp.join("include/srtp.h");
    println!("cargo:rerun-if-changed={}", header.display());

    let mut builder = bindgen::Builder::default()
        .header(header.to_string_lossy())
        .clang_arg(format!("-I{}", config_path.display()))
        .clang_arg(format!("-I{}", libsrtp.join("include").display()))
        .clang_arg(format!("-I{}", libsrtp.join("crypto/include").display()))
        .clang_arg("-DHAVE_CONFIG_H")
        // Functions: the whole srtp_ surface.
        .allowlist_function("srtp_.*")
        // Profile enum + status + policy structs.
        .allowlist_type("srtp_.*")
        .allowlist_var("srtp_.*")
        .allowlist_var("SRTP_.*")
        // The ssrc-type wildcard constants (ssrc_any_inbound/outbound) live in
        // an anonymous-ish enum; allowlist them explicitly.
        .allowlist_var("ssrc_.*")
        .derive_default(true)
        .layout_tests(false)
        .wrap_unsafe_ops(true)
        .generate_comments(false);
    if let Some(inc) = &openssl_include {
        for p in env::split_paths(inc) {
            builder = builder.clang_arg(format!("-I{}", p.display()));
        }
    }

    let bindings = builder.generate().expect("bindgen failed for srtp.h");

    // Edition 2024 requires `unsafe extern` blocks (see usrsctp note above).
    let src = bindings.to_string();
    let src = src.replace("extern \"C\" {", "unsafe extern \"C\" {");
    std::fs::write(out_dir.join("srtp_bindings.rs"), src)
        .expect("failed to write srtp bindings");
}
