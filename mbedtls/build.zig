const std = @import("std");

// const find_build_sources = @import("find-build-sources.zig");

fn is_c_file(path: []const u8) bool {
    return std.mem.endsWith(u8, path, ".c");
}

const build_flags = .{
    "-std=gnu17",
    "-Werror",
    "-Wall", "-Wextra", "-Wpedantic",
};

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mbedtls_dep = b.dependency("mbedtls", .{});


    const crypto = b.addStaticLibrary(.{
        .name = "mbedcrypto",
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    crypto.addIncludePath(mbedtls_dep.path("include"));

    // TODO: when updating mbedtls, development release currently reorganizes files like this:
//     const crypto_core = try find_build_sources.find(mbedtls_dep.builder, "tf-psa-crypto/core", is_c_file);
//     defer crypto_core.deinit();
//     const crypto_drivers = try find_build_sources.find(mbedtls_dep.builder, "tf-psa-crypto/drivers/builtin/src", is_c_file);
//     defer crypto_drivers.deinit();
//     crypto.addCSourceFiles(.{
//         .root = crypto_core.directory.dupe(b),
//         .files = crypto_core.inner,
//         .flags = &build_flags,
//     });
//     crypto.addCSourceFiles(.{
//         .root = crypto_drivers.directory.dupe(b),
//         .files = crypto_drivers.inner,
//         .flags = &build_flags,
//     });
    crypto.addCSourceFiles(.{
        .root = mbedtls_dep.path("library"),
        .files = &crypto_sources,
        .flags = &build_flags,
    });
    b.installArtifact(crypto);



    const x509 = b.addStaticLibrary(.{
        .name = "mbedx509",
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    x509.addIncludePath(mbedtls_dep.path("include"));

    x509.addCSourceFiles(.{
        .root = mbedtls_dep.path("library"),
        .files = &x509_sources,
        .flags = &build_flags,
    });

    x509.linkLibrary(crypto);
    b.installArtifact(x509);



    const tls = b.addStaticLibrary(.{
        .name = "mbedtls",
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    tls.addIncludePath(mbedtls_dep.path("include"));
    tls.addCSourceFiles(.{
        .root = mbedtls_dep.path("library"),
        .files = &tls_sources,
        .flags = &build_flags,
    });

    tls.linkLibrary(crypto);
    tls.linkLibrary(x509);

    tls.installHeadersDirectory(mbedtls_dep.path("include/mbedtls"), "mbedtls", .{});
    tls.installHeadersDirectory(mbedtls_dep.path("include/psa"), "psa", .{});


    b.installArtifact(tls);
}

const crypto_sources = .{
    "aes.c",
    "aesni.c",
    "aesce.c",
    "aria.c",
    "asn1parse.c",
    "asn1write.c",
    "base64.c",
    "bignum.c",
    "bignum_core.c",
    "bignum_mod.c",
    "bignum_mod_raw.c",
//     "block_cipher.c",
    "camellia.c",
    "ccm.c",
    "chacha20.c",
    "chachapoly.c",
    "cipher.c",
    "cipher_wrap.c",
    "constant_time.c",
    "cmac.c",
    "ctr_drbg.c",
    "des.c",
    "dhm.c",
    "ecdh.c",
    "ecdsa.c",
    "ecjpake.c",
    "ecp.c",
    "ecp_curves.c",
    "ecp_curves_new.c",
    "entropy.c",
    "entropy_poll.c",
    "error.c",
    "gcm.c",
    "hkdf.c",
    "hmac_drbg.c",
    "lmots.c",
    "lms.c",
    "md.c",
    "md5.c",
    "memory_buffer_alloc.c",
    "nist_kw.c",
    "oid.c",
    "padlock.c",
    "pem.c",
    "pk.c",
//     "pk_ecc.c",
    "pk_wrap.c",
    "pkcs12.c",
    "pkcs5.c",
    "pkparse.c",
    "pkwrite.c",
    "platform.c",
    "platform_util.c",
    "poly1305.c",
    "psa_crypto.c",
    "psa_crypto_aead.c",
    "psa_crypto_cipher.c",
    "psa_crypto_client.c",
    "psa_crypto_driver_wrappers_no_static.c",
    "psa_crypto_ecp.c",
    "psa_crypto_ffdh.c",
    "psa_crypto_hash.c",
    "psa_crypto_mac.c",
    "psa_crypto_pake.c",
    "psa_crypto_rsa.c",
    "psa_crypto_se.c",
    "psa_crypto_slot_management.c",
    "psa_crypto_storage.c",
    "psa_its_file.c",
    "psa_util.c",
    "ripemd160.c",
    "rsa.c",
    "rsa_alt_helpers.c",
    "sha1.c",
    "sha256.c",
    "sha512.c",
    "sha3.c",
    "threading.c",
    "timing.c",
    "version.c",
    "version_features.c",
};
const x509_sources = .{
    "pkcs7.c",
    "x509.c",
    "x509_create.c",
    "x509_crl.c",
    "x509_crt.c",
    "x509_csr.c",
    "x509write.c",
    "x509write_crt.c",
    "x509write_csr.c",
};
const tls_sources = .{
    "debug.c",
    "mps_reader.c",
    "mps_trace.c",
    "net_sockets.c",
    "ssl_cache.c",
    "ssl_ciphersuites.c",
    "ssl_client.c",
    "ssl_cookie.c",
    "ssl_debug_helpers_generated.c",
    "ssl_msg.c",
    "ssl_ticket.c",
    "ssl_tls.c",
    "ssl_tls12_client.c",
    "ssl_tls12_server.c",
    "ssl_tls13_keys.c",
    "ssl_tls13_server.c",
    "ssl_tls13_client.c",
    "ssl_tls13_generic.c",
};