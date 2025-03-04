const std = @import("std");

const find_build_sources = @import("find-build-sources.zig");

fn is_c_file(path: []const u8) bool {
    return std.mem.endsWith(u8, path, ".c");
}

const build_flags = .{
    "-std=gnu17",
    "-Werror",
    "-Wall",
    "-Wextra",
    "-Wpedantic",
    "-Wno-static-in-inline",
};

fn x509Predicate(path: []const u8) bool {
    if (std.mem.eql(u8, path, "pkcs7.c")) {
        return true;
    } else if (std.mem.startsWith(u8, path, "x509") and std.mem.endsWith(u8, path, ".c")) {
        return true;
    }
    return false;
}

fn tlsPredicate(path: []const u8) bool {
    if (std.mem.startsWith(u8, path, "ssl_") and std.mem.endsWith(u8, path, ".c")) {
        return true;
    }
    inline for (.{ "debug.c", "mps_reader.c", "mps_trace.c", "net_sockets.c" }) |file| {
        if (std.mem.eql(u8, path, file)) {
            return true;
        }
    }
    return false;
}

fn cryptoPredicate(path: []const u8) bool {
    if (tlsPredicate(path) or x509Predicate(path)) {
        return false;
    }
    return std.mem.endsWith(u8, path, ".c");
}

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mbedtls_dep = b.dependency("mbedtls", .{});

    const crypto = b.addStaticLibrary(.{
        .name = "mbedcrypto",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        })
    });
    crypto.root_module.addIncludePath(mbedtls_dep.path("include"));

    const crypto_sources = try find_build_sources.findDep(mbedtls_dep, "library", cryptoPredicate);
    defer crypto_sources.deinit();
    crypto.root_module.addCSourceFiles(.{
        .root = crypto_sources.directory,
        .files = crypto_sources.inner,
        .flags = &build_flags,
    });
    if (target.result.os.tag == .windows) {
        crypto.root_module.linkSystemLibrary("bcrypt", .{});
    }
    b.installArtifact(crypto);

    const x509 = b.addStaticLibrary(.{
        .name = "mbedx509",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        })
    });
    x509.addIncludePath(mbedtls_dep.path("include"));

    const x509_sources = try find_build_sources.findDep(mbedtls_dep, "library", x509Predicate);
    defer x509_sources.deinit();
    x509.root_module.addCSourceFiles(.{
        .root = x509_sources.directory,
        .files = x509_sources.inner,
        .flags = &build_flags,
    });

    x509.root_module.linkLibrary(crypto);
    b.installArtifact(x509);

    const tls = b.addStaticLibrary(.{
        .name = "mbedtls",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        })
    });
    tls.root_module.addIncludePath(mbedtls_dep.path("include"));

    const tls_sources = try find_build_sources.findDep(mbedtls_dep, "library", tlsPredicate);
    defer tls_sources.deinit();
    tls.root_module.addCSourceFiles(.{
        .root = tls_sources.directory,
        .files = tls_sources.inner,
        .flags = &build_flags,
    });

    tls.root_module.linkLibrary(crypto);
    tls.root_module.linkLibrary(x509);

    tls.installHeadersDirectory(mbedtls_dep.path("include/mbedtls"), "mbedtls", .{});
    tls.installHeadersDirectory(mbedtls_dep.path("include/psa"), "psa", .{});

    b.installArtifact(tls);
}
