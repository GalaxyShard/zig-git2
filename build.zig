const std = @import("std");

const find_sources = @import("find_sources");

fn isCFile(path: []const u8) bool {
    return std.mem.endsWith(u8, path, ".c");
}

const build_flags = .{
    "-std=gnu17",
    "-Werror",
    "-Wall",
    "-Wextra",
    "-Wstrict-prototypes",

    "-Wno-missing-field-initializers",
    "-Wno-single-bit-bitfield-constant-conversion",

    // zlib/zutil.h defines OS_CODE twice on MacOS for some reason
    "-Wno-macro-redefined",

    // zlib/zutil.h defines fdopen to null on MacOS if it's not already defined
    "-Dfdopen=fdopen",
};

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const libgit2_dep = b.dependency("libgit2", .{});
    const mbedtls_zig = b.dependency("mbedtls", .{
        .target = target,
        .optimize = optimize,
    });

    const config_header = b.addConfigHeader(.{
        .style = .{ .cmake = libgit2_dep.path("src/util/git2_features.h.in") },
        .include_path = "git2_features.h",
    }, .{
        // regex:
        //     #cmakedefine (.+?)(( .*\n)|\n)
        //     .\1 = null,\n

        // Optional debugging functionality
        .GIT_DEBUG_POOL = null,
        .GIT_DEBUG_STRICT_ALLOC = null,
        .GIT_DEBUG_STRICT_OPEN = null,

        .GIT_THREADS = {}, // default is on
        .GIT_WIN32_LEAKCHECK = null,

        .GIT_ARCH_64 = target.result.ptrBitWidth() == 64,
        .GIT_ARCH_32 = target.result.ptrBitWidth() == 32,

        // iconv doesn't work on MacOS
        .GIT_USE_ICONV = null,
        // non-standard
        .GIT_USE_NSEC = null,
        .GIT_USE_STAT_MTIM = null,
        .GIT_USE_STAT_MTIMESPEC = null,
        .GIT_USE_STAT_MTIME_NSEC = null,
        .GIT_USE_FUTIMENS = null,

        .GIT_REGEX_REGCOMP_L = null,
        .GIT_REGEX_REGCOMP = null,
        .GIT_REGEX_PCRE = null,
        .GIT_REGEX_PCRE2 = null,
        .GIT_REGEX_BUILTIN = {}, // use builtin regex

        .GIT_QSORT_BSD = null,
        .GIT_QSORT_GNU = null,
        .GIT_QSORT_C11 = null, // use standard qsort
        .GIT_QSORT_MSC = null,

        // no ssh, just need https
        .GIT_SSH = null,
        .GIT_SSH_EXEC = null,
        .GIT_SSH_LIBSSH2 = null,
        .GIT_SSH_LIBSSH2_MEMORY_CREDENTIALS = null,

        .GIT_NTLM = null,
        .GIT_GSSAPI = null,
        .GIT_GSSFRAMEWORK = null,

        .GIT_WINHTTP = null,
        .GIT_HTTPS = {},
        .GIT_OPENSSL = null,
        .GIT_OPENSSL_DYNAMIC = null,
        .GIT_SECURE_TRANSPORT = null,
        .GIT_MBEDTLS = {},
        .GIT_SCHANNEL = null,

        .GIT_HTTPPARSER_HTTPPARSER = null,
        .GIT_HTTPPARSER_LLHTTP = null, // TODO: check
        .GIT_HTTPPARSER_BUILTIN = {},

        .GIT_SHA1_COLLISIONDETECT = null,
        .GIT_SHA1_WIN32 = null,
        .GIT_SHA1_COMMON_CRYPTO = null,
        .GIT_SHA1_OPENSSL = null,
        .GIT_SHA1_OPENSSL_DYNAMIC = null,
        .GIT_SHA1_MBEDTLS = {},

        .GIT_SHA256_BUILTIN = null,
        .GIT_SHA256_WIN32 = null,
        .GIT_SHA256_COMMON_CRYPTO = null,
        .GIT_SHA256_OPENSSL = null,
        .GIT_SHA256_OPENSSL_DYNAMIC = null,
        .GIT_SHA256_MBEDTLS = {},

        // posix
        .GIT_RAND_GETENTROPY = target.result.os.tag != .windows and target.result.os.tag != .macos,
        .GIT_RAND_GETLOADAVG = target.result.os.tag != .windows,

        .GIT_IO_WSAPOLL = target.result.os.tag == .windows,
        .GIT_IO_POLL = target.result.os.tag != .windows,
        .GIT_IO_SELECT = target.result.os.tag != .windows,
    });

    const build_options: BuildOptions = .{
        .target = target,
        .optimize = optimize,
        .config_header = config_header,
    };
    const llhttp = try buildLlhttp(b, build_options);
    const zlib = try buildZlib(b, build_options);
    const pcre = try buildPcre(b, build_options);
    const xdiff = try buildXdiff(b, build_options);
    xdiff.linkLibrary(pcre);

    const git2 = b.addStaticLibrary(.{
        .name = "git2",
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    git2.linkLibrary(llhttp);
    git2.linkLibrary(xdiff);
    git2.linkLibrary(pcre);
    git2.linkLibrary(zlib);

    const git2_sources = try find_sources.searchDependency(libgit2_dep, "src/libgit2", isCFile);
    defer git2_sources.deinit();

    const utilPredicateWindows = struct {
        fn inner(path: []const u8) bool {
            return isCFile(path) and !std.mem.containsAtLeast(u8, path, 1, "hash/") and !std.mem.containsAtLeast(u8, path, 1, "unix/");
        }
    }.inner;
    const utilPredicate = struct {
        fn inner(path: []const u8) bool {
            return isCFile(path) and !std.mem.containsAtLeast(u8, path, 1, "hash/") and !std.mem.containsAtLeast(u8, path, 1, "win32/");
        }
    }.inner;

    const util_sources = if (target.result.os.tag == .windows)
        try find_sources.searchDependency(libgit2_dep, "src/util", utilPredicateWindows)
    else
        try find_sources.searchDependency(libgit2_dep, "src/util", utilPredicate);
    defer util_sources.deinit();

    // TODO: check if this works and/or is necessary
    // git2.addWin32ResourceFile(.{
    //     .file = libgit2_dep.path("src/libgit2/git2.rc"),
    // });

    git2.addCSourceFiles(.{
        .root = git2_sources.directory.dupe(b),
        .files = git2_sources.paths,
        .flags = &build_flags,
    });
    git2.addCSourceFiles(.{
        .root = util_sources.directory.dupe(b),
        .files = util_sources.paths,
        .flags = &build_flags,
    });
    git2.addCSourceFile(.{
        .file = libgit2_dep.path("src/util/hash/mbedtls.c"),
        .flags = &build_flags,
    });
    git2.linkLibrary(mbedtls_zig.artifact("mbedtls"));
    if (target.result.os.tag == .windows) {
        git2.linkSystemLibrary("secur32");
    }

    git2.addConfigHeader(config_header);
    git2.installConfigHeader(config_header);
    git2.installHeadersDirectory(libgit2_dep.path("include"), "", .{});

    const include = .{ "src/util", "src/libgit2", "include" };
    inline for (include) |path| {
        git2.addIncludePath(libgit2_dep.path(path));
    }

    const header = b.addTranslateC(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = libgit2_dep.path("include/git2.h"),
    });

    // May as well hard-deprecate
    header.defineCMacro("GIT_DEPRECATE_HARD", "1");

    header.addIncludePath(libgit2_dep.path("include"));
    _ = header.addModule("git2_header");

    b.installArtifact(git2);
}
const BuildOptions = struct {
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    config_header: *std.Build.Step.ConfigHeader,
};
fn buildXdiff(b: *std.Build, options: BuildOptions) !*std.Build.Step.Compile {
    const libgit2_dep = b.dependency("libgit2", .{});

    const xdiff = b.addStaticLibrary(.{
        .name = "xdiff",
        .target = options.target,
        .optimize = options.optimize,
        .link_libc = true,
    });
    const xdiff_src = try find_sources.searchDependency(libgit2_dep, "deps/xdiff", isCFile);
    defer xdiff_src.deinit();

    xdiff.addCSourceFiles(.{
        .root = xdiff_src.directory.dupe(b),
        .files = xdiff_src.paths,
        .flags = &(build_flags ++ .{"-Wno-sign-compare"}),
    });

    const include = .{ "src/util", "include" };
    inline for (include) |path| {
        xdiff.addIncludePath(libgit2_dep.path(path));
    }
    xdiff.addConfigHeader(options.config_header);

    xdiff.installHeadersDirectory(libgit2_dep.path("deps/xdiff"), "", .{});
    return xdiff;
}
fn buildLlhttp(b: *std.Build, options: BuildOptions) !*std.Build.Step.Compile {
    const libgit2_dep = b.dependency("libgit2", .{});

    const llhttp = b.addStaticLibrary(.{
        .name = "llhttp",
        .target = options.target,
        .optimize = options.optimize,
        .link_libc = true,
    });
    const llhttp_src = try find_sources.searchDependency(libgit2_dep, "deps/llhttp", isCFile);
    defer llhttp_src.deinit();

    llhttp.addCSourceFiles(.{
        .root = llhttp_src.directory.dupe(b),
        .files = llhttp_src.paths,
        .flags = &(build_flags ++ .{ "-Wno-unused-parameter", "-Wno-unused-variable", "-Wno-missing-declarations" }),
    });
    llhttp.installHeader(libgit2_dep.path("deps/llhttp/llhttp.h"), "llhttp.h");
    return llhttp;
}
fn buildZlib(b: *std.Build, options: BuildOptions) !*std.Build.Step.Compile {
    const libgit2_dep = b.dependency("libgit2", .{});

    const zlib = b.addStaticLibrary(.{
        .name = "zlib",
        .target = options.target,
        .optimize = options.optimize,
        .link_libc = true,
    });
    const zlib_src = try find_sources.searchDependency(libgit2_dep, "deps/zlib", isCFile);
    defer zlib_src.deinit();

    const defines = .{ "NO_VIZ", "STDC", "NO_GZIP", "HAVE_SYS_TYPES_H", "HAVE_STDINT_H", "HAVE_STDDEF_H" };
    inline for (defines) |define| {
        zlib.root_module.addCMacro(define, "");
    }

    zlib.addCSourceFiles(.{
        .root = zlib_src.directory.dupe(b),
        .files = zlib_src.paths,
        .flags = &build_flags,
    });
    zlib.installHeadersDirectory(libgit2_dep.path("deps/zlib"), "", .{});
    return zlib;
}
fn buildPcre(b: *std.Build, options: BuildOptions) !*std.Build.Step.Compile {
    const libgit2_dep = b.dependency("libgit2", .{});

    const pcre = b.addStaticLibrary(.{
        .name = "pcre",
        .target = options.target,
        .optimize = options.optimize,
        .link_libc = true,
    });

    const config_header = b.addConfigHeader(.{
        .style = .{ .cmake = libgit2_dep.path("deps/pcre/config.h.in") },
        .include_path = "config.h",
    }, .{
        .HAVE_DIRENT_H = null,
        .HAVE_SYS_STAT_H = null,
        .HAVE_SYS_TYPES_H = null,
        .HAVE_UNISTD_H = null,
        .HAVE_WINDOWS_H = options.target.result.os.tag == .windows,
        .HAVE_STDINT_H = {},
        .HAVE_INTTYPES_H = {},

        .HAVE_TYPE_TRAITS_H = null,
        .HAVE_BITS_TYPE_TRAITS_H = null,

        .HAVE_BCOPY = null,
        .HAVE_MEMMOVE = {},
        .HAVE_STRERROR = null,
        .HAVE_STRTOLL = {},
        .HAVE_STRTOQ = null,
        .HAVE__STRTOI64 = null,

        .PCRE_STATIC = null,

        .SUPPORT_PCRE8 = null,
        .SUPPORT_PCRE16 = null,
        .SUPPORT_PCRE32 = null,
        .SUPPORT_JIT = null,
        .SUPPORT_PCREGREP_JIT = null,
        .SUPPORT_UTF = null,
        .SUPPORT_UCP = null,
        .EBCDIC = null,
        .EBCDIC_NL25 = null,
        .BSR_ANYCRLF = null,
        .NO_RECURSE = null,

        .HAVE_LONG_LONG = {},
        .HAVE_UNSIGNED_LONG_LONG = {},

        .SUPPORT_LIBBZ2 = null,
        .SUPPORT_LIBZ = null,
        .SUPPORT_LIBEDIT = null,
        .SUPPORT_LIBREADLINE = null,

        .SUPPORT_VALGRIND = null,
        .SUPPORT_GCOV = null,

        .NEWLINE = "10", // defaults to LF
        .PCRE_POSIX_MALLOC_THRESHOLD = "10",
        .PCRE_LINK_SIZE = "2",
        .PCRE_PARENS_NEST_LIMIT = "250",
        .PCRE_MATCH_LIMIT = "10000000",
        .PCRE_MATCH_LIMIT_RECURSION = "MATCH_LIMIT",
        .PCREGREP_BUFSIZE = null,
    });

    const pcre_src = try find_sources.searchDependency(libgit2_dep, "deps/pcre", isCFile);
    defer pcre_src.deinit();

    pcre.addCSourceFiles(.{
        .root = pcre_src.directory.dupe(b),
        .files = pcre_src.paths,
        .flags = &(build_flags ++ .{"-Wno-unused-but-set-variable"}),
    });
    pcre.root_module.addCMacro("HAVE_CONFIG_H", "");
    pcre.addConfigHeader(config_header);
    pcre.installHeader(libgit2_dep.path("deps/pcre/pcre.h"), "pcre.h");
    return pcre;
}
