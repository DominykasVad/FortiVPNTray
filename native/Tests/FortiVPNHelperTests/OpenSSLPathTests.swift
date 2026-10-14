import Testing
import Foundation
@testable import FortiVPNHelper

/// The child opens no `/opt/homebrew` path (PLAN.md 2.3, S2, decision log 2.3).
///
/// openfortivpn exits before touching OpenSSL unless it runs as root, so this
/// runs a probe that makes openfortivpn's OpenSSL calls instead
/// (`SSL_CTX_new`, `SSL_CTX_set_default_verify_paths`, then verifying an
/// untrusted gateway certificate, which looks for its issuer in the cert
/// directory), linked against Homebrew's OpenSSL, under exactly the launcher's
/// environment, with every file access traced. Needs Homebrew's `openssl@4`
/// and a C compiler. Where they are missing it is skipped, unless
/// `FVT_REQUIRE_OPENSSL_PROBE=1` (set on CI), which makes that a failure.
struct OpenSSLPathTests {
    static let openssl = "/opt/homebrew/opt/openssl@4"
    static let available = FileManager.default.fileExists(atPath: openssl + "/include/openssl/ssl.h")
        && FileManager.default.isExecutableFile(atPath: "/usr/bin/cc")
    static let required = ProcessInfo.processInfo.environment["FVT_REQUIRE_OPENSSL_PROBE"] == "1"

    private static let probe = #"""
    #include <stdio.h>
    #include <openssl/ssl.h>
    #include <openssl/pem.h>
    #include <openssl/x509_vfy.h>
    int main(int argc, char **argv) {
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx || !SSL_CTX_set_default_verify_paths(ctx)) return 2;
        FILE *f = fopen(argv[1], "r");
        X509 *cert = f ? PEM_read_X509(f, NULL, NULL, NULL) : NULL;
        if (!cert) return 3;
        X509_STORE_CTX *v = X509_STORE_CTX_new();
        X509_STORE_CTX_init(v, SSL_CTX_get_cert_store(ctx), cert, NULL);
        printf("verify: %d\n", X509_verify_cert(v));
        return 0;
    }
    """#

    /// Interposes the calls OpenSSL uses to look for files and logs every path.
    private static let trace = #"""
    #include <stdio.h>
    #include <fcntl.h>
    #include <stdarg.h>
    #include <unistd.h>
    #include <dirent.h>
    #include <sys/stat.h>
    #define INTERPOSE(new, old) __attribute__((used)) static struct { const void *n; const void *o; } _i_##old __attribute__((section("__DATA,__interpose"))) = { (const void *)new, (const void *)old }
    static void note(const char *call, const char *path) { if (path) fprintf(stderr, "TRACE %s %s\n", call, path); }
    static FILE *t_fopen(const char *p, const char *m) { note("fopen", p); return fopen(p, m); }
    static int t_open(const char *p, int f, ...) { va_list a; va_start(a, f); int m = va_arg(a, int); va_end(a); note("open", p); return open(p, f, m); }
    static int t_stat(const char *p, struct stat *s) { note("stat", p); return stat(p, s); }
    static int t_lstat(const char *p, struct stat *s) { note("lstat", p); return lstat(p, s); }
    static int t_access(const char *p, int m) { note("access", p); return access(p, m); }
    static int t_fstatat(int d, const char *p, struct stat *s, int f) { note("fstatat", p); return fstatat(d, p, s, f); }
    static DIR *t_opendir(const char *p) { note("opendir", p); return opendir(p); }
    INTERPOSE(t_fopen, fopen); INTERPOSE(t_open, open); INTERPOSE(t_stat, stat); INTERPOSE(t_lstat, lstat);
    INTERPOSE(t_access, access); INTERPOSE(t_fstatat, fstatat); INTERPOSE(t_opendir, opendir);
    """#

    /// A made-up self-signed certificate for `vpn.example.com`: never trusted, so
    /// verifying it makes OpenSSL search the cert directory for its issuer.
    private static let gatewayCertificate = """
    -----BEGIN CERTIFICATE-----
    MIIBZzCCAQ6gAwIBAgIUfs4+AIkQwW8oEWO+gO/D9OTmqOYwCgYIKoZIzj0EAwIw
    GjEYMBYGA1UEAwwPdnBuLmV4YW1wbGUuY29tMB4XDTI2MTAxNDA1MTYyNVoXDTI2
    MTAxNTA1MTYyNVowGjEYMBYGA1UEAwwPdnBuLmV4YW1wbGUuY29tMFkwEwYHKoZI
    zj0CAQYIKoZIzj0DAQcDQgAETMzAhJ5z8QfsHuSo/WqxTp7KZj3xDAnsSk4uQ88u
    Fgpo0nO7yt0kD95HR04/GEsSIiDiTmraJTXPgzOcRwcIAaMyMDAwHQYDVR0OBBYE
    FMsVgPzHFufZ7n8H8ApHxZqkTtyPMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0E
    AwIDRwAwRAIgdjnFarbl5RHordQi8YS/iDPTp0PAlhVyqsknGibqhVECIFBcpIlH
    ok+LrzL/n2+Y49q8EocJ+N6JAH7sqKTFHqQY
    -----END CERTIFICATE-----

    """

    private func run(_ executable: String, _ arguments: [String], environment: [String: String]) throws -> (status: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = environment
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }

    @Test(.enabled(if: available || required, "needs Homebrew openssl@4 and cc; FVT_REQUIRE_OPENSSL_PROBE=1 makes this a failure"))
    func testChildOpenSSLOpensNoHomebrewPath() throws {
        guard Self.available else {
            Issue.record("FVT_REQUIRE_OPENSSL_PROBE=1, but \(Self.openssl)/include/openssl/ssl.h or /usr/bin/cc is missing")
            return
        }
        let fake = try FakeInstall()
        let work = fake.root + "/probe"
        try FakeInstall.makeDirectory(work)
        try fake.write(Self.probe, to: work + "/probe.c", mode: 0o644)
        try fake.write(Self.trace, to: work + "/trace.c", mode: 0o644)
        try fake.write(Self.gatewayCertificate, to: work + "/gateway.pem", mode: 0o644)
        let build = ["PATH": "/usr/bin:/bin"]
        let compile = try run("/usr/bin/cc", ["-I\(Self.openssl)/include", "-o", work + "/probe", work + "/probe.c",
                                              "-L\(Self.openssl)/lib", "-lssl", "-lcrypto"], environment: build)
        #expect(compile.status == 0, "\(compile.output)")
        let library = try run("/usr/bin/cc", ["-dynamiclib", "-o", work + "/trace.dylib", work + "/trace.c"], environment: build)
        #expect(library.status == 0, "\(library.output)")

        func paths(_ environment: [String: String]) throws -> [String] {
            var environment = environment
            environment["DYLD_INSERT_LIBRARIES"] = work + "/trace.dylib"
            let result = try run(work + "/probe", [work + "/gateway.pem"], environment: environment)
            #expect(result.status == 0, "\(result.output)")
            #expect(result.output.contains("verify: 0"), "the made-up certificate must not verify")
            return result.output.split(separator: "\n").filter { $0.hasPrefix("TRACE ") }.map { String($0.split(separator: " ", maxSplits: 2).last ?? "") }
        }

        let pinned = OpenFortiVPNLauncher.environment(for: fake.install)
        let traced = try paths(pinned)
        #expect(traced.filter { $0.hasPrefix("/opt/homebrew") } == [])
        #expect(traced.contains("/etc/ssl/cert.pem"))
        #expect(traced.contains { $0.hasPrefix(fake.install.certsDirectory + "/") }, "the issuer lookup went to the pinned, empty cert directory")

        // Control: without SSL_CERT_DIR the same lookup goes to Homebrew's user-writable
        // directory, so the check above would catch it.
        var unpinned = pinned
        unpinned["SSL_CERT_DIR"] = nil
        #expect(try paths(unpinned).contains { $0.hasPrefix("/opt/homebrew/etc/openssl@4/certs/") })
    }
}
