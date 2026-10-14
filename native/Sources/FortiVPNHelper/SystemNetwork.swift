import Foundation
import FortiVPNShared
import SystemConfiguration

/// The current default route, as `route -n get default` reports it.
struct DefaultRoute: Equatable, Sendable {
    /// Nil if the default route has no IPv4 gateway (for example a point-to-point interface).
    let gateway: String?
    let interface: String
}

/// The calls the helper makes on routes and DNS (PLAN.md 2.5). Behind a protocol so
/// unit tests never touch the real network, routes or DNS.
protocol NetworkControl: Sendable {
    func defaultRoute() -> DefaultRoute?
    /// The gateway's IPv4 address, resolved by the helper itself.
    func resolveIPv4(_ host: String) -> String?
    /// The resolvers the system uses now (`State:/Network/Global/DNS`), IPv4 only.
    func systemDNSServers() -> [String]
    func deleteHostRoute(_ address: String) throws
    func replaceDefaultRoute(gateway: String) throws
    func setDNS(_ configuration: DNSConfiguration) throws
    /// Removes the helper's DNS key. Returns whether there was one.
    func removeDNS() throws -> Bool
    func flushDNSCache() throws
}

struct NetworkFailure: Error, Equatable, CustomStringConvertible {
    let description: String
}

/// `/sbin/route` argument lists. Every value is validated here, so nothing that
/// is not an IPv4 address reaches the command.
enum RouteCommand {
    static let path = "/sbin/route"

    static let getDefault = ["-n", "get", "default"]
    static let deleteDefault = ["-n", "delete", "default"]

    static func deleteHost(_ address: String) throws -> [String] {
        guard Validation.ipv4(address) else { throw NetworkFailure(description: "Not an IPv4 address.") }
        return ["-n", "delete", "-host", address]
    }

    static func addDefault(gateway: String) throws -> [String] {
        guard Validation.ipv4(gateway) else { throw NetworkFailure(description: "Not an IPv4 address.") }
        return ["-n", "add", "default", gateway]
    }

    /// Reads `gateway:` and `interface:` from `route -n get default`. The gateway is
    /// kept only if it is an IPv4 address and the interface only if it is a plain name.
    static func parseDefault(_ output: String) -> DefaultRoute? {
        var gateway: String?
        var interface: String?
        for line in output.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2 else { continue }
            switch parts[0] {
            case "gateway": gateway = Validation.ipv4(parts[1]) ? parts[1] : nil
            case "interface": interface = isInterfaceName(parts[1]) ? parts[1] : nil
            default: break
            }
        }
        guard let interface else { return nil }
        return DefaultRoute(gateway: gateway, interface: interface)
    }

    static func isInterfaceName(_ value: String) -> Bool {
        value.range(of: #"^[a-z]+[0-9]+$"#, options: .regularExpression) != nil && value.utf8.count <= 15
    }
}

/// The value written to the helper's DNS key: the tunnel's resolvers, and its
/// suffixes as match and search domains. With no suffixes the resolvers match
/// every name, as the Rust helper did.
struct DNSConfiguration: Equatable, Sendable {
    let servers: [String]
    let domains: [String]

    init(servers: [String], domains: [String]) throws {
        guard !servers.isEmpty, servers.allSatisfy(Validation.ipv4) else { throw NetworkFailure(description: "Bad DNS servers.") }
        guard domains.allSatisfy(Validation.hostname) else { throw NetworkFailure(description: "Bad DNS domains.") }
        self.servers = servers
        self.domains = domains
    }

    var dictionary: [String: [String]] {
        var value = ["ServerAddresses": servers, "SupplementalMatchDomains": domains.isEmpty ? [""] : domains]
        if !domains.isEmpty { value["SearchDomains"] = domains }
        return value
    }
}

/// Runs a system tool as root: fixed path checked root-owned first, argument array,
/// cleared environment, no shell (AGENTS.md).
enum SystemCommand {
    static func run(_ path: String, _ arguments: [String]) throws -> (status: Int32, output: String) {
        try FileTrust.root.check(path, is: .file)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        process.currentDirectoryURL = URL(fileURLWithPath: "/")
        process.standardInput = FileHandle.nullDevice
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data.prefix(65_536), as: UTF8.self))
    }

    static func require(_ path: String, _ arguments: [String]) throws {
        let result = try run(path, arguments)
        guard result.status == 0 else {
            throw NetworkFailure(description: "\((path as NSString).lastPathComponent) \(arguments.joined(separator: " ")) exited with status \(result.status)")
        }
    }
}

/// The real routes and DNS: `/sbin/route`, SystemConfiguration, `dscacheutil`, and
/// SIGHUP to mDNSResponder (the one `killall` AGENTS.md allows).
struct SystemNetwork: NetworkControl {
    static let globalDNSKey = "State:/Network/Global/DNS"

    func defaultRoute() -> DefaultRoute? {
        guard let result = try? SystemCommand.run(RouteCommand.path, RouteCommand.getDefault), result.status == 0 else { return nil }
        return RouteCommand.parseDefault(result.output)
    }

    func resolveIPv4(_ host: String) -> String? {
        if Validation.ipv4(host) { return host }
        guard Validation.hostname(host) else { return nil }
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let first = result else { return nil }
        defer { freeaddrinfo(result) }
        guard let address = first.pointee.ai_addr, address.pointee.sa_family == sa_family_t(AF_INET) else { return nil }
        var text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        var inAddress = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
        guard inet_ntop(AF_INET, &inAddress, &text, socklen_t(text.count)) != nil else { return nil }
        let value = String(decoding: text.prefix(while: { $0 != 0 }).map(UInt8.init(bitPattern:)), as: UTF8.self)
        return Validation.ipv4(value) ? value : nil
    }

    func systemDNSServers() -> [String] {
        guard let store = Self.store(),
              let value = SCDynamicStoreCopyValue(store, Self.globalDNSKey as CFString) as? [String: Any],
              let servers = value["ServerAddresses"] as? [String] else { return [] }
        return servers.filter(Validation.ipv4)
    }

    func deleteHostRoute(_ address: String) throws {
        let result = try SystemCommand.run(RouteCommand.path, try RouteCommand.deleteHost(address))
        // Already gone is fine: every cleanup step may run more than once.
        guard result.status == 0 || result.output.contains("not in table") else {
            throw NetworkFailure(description: "route delete -host exited with status \(result.status)")
        }
    }

    func replaceDefaultRoute(gateway: String) throws {
        let add = try RouteCommand.addDefault(gateway: gateway)
        _ = try SystemCommand.run(RouteCommand.path, RouteCommand.deleteDefault)
        try SystemCommand.require(RouteCommand.path, add)
    }

    func setDNS(_ configuration: DNSConfiguration) throws {
        guard let store = Self.store(),
              SCDynamicStoreSetValue(store, AppIdentity.dnsServiceKey as CFString, configuration.dictionary as CFDictionary) else {
            throw NetworkFailure(description: "Cannot set the DNS configuration: \(String(cString: SCErrorString(SCError())))")
        }
    }

    func removeDNS() throws -> Bool {
        guard let store = Self.store() else { throw NetworkFailure(description: "Cannot open the dynamic store.") }
        guard SCDynamicStoreCopyValue(store, AppIdentity.dnsServiceKey as CFString) != nil else { return false }
        guard SCDynamicStoreRemoveValue(store, AppIdentity.dnsServiceKey as CFString) else {
            throw NetworkFailure(description: "Cannot remove the DNS configuration: \(String(cString: SCErrorString(SCError())))")
        }
        return true
    }

    func flushDNSCache() throws {
        var failures: [String] = []
        do { try SystemCommand.require("/usr/bin/dscacheutil", ["-flushcache"]) } catch { failures.append(String(describing: error)) }
        // SIGHUP only makes mDNSResponder flush its cache (decision log, 2.5).
        do { try SystemCommand.require("/usr/bin/killall", ["-HUP", "mDNSResponder"]) } catch { failures.append(String(describing: error)) }
        guard failures.isEmpty else { throw NetworkFailure(description: failures.joined(separator: "; ")) }
    }

    private static func store() -> SCDynamicStore? {
        SCDynamicStoreCreate(nil, AppIdentity.helperLabel as CFString, nil, nil)
    }
}
