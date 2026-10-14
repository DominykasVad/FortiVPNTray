import Foundation
import FortiVPNShared

public struct ConfigurationStore {
    public let directory: URL
    public init(directory: URL? = nil) {
        self.directory = directory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent(AppIdentity.identifier)
    }
    public func profiles() throws -> [VPNProfile] { try read("profiles.json", fallback: []) }
    public func settings() throws -> AppSettings { try read("settings.json", fallback: AppSettings()) }
    public func save(profiles: [VPNProfile]) throws { try write(profiles, to: "profiles.json") }
    public func save(settings: AppSettings) throws { try write(settings, to: "settings.json") }
    private func read<T: Decodable>(_ name: String, fallback: T) throws -> T {
        let url = directory.appendingPathComponent(name)
        guard FileManager.default.fileExists(atPath: url.path) else { return fallback }
        return try JSONDecoder().decode(T.self, from: Data(contentsOf: url))
    }
    private func write<T: Encodable>(_ value: T, to name: String) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(value).write(to: directory.appendingPathComponent(name), options: .atomic)
    }
}
