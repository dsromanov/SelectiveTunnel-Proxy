import Foundation

// Порты src/core/profile.cpp, policy.cpp, status.cpp.

public struct Profile: Codable {
    public var schema: Int = 2
    public var protocol_: String = "socks5"
    public var serverIp: String = ST.defaultProxyIp
    public var serverPort: Int = ST.defaultSocksPort
    public var username: String = ""
    public var password: String = ""
    public var expectedExitIp: String = ""
    public var tlsServerName: String = ""
    public var policyUrl: String = ""
    public var policyPublicKey: String = ""

    public init() {}

    enum CodingKeys: String, CodingKey {
        case schema
        case protocol_ = "protocol"
        case serverIp = "server_ip"
        case serverPort = "server_port"
        case username, password
        case expectedExitIp = "expected_exit_ip"
        case tlsServerName = "tls_server_name"
        case policyUrl = "policy_url"
        case policyPublicKey = "policy_public_key"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        schema = try c.decode(Int.self, forKey: .schema)
        protocol_ = try c.decode(String.self, forKey: .protocol_)
        serverIp = try c.decode(String.self, forKey: .serverIp)
        serverPort = try c.decode(Int.self, forKey: .serverPort)
        username = try c.decodeIfPresent(String.self, forKey: .username) ?? ""
        password = try c.decodeIfPresent(String.self, forKey: .password) ?? ""
        expectedExitIp = try c.decodeIfPresent(String.self, forKey: .expectedExitIp) ?? ""
        tlsServerName = try c.decodeIfPresent(String.self, forKey: .tlsServerName) ?? ""
        policyUrl = try c.decodeIfPresent(String.self, forKey: .policyUrl) ?? ""
        policyPublicKey = try c.decodeIfPresent(String.self, forKey: .policyPublicKey) ?? ""
    }
}

public struct Policy: Codable {
    public var version: Int = 1
    public var domains: [String] = []
    public var cidrs: [String] = []

    public init() {}

    enum CodingKeys: String, CodingKey {
        case version, domains, cidrs
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(Int.self, forKey: .version)
        domains = try c.decode([String].self, forKey: .domains)
        cidrs = try c.decodeIfPresent([String].self, forKey: .cidrs) ?? []
    }
}

public struct Status: Codable {
    public var state: String = "unknown"
    public var detail: String = ""
    public var updatedUtc: String = ""
    public var policyVersion: Int = 0
    public var updateError: String = ""
    public var enginePid: Int? = nil

    public init() {}

    enum CodingKeys: String, CodingKey {
        case state, detail
        case updatedUtc = "updated_utc"
        case policyVersion = "policy_version"
        case updateError = "update_error"
        case enginePid = "engine_pid"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        state = try c.decodeIfPresent(String.self, forKey: .state) ?? "unknown"
        detail = try c.decodeIfPresent(String.self, forKey: .detail) ?? ""
        updatedUtc = try c.decodeIfPresent(String.self, forKey: .updatedUtc) ?? ""
        policyVersion = try c.decodeIfPresent(Int.self, forKey: .policyVersion) ?? 0
        updateError = try c.decodeIfPresent(String.self, forKey: .updateError) ?? ""
        enginePid = try c.decodeIfPresent(Int.self, forKey: .enginePid)
    }

    public var isStale: Bool {
        guard let date = UtcFormat.formatter.date(from: updatedUtc) else { return true }
        return Date().timeIntervalSince(date) > ST.statusStaleSeconds
    }
}

public enum UtcFormat {
    public static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        return f
    }()

    public static func now() -> String { formatter.string(from: Date()) }
}

private let ipv4Pattern = #"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"#

public func isIpv4(_ text: String) -> Bool {
    text.range(of: ipv4Pattern, options: .regularExpression) != nil
}

private func hasControlChars(_ value: String) -> Bool {
    value.utf8.contains { $0 <= 0x1f || $0 == 0x7f }
}

/// AssertProfile — то же, что в profile.cpp.
public func assertProfile(_ p: Profile) throws {
    guard p.schema == 2 else {
        throw STError.message("A proxy connection (schema 2) is required.")
    }
    guard ["socks5", "http", "https"].contains(p.protocol_) else {
        throw STError.message("Unsupported proxy protocol.")
    }
    guard isIpv4(p.serverIp) else {
        throw STError.message("Enter the numeric IPv4 address of the proxy.")
    }
    guard p.serverPort >= 1 && p.serverPort <= 65535 else {
        throw STError.message("Invalid server port.")
    }
    for value in [p.username, p.password] {
        guard !value.isEmpty, !hasControlChars(value), value.utf8.count <= 255 else {
            throw STError.message("Invalid proxy username/password (1..255 UTF-8 bytes; no control characters).")
        }
    }
    if p.protocol_ != "socks5" && p.username.contains(":") {
        throw STError.message("HTTP proxy username cannot contain a colon.")
    }
    if !p.expectedExitIp.isEmpty && !isIpv4(p.expectedExitIp) {
        throw STError.message("Invalid expected exit IP.")
    }
    if p.protocol_ == "https" {
        let host = #"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$"#
        guard p.tlsServerName.range(of: host, options: .regularExpression) != nil else {
            throw STError.message(
                "HTTPS proxy requires the hostname on its TLS certificate. HTTP(S) marketing alone does not imply TLS to the proxy.")
        }
    }
    guard p.policyUrl.isEmpty == p.policyPublicKey.isEmpty else {
        throw STError.message("Policy URL and public signing key must be configured together.")
    }
    if !p.policyUrl.isEmpty {
        let url = #"^https://[^/@:?#]+/[^?#]*$"#
        guard p.policyUrl.range(of: url, options: .regularExpression) != nil, !p.policyUrl.contains("@") else {
            throw STError.message("Policy URL must be HTTPS on port 443, without credentials or query.")
        }
        let rest = String(p.policyUrl.dropFirst("https://".count))
        let hostport = rest.split(separator: "/", maxSplits: 1).first.map(String.init) ?? rest
        if hostport.contains(":") && !hostport.contains(":443") {
            throw STError.message("Policy URL must be HTTPS on port 443, without credentials or query.")
        }
    }
}

private let broadSuffixes: Set<String> = [
    "com", "net", "org", "co.uk", "com.au", "cloudflare.com", "cloudfront.net", "amazonaws.com",
    "azureedge.net", "google.com", "jsdelivr.net",
]

private func validDomain(_ domain: String) -> Bool {
    guard domain.utf8.count <= 253, domain == domain.lowercased() else { return false }
    let re = #"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"#
    return domain.range(of: re, options: .regularExpression) != nil
}

private func parseIpv4(_ text: String) -> UInt32? {
    let parts = text.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return nil }
    var ip: UInt32 = 0
    for part in parts {
        guard let v = UInt32(part), v <= 255 else { return nil }
        ip = (ip << 8) | v
    }
    return ip
}

private func assertCidr(_ cidr: String) throws {
    guard let slash = cidr.firstIndex(of: "/") else {
        throw STError.message("Only explicit IPv4 CIDRs are supported.")
    }
    guard let ip = parseIpv4(String(cidr[..<slash])) else {
        throw STError.message("Only explicit IPv4 CIDRs are supported.")
    }
    guard let prefix = Int(cidr[cidr.index(after: slash)...]) else {
        throw STError.message("Only explicit IPv4 CIDRs are supported.")
    }
    guard prefix >= 24 && prefix <= 32 else {
        throw STError.message("CIDRs must be IPv4 /24 through /32; do not route whole CDN networks.")
    }
    let a = ip >> 24
    let b = (ip >> 16) & 0xff
    if a == 0 || a == 10 || a == 127 || a >= 224 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168)
        || (a == 169 && b == 254) || (a == 198 && (b == 18 || b == 19)) {
        throw STError.message("Non-public CIDR is forbidden.")
    }
    let hostMask: UInt32 = prefix == 32 ? 0 : ((1 << (32 - prefix)) - 1)
    guard ip & hostMask == 0 else {
        throw STError.message("CIDR must be a network address.")
    }
}

public func assertPolicy(_ policy: Policy) throws {
    guard policy.version >= 1 && policy.version <= 2147483647 else {
        throw STError.message("Invalid policy version.")
    }
    guard policy.domains.count >= 1 && policy.domains.count <= 200 else {
        throw STError.message("Expected 1..200 domain suffixes.")
    }
    var seen = Set<String>()
    for domain in policy.domains {
        guard validDomain(domain) else {
            throw STError.message("Invalid domain suffix: \(domain)")
        }
        guard !broadSuffixes.contains(domain) else {
            throw STError.message("Shared infrastructure suffix is too broad: \(domain)")
        }
        guard seen.insert(domain).inserted else {
            throw STError.message("Duplicate domains.")
        }
    }
    guard policy.cidrs.count <= 100 else {
        throw STError.message("Too many IP ranges.")
    }
    for cidr in policy.cidrs {
        try assertCidr(cidr)
    }
}

public func assertProxyPolicy(_ policy: Policy) throws {
    try assertPolicy(policy)
    guard policy.cidrs.isEmpty else {
        throw STError.message(
            "The proxy edition uses domain rules only. Leave cidrs empty to avoid shared-CDN and adapter-change leaks.")
    }
}

public func mergePolicies(current: Policy, candidate: Policy) -> Policy {
    var merged = candidate
    merged.domains = Array(Set(current.domains).union(candidate.domains)).sorted()
    merged.cidrs = Array(Set(current.cidrs).union(candidate.cidrs)).sorted()
    return merged
}
