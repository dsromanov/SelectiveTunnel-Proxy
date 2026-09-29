import Foundation

// Порт src/core/engine_config.cpp — генерация sing-box конфигурации.
// Отличие macOS-версии: TUN без interface_name (utun назначает система),
// и engine запускается тем же способом `run -c stdin`.

public func newEngineConfig(profile: Profile, policy: Policy, dataRoot: String,
                            bindInterface: String, ipv4Only: Bool) throws -> [String: Any] {
    try assertProfile(profile)
    try assertProxyPolicy(policy)

    var proxy: [String: Any]
    if profile.protocol_ == "socks5" {
        proxy = [
            "type": "socks",
            "tag": "proxy",
            "server": profile.serverIp,
            "server_port": profile.serverPort,
            "version": "5",
            "username": profile.username,
            "password": profile.password,
            "network": "tcp",
        ]
    } else {
        proxy = [
            "type": "http",
            "tag": "proxy",
            "server": profile.serverIp,
            "server_port": profile.serverPort,
            "username": profile.username,
            "password": profile.password,
        ]
        if profile.protocol_ == "https" {
            proxy["tls"] = ["enabled": true, "server_name": profile.tlsServerName]
        }
    }

    var fakeip: [String: Any] = ["type": "fakeip", "tag": "fake", "inet4_range": ST.fakeV4]
    if !ipv4Only {
        fakeip["inet6_range"] = ST.fakeV6
    }

    var dnsRules: [[String: Any]] = []
    if ipv4Only {
        dnsRules.append([
            "domain_suffix": policy.domains,
            "query_type": ["A"],
            "action": "route",
            "server": "fake",
            "rewrite_ttl": 60,
        ])
        dnsRules.append([
            "domain_suffix": policy.domains,
            "query_type": ["AAAA", "HTTPS", "SVCB"],
            "action": "predefined",
            "rcode": "NOERROR",
        ])
    } else {
        dnsRules.append([
            "domain_suffix": policy.domains,
            "query_type": ["A", "AAAA"],
            "action": "route",
            "server": "fake",
            "rewrite_ttl": 60,
        ])
        dnsRules.append([
            "domain_suffix": policy.domains,
            "query_type": ["HTTPS", "SVCB"],
            "action": "predefined",
            "rcode": "NOERROR",
        ])
    }
    dnsRules.append(["domain_suffix": policy.domains, "action": "route", "server": "remote"])
    dnsRules.append(["action": "reject"])

    var tun: [String: Any] = [
        "type": "tun",
        "tag": "tun",
        "mtu": 1380,
        "auto_route": true,
        "strict_route": false,
        "dns_mode": "disabled",
        "stack": "gvisor",
    ]
    if ipv4Only {
        tun["address"] = [ST.tunV4]
        tun["route_address"] = [ST.fakeV4a, ST.fakeV4b]
    } else {
        tun["address"] = [ST.tunV4, ST.tunV6]
        tun["route_address"] = [ST.fakeV4a, ST.fakeV4b, ST.fakeV6a, ST.fakeV6b]
    }

    var fakeCidrs = [ST.fakeV4]
    if !ipv4Only { fakeCidrs.append(ST.fakeV6) }

    var rules: [[String: Any]] = []
    rules.append(["inbound": ["dns-in"], "action": "hijack-dns"])
    rules.append(["inbound": ["diagnostic"], "network": "udp", "action": "reject"])
    rules.append(["domain_suffix": policy.domains, "network": "udp", "action": "reject"])
    rules.append(["inbound": ["diagnostic"], "action": "route", "outbound": "proxy"])
    rules.append(["domain_suffix": policy.domains, "action": "route", "outbound": "proxy"])
    rules.append(["ip_cidr": fakeCidrs, "action": "reject"])

    var route: [String: Any] = [
        "default_domain_resolver": ["server": "remote", "strategy": "ipv4_only"],
        "rules": rules,
        "final": "direct",
    ]
    if !bindInterface.isEmpty {
        route["auto_detect_interface"] = false
        route["default_interface"] = bindInterface
    } else {
        route["auto_detect_interface"] = true
    }

    let cache = dataRoot + "/" + (ipv4Only ? "cache-ipv4.db" : "cache.db")

    return [
        "log": ["disabled": true],
        "dns": [
            "servers": [
                fakeip,
                [
                    "type": "https",
                    "tag": "remote",
                    "server": "1.1.1.1",
                    "server_port": 443,
                    "path": "/dns-query",
                    "tls": ["enabled": true, "server_name": "cloudflare-dns.com"],
                    "detour": "proxy",
                ],
            ],
            "rules": dnsRules,
            "final": "remote",
        ],
        "inbounds": [
            ["type": "direct", "tag": "dns-in", "listen": ST.dnsListen, "listen_port": ST.dnsPort],
            ["type": "mixed", "tag": "diagnostic", "listen": ST.diagListen, "listen_port": ST.diagPort],
            tun,
        ],
        "outbounds": [proxy, ["type": "direct", "tag": "direct"]],
        "route": route,
        "experimental": ["cache_file": ["enabled": true, "path": cache, "store_fakeip": true]],
    ]
}

public func engineConfigJson(_ config: [String: Any]) throws -> Data {
    try JSONSerialization.data(withJSONObject: config, options: [])
}
