import Foundation
import STCore

#if canImport(Darwin)
import Darwin
#endif

// Порт src/core/guards.cpp: на Windows DNS-политики ставились через NRPT,
// на macOS аналог — per-domain резолверы в /etc/resolver/<domain>,
// которые отправляют запросы выбранных доменов на 127.0.0.53:53 (sing-box).

enum Guards {

    private static let resolverBody = "# SelectiveTunnel\nnameserver \(ST.dnsListen)\nport \(ST.dnsPort)\n"

    private static func readManaged() -> Set<String> {
        guard let data = FileManager.default.contents(atPath: ST.guardsStatePath),
              let list = try? JSONDecoder().decode([String].self, from: data)
        else { return [] }
        return Set(list)
    }

    private static func writeManaged(_ domains: Set<String>) {
        try? writeJsonAtomic(ST.guardsStatePath, domains.sorted())
    }

    private static func resolverFile(_ domain: String) -> String {
        "\(ST.resolverDir)/\(domain)"
    }

    /// Ставит резолверы для доменов политики, убирает устаревшие, которыми мы управляем.
    static func setGuards(_ policy: Policy) throws {
        try FileManager.default.createDirectory(atPath: ST.resolverDir, withIntermediateDirectories: true)
        let managed = readManaged()
        let wanted = Set(policy.domains)
        var touched = false
        for domain in managed.subtracting(wanted) {
            try? FileManager.default.removeItem(atPath: resolverFile(domain))
            touched = true
        }
        for domain in wanted {
            let path = resolverFile(domain)
            let current = FileManager.default.contents(atPath: path).flatMap { String(data: $0, encoding: .utf8) }
            if current != resolverBody {
                try resolverBody.write(toFile: path, atomically: true, encoding: .utf8)
                chmod(path, 0o644)
                touched = true
            }
        }
        writeManaged(wanted)
        if touched {
            clearDnsCache()
        }
    }

    /// Снимает все DNS-правила, которыми управляет демон (uninstall / shutdown).
    static func clearGuards() {
        for domain in readManaged() {
            try? FileManager.default.removeItem(atPath: resolverFile(domain))
        }
        writeManaged([])
        clearDnsCache()
    }

    /// Очистка DNS-кеша, как ClearDnsCache на Windows.
    static func clearDnsCache() {
        runCommand("/usr/bin/dscacheutil", ["-flushcache"])
        runCommand("/usr/bin/killall", ["-HUP", "mDNSResponder"])
    }

    /// Интерфейс default-маршрута (en0 и т.п.) — аналог DetectBindInterface.
    static func detectBindInterface() -> String {
        let (code, out) = runCommand("/sbin/route", ["-n", "get", "default"], timeout: 10)
        guard code == 0 else { return "" }
        for line in out.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2, parts[0] == "interface" {
                return parts[1]
            }
        }
        return ""
    }

    /// Порт ApplyProxyBypass: если сторонний клиент (Happ и т.п.) включил системный
    /// прокси, добавляем домены политики в список исключений сетевых служб,
    /// чтобы они шли в TUN, а не в этот прокси.
    static func applyProxyBypass(_ policy: Policy) {
        let (code, list) = runCommand("/usr/sbin/networksetup", ["-listallnetworkservices"], timeout: 15)
        guard code == 0 else { return }
        let services = list.split(separator: "\n")
            .map { String($0).trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("*") && !$0.hasPrefix("An asterisk") }
        var bypass: [String] = []
        for domain in policy.domains {
            bypass.append(domain)
            bypass.append("*.\(domain)")
        }
        for service in services {
            guard proxyEnabled(service: service) else { continue }
            let (_, current) = runCommand("/usr/sbin/networksetup", ["-getproxybypassdomains", service], timeout: 15)
            var merged = current.split(separator: "\n").map { String($0) }
                .filter { !$0.contains("aren't any bypass") }
            let before = Set(merged)
            for domain in bypass where !before.contains(domain) {
                merged.append(domain)
            }
            if merged.count != before.count {
                runCommand("/usr/sbin/networksetup", ["-setproxybypassdomains", service] + merged, timeout: 15)
            }
        }
    }

    private static func proxyEnabled(service: String) -> Bool {
        for opt in ["-getwebproxy", "-getsecurewebproxy", "-getsocksfirewallproxy"] {
            let (code, out) = runCommand("/usr/sbin/networksetup", [opt, service], timeout: 15)
            if code == 0, out.contains("Enabled: Yes") {
                return true
            }
        }
        return false
    }

    /// Свободны ли порты для sing-box (проверка при установке/диагностике).
    static func portBusy(ip: String, port: UInt16, udp: Bool) -> Bool {
        #if canImport(Darwin)
        let dgram = SOCK_DGRAM
        #else
        let dgram = Int32(SOCK_DGRAM.rawValue)
        #endif
        let fd = socket(AF_INET, udp ? dgram : stSockStream, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        #if canImport(Darwin)
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        #endif
        inet_pton(AF_INET, ip, &addr.sin_addr)
        let rc = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                bind(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return rc != 0
    }
}
