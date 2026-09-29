import Foundation
import STCore

// Порт src/app/diagnose.cpp — сбор диагностики одним текстовым отчётом.

enum Diagnose {
    static func report(policy: Policy, engineRunning: Bool, enginePid: Int32, bind: String) -> String {
        var lines: [String] = []
        lines.append("SelectiveTunnel \(ST.version) — macOS diagnostics")
        lines.append("Date: \(UtcFormat.now())")
        lines.append("")

        lines.append("== Engine ==")
        lines.append("sing-box path: \(ST.enginePath)")
        if FileManager.default.isExecutableFile(atPath: ST.enginePath) {
            let (code, out) = runCommand(ST.enginePath, ["version"], timeout: 10)
            lines.append("sing-box version: \(code == 0 ? out.trimmingCharacters(in: .whitespacesAndNewlines) : "unreadable")")
        } else {
            lines.append("sing-box: MISSING — run scripts/install.sh")
        }
        lines.append("engine running: \(engineRunning)\(enginePid > 0 ? " (pid \(enginePid))" : "")")
        lines.append("default interface: \(bind.isEmpty ? "auto" : bind)")
        lines.append("")

        lines.append("== Ports ==")
        lines.append("127.0.0.53:53 UDP busy: \(Guards.portBusy(ip: ST.dnsListen, port: UInt16(ST.dnsPort), udp: true))")
        lines.append("127.0.0.53:53 TCP busy: \(Guards.portBusy(ip: ST.dnsListen, port: UInt16(ST.dnsPort), udp: false))")
        lines.append("127.0.0.1:\(ST.diagPort) TCP busy: \(Guards.portBusy(ip: ST.diagListen, port: UInt16(ST.diagPort), udp: false))")
        // Кто держит порт 53 — чужой DNS/VPN ломает запуск sing-box.
        let (_, lsof) = runCommand("/usr/sbin/lsof", ["-nP", "-iUDP@127.0.0.53:53", "-iTCP@127.0.0.53:53"], timeout: 10)
        let holders = lsof.split(separator: "\n").map(String.init)
        if !holders.isEmpty {
            lines.append("port 53 holders:")
            lines.append(contentsOf: holders.prefix(8))
        }
        let engineLog = ST.dataRoot + "/engine.log"
        if let log = try? String(contentsOfFile: engineLog, encoding: .utf8) {
            let tail = log.split(separator: "\n").suffix(10).map(String.init)
            if !tail.isEmpty {
                lines.append("engine.log tail:")
                lines.append(contentsOf: tail)
            }
        }
        lines.append("")

        lines.append("== DNS resolvers (/etc/resolver) ==")
        for domain in policy.domains {
            let path = "\(ST.resolverDir)/\(domain)"
            lines.append("\(domain): \(fileExists(path) ? "managed" : "MISSING")")
        }
        let (scCode, scOut) = runCommand("/usr/sbin/scutil", ["--dns"], timeout: 10)
        if scCode == 0 {
            let hits = scOut.split(separator: "\n").filter {
                $0.contains("127.0.0.53") || $0.contains("domain[")
            }
            lines.append(contentsOf: hits.prefix(30).map(String.init))
        }
        lines.append("")

        lines.append("== Interfaces / routes ==")
        let (_, ifaces) = runCommand("/sbin/ifconfig", ["-l"], timeout: 10)
        lines.append("interfaces: \(ifaces.trimmingCharacters(in: .whitespacesAndNewlines))")
        let (_, route) = runCommand("/sbin/route", ["-n", "get", "default"], timeout: 10)
        for line in route.split(separator: "\n") where line.contains("interface") || line.contains("gateway") {
            lines.append(String(line).trimmingCharacters(in: .whitespaces))
        }
        lines.append("")

        lines.append("== Files ==")
        for path in [ST.connectionPath, ST.policyPath, ST.desiredPath, ST.statusPath, ST.guardErrorPath] {
            let exists = fileExists(path)
            lines.append("\(path): \(exists ? "present" : "absent")")
        }
        if let status = try? readJson(ST.statusPath, Status.self) {
            lines.append("status: \(status.state) — \(status.detail) (\(status.updatedUtc))")
        }
        lines.append("")

        lines.append("== Policy ==")
        lines.append("version: \(policy.version)")
        lines.append("domains: \(policy.domains.joined(separator: ", "))")
        lines.append("")
        lines.append("If an app still resolves a managed domain directly, it may bypass the macOS system resolver")
        lines.append("(own DNS client or DoH). Add a bypass for it in that app, like the Happ exclusions on Windows.")
        return lines.joined(separator: "\n")
    }
}
