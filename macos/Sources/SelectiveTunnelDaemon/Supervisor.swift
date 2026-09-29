import Foundation
import STCore

#if canImport(Darwin)
import Darwin
#endif

// Порт src/service/supervisor.cpp: цикл надзирателя + JSON-команды по IPC.
// Желаемый режим хранится в desired.json ("connected"/"blocked"), состояние — в status.json.

final class Supervisor {
    private let engine = Engine()
    private var policy = Policy()
    private var updateError = ""
    private var bindInterface = ""
    private var lastMaintenance = Date.distantPast
    private var nextUpdate = Date.distantPast
    private let wake = DispatchSemaphore(value: 0)
    private let stateQueue = DispatchQueue(label: "st.supervisor.ipc", attributes: .concurrent)
    private var stopping = false

    var isStopping: Bool {
        stateQueue.sync { stopping }
    }

    func requestStop() {
        stateQueue.sync(flags: .barrier) { stopping = true }
        wake.signal()
    }

    private func writeState(_ state: String, _ detail: String) {
        var status = Status()
        status.state = state
        status.detail = detail
        status.updatedUtc = UtcFormat.now()
        status.policyVersion = policy.version
        status.updateError = updateError
        status.enginePid = engine.running ? Int(engine.pid) : nil
        try? writeJsonAtomic(ST.statusPath, status, mode: 0o644)
    }

    private struct Desired: Codable { let mode: String }

    private func ipv4Only() -> Bool { fileExists(ST.ipv4OnlyFlagPath) }

    private func readDesired() -> String {
        guard let d = try? readJson(ST.desiredPath, Desired.self),
              d.mode == "connected" || d.mode == "blocked" else {
            return "blocked"
        }
        return d.mode
    }

    private func setDesired(_ mode: String) {
        try? writeJsonAtomic(ST.desiredPath, Desired(mode: mode))
    }

    private func loadPolicy() throws -> Policy {
        let p = try readJson(ST.policyPath, Policy.self)
        try assertPolicy(p)
        return p
    }

    private func readProfile() throws -> Profile {
        let p = try readJson(ST.connectionPath, Profile.self)
        try assertProfile(p)
        return p
    }

    // MARK: - IPC

    private func ok(_ extra: [String: Any] = [:]) -> [String: Any] {
        var json = extra
        json["ok"] = true
        return json
    }

    private func err(_ message: String) -> [String: Any] {
        ["ok": false, "error": message]
    }

    func dispatch(_ request: [String: Any]) -> [String: Any] {
        let cmd = request["cmd"] as? String ?? ""
        do {
            switch cmd {
            case "status":
                guard let status = try? readJson(ST.statusPath, Status.self) else {
                    return err("Background service is not running.")
                }
                var json = try JSONSerialization.jsonObject(
                    with: JSONEncoder().encode(status)) as? [String: Any] ?? [:]
                json["ok"] = true
                json["bind_interface"] = bindInterface
                json["domains"] = policy.domains
                return json
            case "connect":
                let loaded = try loadPolicy()
                try Guards.setGuards(loaded)
                setDesired("connected")
                wake.signal()
                return ok()
            case "block":
                if let loaded = try? loadPolicy() {
                    try? Guards.setGuards(loaded)
                }
                setDesired("blocked")
                killOwnEngine()
                engine.stop()
                Guards.clearDnsCache()
                wake.signal()
                return ok()
            case "refresh":
                _ = FileManager.default.createFile(atPath: ST.refreshRequestPath, contents: Data("1".utf8))
                wake.signal()
                return ok()
            case "verify":
                let result = try verifyEgress()
                return ok(["verify": result])
            case "save_profile":
                let data = try JSONSerialization.data(withJSONObject: request["profile"] ?? NSNull())
                var incoming = try JSONDecoder().decode(Profile.self, from: data)
                if incoming.password.isEmpty, let current = try? readProfile() {
                    incoming.password = current.password
                }
                let loaded = try loadPolicy()
                let config = try newEngineConfig(profile: incoming, policy: loaded,
                                               dataRoot: ST.dataRoot,
                                               bindInterface: Guards.detectBindInterface(),
                                               ipv4Only: ipv4Only())
                try engine.testConfig(config)
                setDesired("blocked")
                killOwnEngine()
                engine.stop()
                try writeJsonAtomic(ST.connectionPath, incoming, mode: 0o600)
                wake.signal()
                return ok(["message": "Сохранено. Нажмите «Через прокси»."])
            case "import_policy":
                let data = try JSONSerialization.data(withJSONObject: request["policy"] ?? NSNull())
                let candidate = try JSONDecoder().decode(Policy.self, from: data)
                try assertProxyPolicy(candidate)
                let current = try loadPolicy()
                guard candidate.version > current.version else {
                    return err("Increase the policy version before importing.")
                }
                let merged = mergePolicies(current: current, candidate: candidate)
                let profile = try readProfile()
                let config = try newEngineConfig(profile: profile, policy: merged,
                                               dataRoot: ST.dataRoot,
                                               bindInterface: Guards.detectBindInterface(),
                                               ipv4Only: ipv4Only())
                try engine.testConfig(config)
                setDesired("blocked")
                killOwnEngine()
                engine.stop()
                try Guards.setGuards(merged)
                try writeJsonAtomic(ST.policyPath, merged)
                policy = merged
                wake.signal()
                return ok(["message": "Список обновлён. Нажмите «Через прокси»."])
            case "get_profile":
                // Если профиля ещё нет — отдаём дефолтный, как в Windows-форме настроек.
                var profile = (try? readProfile()) ?? Profile()
                profile.password = ""
                return ok(["profile": try JSONSerialization.jsonObject(with: JSONEncoder().encode(profile))])
            case "diagnose":
                return ok(["report": Diagnose.report(policy: policy, engineRunning: engine.running,
                                                   enginePid: engine.pid, bind: bindInterface)])
            default:
                return err("Unknown command.")
            }
        } catch let error as STError {
            return err(error.description)
        } catch {
            return err(error.localizedDescription)
        }
    }

    // MARK: - Supervisor loop

    private func verifyEgress() throws -> String {
        let profile = try readProfile()
        let proxied = try runCurl([
            "--noproxy", "no-bypass.invalid", "--socks5-hostname", "\(ST.diagListen):\(ST.diagPort)",
            "https://api.ipify.org",
        ])
        guard isIpv4(proxied) else {
            throw STError.message("Proxy probe returned an invalid IP.")
        }
        if !profile.expectedExitIp.isEmpty && proxied != profile.expectedExitIp {
            throw STError.message("Unexpected proxy egress: \(proxied); expected \(profile.expectedExitIp).")
        }
        let direct: String
        do {
            direct = try runCurl(["--noproxy", "*", "https://api.ipify.org"])
        } catch {
            throw STError.message("Direct probe failed: \(error.localizedDescription)")
        }
        return "Proxy egress: \(proxied)\nOrdinary direct egress: \(direct)"
    }

    private func runCurl(_ extra: [String]) throws -> String {
        let (code, out) = runCommand("/usr/bin/curl",
                                     ["--silent", "--show-error", "--fail", "--max-time", "12"] + extra,
                                     timeout: 15)
        let text = out.trimmingCharacters(in: .whitespacesAndNewlines)
        guard code == 0 else {
            throw STError.message("Tunnel probe failed: \(text)")
        }
        return text
    }

    func run() {
        // Один экземпляр демона (аналог guard.lock).
        let lockFd = open(ST.dataRoot + "/guard.lock", O_CREAT | O_RDWR, 0o600)
        if lockFd >= 0 { flock(lockFd, LOCK_EX | LOCK_NB) }

        // IPC-сервер поднимаем всегда — иначе приложение не сможет сохранить профиль.
        let ipcThread = Thread { [weak self] in
            runSocketServer(stop: { self?.isStopping ?? true }) { [weak self] request in
                self?.dispatch(request) ?? ["ok": false, "error": "Service is stopping."]
            }
        }
        ipcThread.start()

        do {
            policy = try loadPolicy()
            killOwnEngine()
            try? Guards.setGuards(policy)
        } catch {
            writeGuardError("Supervisor startup failed. Check connection profile, installation and system DNS rules.")
        }

        while !isStopping {
            do {
                let desired = readDesired()
                if desired == "blocked" {
                    engine.stop()
                    if Date().timeIntervalSince(lastMaintenance) > 30 {
                        if policy.version > 0 {
                            try? Guards.setGuards(policy)
                            Guards.applyProxyBypass(policy)
                        }
                        lastMaintenance = Date()
                    }
                    writeState("blocked", "Selected domains blocked. Other traffic stays direct.")
                    _ = wake.wait(timeout: .now() + 2)
                    continue
                }

                if Date().timeIntervalSince(lastMaintenance) > 30 {
                    if policy.version > 0 {
                        try? Guards.setGuards(policy)
                        Guards.applyProxyBypass(policy)
                    }
                    let bind = Guards.detectBindInterface()
                    if !bind.isEmpty, bind != bindInterface, engine.running {
                        engine.stop()
                    }
                    bindInterface = bind
                    lastMaintenance = Date()
                }

                if !engine.running {
                    engine.stop()
                    let profile = try readProfile()
                    policy = try loadPolicy()
                    bindInterface = Guards.detectBindInterface()
                    let config = try newEngineConfig(profile: profile, policy: policy,
                                                   dataRoot: ST.dataRoot,
                                                   bindInterface: bindInterface,
                                                   ipv4Only: ipv4Only())
                    try engine.testConfig(config)
                    try engine.startMemory(config)
                    Thread.sleep(forTimeInterval: 2)
                    if !engine.running {
                        throw STError.message(
                            "Proxy engine could not start. Check local ports and network configuration.")
                    }
                    Guards.clearDnsCache()
                }
                writeState("running", "Engine running. Verify egress checks proxy access and the external IP.")

                let refresh = fileExists(ST.refreshRequestPath)
                if refresh || Date() >= nextUpdate {
                    if refresh { try? FileManager.default.removeItem(atPath: ST.refreshRequestPath) }
                    nextUpdate = Date().addingTimeInterval(6 * 3600)
                    do {
                        let profile = try readProfile()
                        if profile.policyUrl.isEmpty {
                            updateError = "No signed feed. DNS IPs refresh automatically; import domain rules locally."
                        } else {
                            if let candidate = try receivePolicy(profile: profile, current: policy) {
                                let config = try newEngineConfig(profile: profile, policy: candidate,
                                                                 dataRoot: ST.dataRoot,
                                                                 bindInterface: bindInterface,
                                                                 ipv4Only: ipv4Only())
                                try engine.testConfig(config)
                                engine.stop()
                                try Guards.setGuards(candidate)
                                try writeJsonAtomic(ST.policyPath, candidate)
                                policy = candidate
                            }
                            updateError = ""
                        }
                    } catch {
                        updateError = "Rule update rejected or unavailable; previous policy retained."
                        nextUpdate = Date().addingTimeInterval(15 * 60)
                    }
                }
            } catch {
                engine.stop()
                let detail = (error as? STError)?.description ?? error.localizedDescription
                writeState("error", "Engine stopped safely. \(detail)")
                Thread.sleep(forTimeInterval: 5)
            }
            _ = wake.wait(timeout: .now() + 2)
        }
        engine.stop()
    }

    private func writeGuardError(_ text: String) {
        try? text.write(toFile: ST.guardErrorPath, atomically: false, encoding: .utf8)
    }
}
