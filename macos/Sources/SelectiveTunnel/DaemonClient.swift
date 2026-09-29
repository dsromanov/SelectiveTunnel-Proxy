import Foundation
import STCore

// Клиент IPC демона — асинхронная обёртка над unix-сокетом (аналог Call() в gui.cpp).
// Без Combine/SwiftUI — модель отдаёт обновления через колбэки (сборка работает на голых CLT).

enum DaemonClient {
    static func call(_ request: [String: Any], timeout: Int = 15) async throws -> [String: Any] {
        try await Task.detached {
            try sendIpc(request, timeoutSeconds: timeout)
        }.value
    }
}

@MainActor
final class StatusModel {
    /// Колбэки UI (главное окно, пункт меню) — вызываются на главном потоке.
    private var observers: [@MainActor () -> Void] = []
    /// Показ предупреждения/ответа — как MessageBox на Windows.
    var onAlert: (@MainActor (_ title: String, _ text: String) -> Void)?

    private(set) var statusText = "Запуск…"
    private(set) var domainsText = ""

    private var timer: Timer?
    private var refreshing = false

    func addObserver(_ observer: @escaping @MainActor () -> Void) {
        observers.append(observer)
        observer()
    }

    private func changed() {
        for observer in observers { observer() }
    }

    func start() {
        guard timer == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in
            Task { await self?.refresh() }
        }
        Task { await refresh() }
    }

    func refresh() async {
        guard !refreshing else { return }
        refreshing = true
        defer { refreshing = false }
        do {
            let res = try await DaemonClient.call(["cmd": "status"], timeout: 5)
            applyStatus(res)
        } catch {
            statusText = "Служба не отвечает — запустите: sudo bash macos/scripts/install.sh"
            changed()
        }
    }

    private func applyStatus(_ res: [String: Any]) {
        if res["ok"] as? Bool == true,
           let data = try? JSONSerialization.data(withJSONObject: res),
           let status = try? JSONDecoder().decode(Status.self, from: data) {
            if status.isStale {
                statusText = "Служба не отвечает"
            } else {
                switch status.state {
                case "running": statusText = "Figma и ChatGPT — через прокси"
                case "blocked": statusText = "Figma и ChatGPT заблокированы"
                case "error": statusText = "Ошибка. Откройте «Ещё» → Диагностика"
                default: statusText = status.state
                }
            }
        } else {
            statusText = "Служба не отвечает"
        }
        if let domains = res["domains"] as? [String], !domains.isEmpty {
            domainsText = "Домены: " + domains.joined(separator: ", ")
        }
        changed()
    }

    /// Отправка команды с показом ответа, как Call() в gui.cpp.
    @discardableResult
    func command(_ cmd: String, extra: [String: Any] = [:], timeout: Int = 15) async -> [String: Any] {
        var request = extra
        request["cmd"] = cmd
        do {
            let res = try await DaemonClient.call(request, timeout: timeout)
            if let error = res["error"] as? String, res["ok"] as? Bool != true {
                onAlert?("SelectiveTunnel", error)
            } else if let message = res["message"] as? String {
                onAlert?("SelectiveTunnel", message)
            } else if let verify = res["verify"] as? String {
                onAlert?("Egress verification", verify)
            }
            await refresh()
            return res
        } catch let error as STError {
            onAlert?("SelectiveTunnel", error.description)
            return ["ok": false]
        } catch {
            onAlert?("SelectiveTunnel", error.localizedDescription)
            return ["ok": false]
        }
    }
}
