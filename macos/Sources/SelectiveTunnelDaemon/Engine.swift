import Foundation
import STCore

#if canImport(Darwin)
import Darwin
#endif

// Порт src/core/engine.cpp: sing-box получает конфиг через stdin (`run -c stdin` /
// `check -c stdin`), учётные данные прокси на диск не пишутся.

final class Engine {
    private var process: Process?

    var pid: Int32 {
        guard let p = process, p.isRunning else { return 0 }
        return p.processIdentifier
    }

    var running: Bool { process?.isRunning == true }

    private func spawn(mode: String, config: [String: Any], stderr: Any = FileHandle.nullDevice) throws -> Process {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: ST.enginePath)
        proc.arguments = [mode, "-c", "stdin"]
        let stdinPipe = Pipe()
        proc.standardInput = stdinPipe
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = stderr
        do {
            try proc.run()
        } catch {
            throw STError.message("Could not start the proxy engine. No credentials were written to disk.")
        }
        let json = try engineConfigJson(config)
        do {
            try stdinPipe.fileHandleForWriting.write(contentsOf: json)
            try stdinPipe.fileHandleForWriting.close()
        } catch {
            proc.terminate()
            throw STError.message("Could not start the proxy engine. No credentials were written to disk.")
        }
        return proc
    }

    /// Лог движка — stderr sing-box, иначе причина падения не видна нигде.
    private func engineLogHandle() -> FileHandle {
        let path = ST.dataRoot + "/engine.log"
        _ = FileManager.default.createFile(atPath: path, contents: nil)
        if let handle = FileHandle(forWritingAtPath: path) {
            handle.truncateFile(atOffset: 0)
            return handle
        }
        return FileHandle.nullDevice
    }

    /// Запуск `sing-box run` с конфигом из памяти.
    func startMemory(_ config: [String: Any]) throws {
        stop()
        process = try spawn(mode: "run", config: config, stderr: engineLogHandle())
    }

    /// Проверка конфига `sing-box check` — stderr сохраняем, там причина отказа.
    func testConfig(_ config: [String: Any]) throws {
        let errPipe = Pipe()
        let proc = try spawn(mode: "check", config: config, stderr: errPipe)
        let deadline = Date().addingTimeInterval(15)
        while proc.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if proc.isRunning {
            proc.terminate()
            proc.waitUntilExit()
            throw STError.message("Engine configuration check timed out.")
        }
        proc.waitUntilExit()
        guard proc.terminationStatus == 0 else {
            let raw = errPipe.fileHandleForReading.readDataToEndOfFile()
            let tail = String(data: raw, encoding: .utf8)?
                .split(separator: "\n").suffix(3).joined(separator: " ")
            throw STError.message(
                "Engine rejected proxy settings. " + (tail?.isEmpty == false ? tail! : "Check host, port, protocol and credentials format."))
        }
    }

    func stop() {
        guard let p = process else { return }
        if p.isRunning {
            p.terminate()
            let deadline = Date().addingTimeInterval(5)
            while p.isRunning && Date() < deadline {
                Thread.sleep(forTimeInterval: 0.05)
            }
            if p.isRunning {
                kill(p.processIdentifier, SIGKILL)
            }
        }
        p.waitUntilExit()
        process = nil
    }
}

/// Убивает сторонние экземпляры нашего sing-box (по точному пути бинаря), как KillOwnEngine.
func killOwnEngine() {
    let (code, out) = runCommand("/usr/bin/pgrep", ["-x", "sing-box"], timeout: 10)
    guard code == 0 else { return }
    for line in out.split(separator: "\n") {
        guard let pid = pid_t(line.trimmingCharacters(in: .whitespaces)) else { continue }
        if pid != getpid(), executablePath(of: pid) == ST.enginePath {
            kill(pid, SIGKILL)
        }
    }
}
