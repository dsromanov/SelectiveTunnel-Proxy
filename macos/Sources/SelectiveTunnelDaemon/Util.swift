import Foundation

#if canImport(Darwin)
import Darwin
#endif

/// Запуск утилиты с захватом stdout (аналог RunHidden на Windows).
@discardableResult
func runCommand(_ path: String, _ args: [String], timeout: TimeInterval = 30) -> (code: Int32, out: String) {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: path)
    proc.arguments = args
    let pipe = Pipe()
    proc.standardOutput = pipe
    proc.standardError = FileHandle.nullDevice
    do {
        try proc.run()
    } catch {
        return (-1, "")
    }
    let deadline = Date().addingTimeInterval(timeout)
    while proc.isRunning && Date() < deadline {
        Thread.sleep(forTimeInterval: 0.05)
    }
    if proc.isRunning {
        proc.terminate()
        kill(proc.processIdentifier, SIGKILL)
    }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    proc.waitUntilExit()
    return (proc.terminationStatus, String(data: data, encoding: .utf8) ?? "")
}

#if canImport(Darwin)
@_silgen_name("proc_pidpath")
private func proc_pidpath(_ pid: pid_t, _ buffer: UnsafeMutableRawPointer, _ bufsize: UInt32) -> Int32
#endif

/// Путь к исполняемому файлу процесса.
func executablePath(of pid: pid_t) -> String? {
    #if canImport(Darwin)
    var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    let n = proc_pidpath(pid, &buffer, UInt32(buffer.count))
    guard n > 0 else { return nil }
    return String(cString: buffer)
    #else
    return try? FileManager.default.destinationOfSymbolicLink(atPath: "/proc/\(pid)/exe")
    #endif
}
