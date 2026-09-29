import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// Порт src/core/ipc.cpp: вместо named pipe — unix domain socket.
// Протокол тот же: один JSON-запрос -> один JSON-ответ, соединение закрывается.

private func makeSocketAddr(_ path: String) -> sockaddr_un {
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    #if canImport(Darwin)
    addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    #endif
    let capacity = MemoryLayout.size(ofValue: addr.sun_path) - 1
    _ = withUnsafeMutableBytes(of: &addr.sun_path) { buf in
        path.withCString { cstr in
            strncpy(buf.baseAddress!.assumingMemoryBound(to: CChar.self), cstr, capacity)
        }
    }
    return addr
}

// В Glibc SOCK_STREAM — enum __socket_type, в Darwin — Int32.
#if canImport(Darwin)
public let stSockStream = SOCK_STREAM
#else
public let stSockStream = Int32(SOCK_STREAM.rawValue)
#endif

private func newStreamSocket() throws -> Int32 {
    let fd = socket(AF_UNIX, stSockStream, 0)
    guard fd >= 0 else {
        throw STError.message("Cannot create IPC socket.")
    }
    // На macOS send() на закрытом сокете бросает SIGPIPE — глушим через SO_NOSIGPIPE.
    #if canImport(Darwin)
    var yes: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))
    #endif
    return fd
}

private func writeAll(_ fd: Int32, _ data: Data) throws {
    try data.withUnsafeBytes { raw in
        var offset = 0
        while offset < raw.count {
            let n = send(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset, 0)
            if n <= 0 {
                throw STError.message("Cannot send command to the service.")
            }
            offset += n
        }
    }
}

private func readAll(_ fd: Int32, timeoutSeconds: Int) throws -> Data {
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 65536)
    let deadline = Date().addingTimeInterval(TimeInterval(timeoutSeconds))
    while true {
        var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let remaining = Int32(max(1, deadline.timeIntervalSinceNow * 1000))
        let ready = poll(&pfd, 1, remaining)
        if ready == 0 { throw STError.message("Service did not answer.") }
        if ready < 0 { throw STError.message("IPC read failed.") }
        if (pfd.revents & Int16(POLLIN)) != 0 {
            let n = buffer.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
            if n <= 0 { break }
            data.append(contentsOf: buffer[..<n])
            if data.count > 1_048_576 { throw STError.message("Service response is too large.") }
        } else if (pfd.revents & Int16(POLLHUP | POLLERR | POLLNVAL)) != 0 {
            break
        }
    }
    return data
}

/// Отправка запроса демону (клиентская сторона, из приложения).
public func sendIpc(_ request: [String: Any], timeoutSeconds: Int = 10) throws -> [String: Any] {
    let payload = try JSONSerialization.data(withJSONObject: request, options: [])
    let fd = try newStreamSocket()
    defer { close(fd) }
    var addr = makeSocketAddr(ST.socketPath)
    let result = withUnsafePointer(to: &addr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            connect(fd, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    guard result == 0 else {
        throw STError.message("Background service is not running.")
    }
    try writeAll(fd, payload)
    shutdown(fd, Int32(SHUT_WR))
    let raw = try readAll(fd, timeoutSeconds: timeoutSeconds)
    guard let json = try JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
        throw STError.message("Invalid service response.")
    }
    return json
}

public typealias IpcHandler = ([String: Any]) -> [String: Any]

/// Цикл accept() unix-сокета демона. Вызывается на отдельном потоке.
public func runSocketServer(stop: @escaping () -> Bool, handler: @escaping IpcHandler) {
    unlink(ST.socketPath)
    guard let server = try? newStreamSocket() else { return }
    defer { close(server) }

    var addr = makeSocketAddr(ST.socketPath)
    let bound = withUnsafePointer(to: &addr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            bind(server, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    guard bound == 0, listen(server, 16) == 0 else { return }
    // Клиент — обычное приложение без root, поэтому сокет открыт для всех локальных пользователей.
    chmod(ST.socketPath, 0o666)

    while !stop() {
        var pfd = pollfd(fd: server, events: Int16(POLLIN), revents: 0)
        if poll(&pfd, 1, 500) <= 0 { continue }
        let client = accept(server, nil, nil)
        if client < 0 { continue }
        // SO_NOSIGPIPE не наследуется через accept() — ставим и на клиентском сокете.
        #if canImport(Darwin)
        var yes: Int32 = 1
        setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))
        #endif
        // Обработка последовательная, как у named pipe на Windows: один клиент за раз.
        if let raw = try? readAll(client, timeoutSeconds: 30), !raw.isEmpty {
            let request = (try? JSONSerialization.jsonObject(with: raw)) as? [String: Any] ?? ["cmd": ""]
            let response = handler(request)
            if let text = try? JSONSerialization.data(withJSONObject: response, options: []) {
                try? writeAll(client, text)
            }
        }
        close(client)
    }
    unlink(ST.socketPath)
}
