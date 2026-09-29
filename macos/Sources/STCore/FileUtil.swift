import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// Порты src/core/json_io.cpp / util.cpp — атомарная запись и чтение JSON.

/// Атомарная запись: временный файл рядом + rename().
public func writeDataAtomic(_ path: String, _ data: Data, mode: mode_t? = nil) throws {
    let url = URL(fileURLWithPath: path)
    let dir = url.deletingLastPathComponent()
    let tmp = dir.appendingPathComponent(".\(url.lastPathComponent).tmp-\(UUID().uuidString)")
    try data.write(to: tmp, options: [])
    if let mode {
        chmod(tmp.path, mode)
    }
    guard rename(tmp.path, url.path) == 0 else {
        try? FileManager.default.removeItem(at: tmp)
        throw STError.message("Cannot write \(path): \(String(cString: strerror(errno)))")
    }
}

public func writeJsonAtomic(_ path: String, _ value: some Encodable, mode: mode_t? = nil) throws {
    let data = try JSONEncoder().encode(value)
    try writeDataAtomic(path, data, mode: mode)
}

public func readJson<T: Decodable>(_ path: String, _ type: T.Type) throws -> T {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    return try JSONDecoder().decode(T.self, from: data)
}

public func fileExists(_ path: String) -> Bool {
    FileManager.default.fileExists(atPath: path)
}
