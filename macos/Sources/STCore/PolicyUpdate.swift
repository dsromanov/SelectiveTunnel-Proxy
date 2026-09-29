import Foundation
#if canImport(Security)
import Security
#endif
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// Порт src/core/policy.cpp (ReceivePolicy/ConvertFromSignedPolicy) и crypto.cpp (VerifyRsaSha256).
// Ключ — .NET XML <RSAKeyValue><Modulus/><Exponent/></RSAKeyValue>, проверка PKCS#1 v1.5 SHA-256
// через Security.framework.

private func xmlField(_ xml: String, _ tag: String) -> String? {
    guard let open = xml.range(of: "<\(tag)>"),
          let close = xml.range(of: "</\(tag)>", range: open.upperBound..<xml.endIndex)
    else { return nil }
    return String(xml[open.upperBound..<close.lowerBound])
}

private func derLength(_ n: Int) -> [UInt8] {
    if n < 0x80 { return [UInt8(n)] }
    var bytes: [UInt8] = []
    var v = n
    while v > 0 { bytes.insert(UInt8(v & 0xff), at: 0); v >>= 8 }
    return [0x80 | UInt8(bytes.count)] + bytes
}

private func derInteger(_ raw: Data) -> [UInt8] {
    var bytes = [UInt8](raw)
    while bytes.count > 1 && bytes[0] == 0 && (bytes[1] & 0x80) == 0 {
        bytes.removeFirst()
    }
    if bytes.isEmpty { bytes = [0] }
    if bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }
    return [0x02] + derLength(bytes.count) + bytes
}

private func derSequence(_ content: [UInt8]) -> [UInt8] {
    [0x30] + derLength(content.count) + content
}

#if canImport(Security)
private func rsaSecKey(xml: String) throws -> SecKey {
    guard let modB64 = xmlField(xml, "Modulus"), let expB64 = xmlField(xml, "Exponent"),
          let modulus = Data(base64Encoded: modB64, options: .ignoreUnknownCharacters),
          let exponent = Data(base64Encoded: expB64, options: .ignoreUnknownCharacters),
          modulus.count >= 384 else {
        throw STError.message("A public RSA key of at least 3072 bits is required.")
    }
    let der = Data(derSequence(derInteger(modulus) + derInteger(exponent)))
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits as String: modulus.count * 8,
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(der as CFData, attrs as CFDictionary, &error) else {
        throw STError.message("A public RSA key of at least 3072 bits is required.")
    }
    return key
}

private func verifyRsaSha256(xmlKey: String, message: Data, signature: Data) throws {
    let key = try rsaSecKey(xml: xmlKey)
    guard SecKeyIsAlgorithmSupported(key, .verify, .rsaSignatureMessagePKCS1v15SHA256) else {
        throw STError.message("Invalid policy signature.")
    }
    var error: Unmanaged<CFError>?
    let ok = SecKeyVerifySignature(key, .rsaSignatureMessagePKCS1v15SHA256,
                                   message as CFData, signature as CFData, &error)
    guard ok else {
        throw STError.message("Invalid policy signature.")
    }
}
#else
// Security.framework есть только на Darwin. Linux-сборка нужна лишь для проверки компиляции.
private func verifyRsaSha256(xmlKey: String, message: Data, signature: Data) throws {
    throw STError.message("Policy signature verification requires macOS Security.framework.")
}
#endif

/// HTTPS GET без редиректов, только порт 443 (порт HttpGetNoRedirect на WinHTTP).
public func httpGetNoRedirect(_ urlString: String) throws -> Data {
    guard let url = URL(string: urlString), url.scheme == "https",
          (url.port ?? 443) == 443, url.user == nil, url.query == nil else {
        throw STError.message("Policy URL must be HTTPS on port 443, without credentials or query.")
    }
    final class NoRedirect: NSObject, URLSessionDataDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask,
                        willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest,
                        completionHandler: @escaping (URLRequest?) -> Void) {
            completionHandler(nil)
        }
    }
    let session = URLSession(configuration: .ephemeral, delegate: NoRedirect(), delegateQueue: nil)
    var result: Result<(Data, Int), Error>?
    let sem = DispatchSemaphore(value: 0)
    let task = session.dataTask(with: url) { data, response, error in
        defer { sem.signal() }
        if let error {
            result = .failure(error)
            return
        }
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        result = .success((data ?? Data(), code))
    }
    task.resume()
    if sem.wait(timeout: .now() + 25) == .timedOut {
        task.cancel()
        throw STError.message("Rule update rejected or unavailable; previous policy retained.")
    }
    session.invalidateAndCancel()
    guard case let .success((body, code)) = result, code == 200 else {
        throw STError.message("Rule update rejected or unavailable; previous policy retained.")
    }
    guard body.count <= 131072 else {
        throw STError.message("Policy response is too large.")
    }
    return body
}

private struct PolicyEnvelope: Decodable {
    let payload: String
    let signature: String
}

/// Проверка подписанного пакета и слияние с текущей политикой.
/// Возвращает nil, если новой версии нет (как в ConvertFromSignedPolicy).
public func convertFromSignedPolicy(_ body: Data, profile: Profile, current: Policy) throws -> Policy? {
    guard !profile.policyPublicKey.isEmpty else {
        throw STError.message("No trusted policy signing key configured.")
    }
    let envelope = try JSONDecoder().decode(PolicyEnvelope.self, from: body)
    guard let payload = Data(base64Encoded: envelope.payload, options: .ignoreUnknownCharacters),
          let signature = Data(base64Encoded: envelope.signature, options: .ignoreUnknownCharacters),
          payload.count <= 65536 else {
        throw STError.message("Invalid policy signature.")
    }
    try verifyRsaSha256(xmlKey: profile.policyPublicKey, message: payload, signature: signature)
    let candidate = try JSONDecoder().decode(Policy.self, from: payload)
    try assertPolicy(candidate)
    if candidate.version <= current.version {
        return nil
    }
    let merged = mergePolicies(current: current, candidate: candidate)
    try assertPolicy(merged)
    return merged
}

public func receivePolicy(profile: Profile, current: Policy) throws -> Policy? {
    try assertProfile(profile)
    guard !profile.policyUrl.isEmpty else { return nil }
    let body = try httpGetNoRedirect(profile.policyUrl)
    return try convertFromSignedPolicy(body, profile: profile, current: current)
}
