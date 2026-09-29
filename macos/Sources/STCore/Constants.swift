import Foundation

/// Общие константы. Зеркалят src/core/constants.h Windows-версии.
public enum ST {
    public static let appName = "SelectiveTunnel"
    public static let version = "2.0.0"
    public static let launchDaemonLabel = "com.selectivetunnel.daemon"

    // Каталоги (демон работает от root, данные общесистемные).
    public static let dataRoot = "/Library/Application Support/SelectiveTunnel"
    public static let binDir = dataRoot + "/bin"
    public static let runDir = dataRoot + "/run"
    public static let logDir = "/Library/Logs/SelectiveTunnel"

    public static let enginePath = binDir + "/sing-box"
    public static let daemonPath = binDir + "/selectivetunnel-daemon"

    public static let connectionPath = dataRoot + "/connection.json"
    public static let policyPath = dataRoot + "/policy.json"
    public static let desiredPath = dataRoot + "/desired.json"
    public static let statusPath = dataRoot + "/status.json"
    public static let refreshRequestPath = dataRoot + "/refresh.request"
    public static let ipv4OnlyFlagPath = dataRoot + "/tun-ipv4-only.flag"
    public static let guardsStatePath = dataRoot + "/guards.json"
    public static let guardErrorPath = dataRoot + "/guard-error.txt"
    public static let socketPath = runDir + "/control.sock"

    public static let launchDaemonPlistPath = "/Library/LaunchDaemons/com.selectivetunnel.daemon.plist"
    public static let resolverDir = "/etc/resolver"

    // FakeIP и точки прослушивания — те же, что на Windows.
    public static let fakeV4 = "100.82.0.0/16"
    public static let fakeV4a = "100.82.0.0/17"
    public static let fakeV4b = "100.82.128.0/17"
    public static let fakeV6 = "fd71:5e1e:c710::/48"
    public static let fakeV6a = "fd71:5e1e:c710::/49"
    public static let fakeV6b = "fd71:5e1e:c710:8000::/49"
    public static let dnsListen = "127.0.0.53"
    public static let dnsPort = 53
    public static let diagListen = "127.0.0.1"
    public static let diagPort = 17891
    public static let tunV4 = "172.31.255.1/30"
    public static let tunV6 = "fd71:5e1e:c711::1/126"
    public static let tunV4Net = "172.31.255.0/30"
    public static let tunV6Net = "fd71:5e1e:c711::/126"

    public static let statusStaleSeconds: TimeInterval = 60

    // sing-box 1.14.0 darwin-arm64 — аналог windows-зависимости.
    public static let singBoxVersion = "1.14.0"
    public static let singBoxTarName = "sing-box-1.14.0-darwin-arm64.tar.gz"
    public static let singBoxURL =
        "https://github.com/SagerNet/sing-box/releases/download/v1.14.0/sing-box-1.14.0-darwin-arm64.tar.gz"
    public static let singBoxTarSha256 = "a150c94012ff768b7261939cd236b9c8554127f45137230295d23a5660225cc9"

    public static let defaultProxyIp = "176.119.140.14"
    public static let defaultSocksPort = 14073
    public static let defaultHttpPort = 4073
}

public enum STError: Error, CustomStringConvertible {
    case message(String)
    public var description: String {
        switch self {
        case .message(let text): return text
        }
    }
}
