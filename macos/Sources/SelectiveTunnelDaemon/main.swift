import Foundation
import STCore

// selectivetunnel-daemon — root-демон под launchd (аналог SelectiveTunnelSvc на Windows).
// Запуск: LaunchDaemon com.selectivetunnel.daemon, KeepAlive.

#if canImport(Darwin)
import Darwin
#endif

guard geteuid() == 0 else {
    FileHandle.standardError.write("selectivetunnel-daemon must run as root (LaunchDaemon).\n".data(using: .utf8)!)
    exit(1)
}

// send()/write() на закрытых пайпах и сокетах не должны ронять демон.
signal(SIGPIPE, SIG_IGN)

let supervisor = Supervisor()

// Мягкая остановка по SIGTERM/SIGINT: цикл завершится и остановит sing-box.
var signalSources: [DispatchSourceSignal] = []
for sig in [SIGTERM, SIGINT] {
    signal(sig, SIG_IGN)
    let source = DispatchSource.makeSignalSource(signal: sig, queue: .global())
    source.setEventHandler { supervisor.requestStop() }
    source.resume()
    signalSources.append(source)
}

supervisor.run()
