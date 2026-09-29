import AppKit

// SelectiveTunnel.app — GUI-клиент (аналог SelectiveTunnel.exe на Windows).
// Чистый AppKit: собирается Command Line Tools без Xcode.
// @main-тип вместо top-level кода: top-level в main.swift nonisolated,
// а AppDelegate — @MainActor.

@main
@MainActor
enum AppMain {
    static func main() {
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.setActivationPolicy(.regular)
        app.run()
    }
}
