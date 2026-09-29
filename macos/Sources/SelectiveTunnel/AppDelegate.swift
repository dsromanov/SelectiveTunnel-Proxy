import AppKit
import STCore

// Трей-иконка (NSStatusItem) + главное окно — порт трея и окна из gui.cpp.

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let model = StatusModel()
    private var statusItem: NSStatusItem!
    private var statusMenuItem: NSMenuItem!
    private var mainWindow: MainWindowController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem.button?.image = NSImage(
            systemSymbolName: "network.badge.shield.half.filled",
            accessibilityDescription: "SelectiveTunnel")
            ?? NSImage(systemSymbolName: "network", accessibilityDescription: "SelectiveTunnel")

        let menu = NSMenu()
        statusMenuItem = NSMenuItem(title: "SelectiveTunnel", action: nil, keyEquivalent: "")
        statusMenuItem.isEnabled = false
        menu.addItem(statusMenuItem)
        menu.addItem(.separator())
        menu.addItem(makeItem("Через прокси", action: #selector(onConnect)))
        menu.addItem(makeItem("Заблокировать", action: #selector(onBlock)))
        menu.addItem(.separator())
        menu.addItem(makeItem("Открыть", action: #selector(onOpen)))
        menu.addItem(makeItem("Выход", action: #selector(onQuit)))
        statusItem.menu = menu

        model.addObserver { [weak self] in
            guard let self else { return }
            self.statusMenuItem.title = self.model.statusText
        }
        model.onAlert = { title, text in
            let alert = NSAlert()
            alert.messageText = title
            alert.informativeText = text
            alert.alertStyle = .informational
            alert.runModal()
        }
        model.start()
        onOpen()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false  // как крестик на Windows: прячет окно, служба живёт
    }

    private func makeItem(_ title: String, action: Selector) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
        item.target = self
        return item
    }

    @objc private func onConnect() { Task { await model.command("connect") } }
    @objc private func onBlock() { Task { await model.command("block") } }
    @objc private func onQuit() { NSApp.terminate(nil) }

    @objc private func onOpen() {
        if mainWindow == nil {
            mainWindow = MainWindowController(model: model)
        }
        mainWindow?.showWindow(nil)
        mainWindow?.window?.orderFrontRegardless()
        NSApp.activate(ignoringOtherApps: true)
    }
}
