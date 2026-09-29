import AppKit
import STCore
import UniformTypeIdentifiers

// Главное окно — порт разметки gui.cpp: заголовок, статус, домены, кнопки.

@MainActor
final class MainWindowController: NSWindowController {
    private let model: StatusModel
    private let statusLabel = NSTextField(labelWithString: "")
    private let domainsLabel = NSTextField(wrappingLabelWithString: "")
    private var settingsWindow: SettingsWindowController?
    private var diagnoseWindow: DiagnoseWindowController?

    init(model: StatusModel) {
        self.model = model
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 540, height: 290),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered, defer: false)
        window.title = "SelectiveTunnel \(ST.version)"
        window.center()
        super.init(window: window)
        build()

        model.addObserver { [weak self] in
            guard let self else { return }
            self.statusLabel.stringValue = self.model.statusText
            self.domainsLabel.stringValue = self.model.domainsText
        }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError() }

    private func build() {
        guard let content = window?.contentView else { return }

        let titleLabel = NSTextField(labelWithString: "Figma / ChatGPT")
        titleLabel.font = .systemFont(ofSize: 26, weight: .bold)
        statusLabel.font = .systemFont(ofSize: 15)
        domainsLabel.font = .systemFont(ofSize: 13)
        domainsLabel.textColor = .secondaryLabelColor
        domainsLabel.maximumNumberOfLines = 3
        domainsLabel.lineBreakMode = .byWordWrapping

        let connectBtn = NSButton(title: "Через прокси", target: self, action: #selector(onConnect))
        connectBtn.keyEquivalent = "\r"
        connectBtn.bezelStyle = .rounded
        let blockBtn = NSButton(title: "Заблокировать", target: self, action: #selector(onBlock))
        let row1 = NSStackView(views: [connectBtn, blockBtn])
        row1.spacing = 12
        row1.distribution = .fillEqually

        let settingsBtn = NSButton(title: "Прокси", target: self, action: #selector(onSettings))
        let verifyBtn = NSButton(title: "Проверить IP", target: self, action: #selector(onVerify))
        let moreBtn = NSPopUpButton()
        moreBtn.pullsDown = true
        let moreMenu = NSMenu()
        let header = NSMenuItem(title: "Ещё", action: nil, keyEquivalent: "")
        header.isEnabled = false
        moreMenu.addItem(header)
        for (title, sel) in [
            ("Импорт списка", #selector(onImport)),
            ("Обновить список", #selector(onRefresh)),
            ("Диагностика", #selector(onDiagnose)),
        ] as [(String, Selector)] {
            let item = NSMenuItem(title: title, action: sel, keyEquivalent: "")
            item.target = self
            moreMenu.addItem(item)
        }
        moreBtn.menu = moreMenu
        let row2 = NSStackView(views: [settingsBtn, verifyBtn, moreBtn])
        row2.spacing = 12
        row2.distribution = .fillEqually

        let stack = NSStackView(views: [titleLabel, statusLabel, domainsLabel, row1, row2])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(stack)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 22),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -22),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
            row1.widthAnchor.constraint(equalTo: stack.widthAnchor),
            row2.widthAnchor.constraint(equalTo: stack.widthAnchor),
            domainsLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
    }

    // MARK: - actions

    @objc private func onConnect() { Task { await model.command("connect") } }
    @objc private func onBlock() { Task { await model.command("block") } }
    @objc private func onVerify() { Task { await model.command("verify", timeout: 30) } }
    @objc private func onRefresh() { Task { await model.command("refresh") } }

    @objc private func onSettings() {
        if settingsWindow == nil {
            settingsWindow = SettingsWindowController(model: model)
        }
        settingsWindow?.showWindow(nil)
        settingsWindow?.window?.orderFrontRegardless()
        settingsWindow?.reload()
    }

    @objc private func onDiagnose() {
        Task {
            let res = await model.command("diagnose", timeout: 30)
            if res["ok"] as? Bool == true, let report = res["report"] as? String {
                diagnoseWindow = DiagnoseWindowController(text: report)
                diagnoseWindow?.showWindow(nil)
            }
        }
    }

    @objc private func onImport() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [UTType.json]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task { await importPolicy(url) }
    }

    private func importPolicy(_ url: URL) async {
        do {
            let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
            if let size = attrs[.size] as? Int, size > 65536 {
                model.onAlert?("SelectiveTunnel", "Policy is too large.")
                return
            }
            let data = try Data(contentsOf: url)
            let json = try JSONSerialization.jsonObject(with: data)
            await model.command("import_policy", extra: ["policy": json])
        } catch {
            model.onAlert?("SelectiveTunnel", "Cannot read policy file.")
        }
    }
}
