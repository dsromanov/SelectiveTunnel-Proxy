import AppKit
import STCore

// Диалог настроек прокси — порт settings.cpp. Пустой пароль = оставить текущий.

@MainActor
final class SettingsWindowController: NSWindowController {
    private let model: StatusModel
    private var profile = Profile()

    private let protoPopup = NSPopUpButton()
    private let ipField = NSTextField()
    private let portField = NSTextField()
    private let userField = NSTextField()
    private let passField = NSSecureTextField()
    private let expectedField = NSTextField()
    private let tlsField = NSTextField()
    private let errorLabel = NSTextField(wrappingLabelWithString: "")
    private let spinner = NSProgressIndicator()

    init(model: StatusModel) {
        self.model = model
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 586, height: 480),
            styleMask: [.titled, .closable],
            backing: .buffered, defer: false)
        window.title = "Прокси"
        window.center()
        super.init(window: window)
        build()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError() }

    private func build() {
        guard let content = window?.contentView else { return }

        protoPopup.addItems(withTitles: ["socks5", "http", "https"])

        func row(_ title: String, _ field: NSView) -> [NSView] {
            let label = NSTextField(labelWithString: title)
            label.alignment = .right
            label.setContentHuggingPriority(.required, for: .horizontal)
            label.widthAnchor.constraint(equalToConstant: 230).isActive = true
            field.widthAnchor.constraint(equalToConstant: 280).isActive = true
            return [label, field]
        }

        let grid = NSGridView(views: [
            row("Протокол", protoPopup),
            row("IP прокси", ipField),
            row("Порт", portField),
            row("Логин прокси", userField),
            row("Пароль прокси", passField),
            row("Ожидаемый внешний IP", expectedField),
            row("Имя в TLS-сертификате", tlsField),
        ])
        grid.rowSpacing = 10
        grid.columnSpacing = 12

        let note = NSTextField(wrappingLabelWithString: "Данные самого прокси. Пустой пароль — оставить текущий.")
        note.font = .systemFont(ofSize: 12)
        note.textColor = .secondaryLabelColor
        note.maximumNumberOfLines = 2

        errorLabel.textColor = .systemRed
        errorLabel.font = .systemFont(ofSize: 12)
        errorLabel.maximumNumberOfLines = 2

        spinner.style = .spinning
        spinner.controlSize = .small
        spinner.isDisplayedWhenStopped = false

        let saveBtn = NSButton(title: "Сохранить", target: self, action: #selector(onSave))
        saveBtn.keyEquivalent = "\r"
        saveBtn.bezelStyle = .rounded
        let cancelBtn = NSButton(title: "Отмена", target: self, action: #selector(onCancel))
        let buttons = NSStackView(views: [saveBtn, cancelBtn])
        buttons.spacing = 12
        buttons.alignment = .centerY

        let bottom = NSStackView(views: [spinner, NSView(), buttons])
        bottom.orientation = .horizontal
        bottom.distribution = .fill

        let stack = NSStackView(views: [grid, note, errorLabel, bottom])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(stack)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -20),
            note.widthAnchor.constraint(equalTo: stack.widthAnchor),
            errorLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            bottom.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
    }

    /// Перезагрузка формы сохранённым профилем (запрос к демону).
    func reload() {
        spinner.startAnimation(nil)
        Task {
            let res = await model.command("get_profile")
            if res["ok"] as? Bool == true, let obj = res["profile"],
               let data = try? JSONSerialization.data(withJSONObject: obj),
               let saved = try? JSONDecoder().decode(Profile.self, from: data) {
                profile = saved
            }
            protoPopup.selectItem(withTitle: profile.protocol_)
            ipField.stringValue = profile.serverIp
            portField.stringValue = String(profile.serverPort)
            userField.stringValue = profile.username
            passField.stringValue = ""
            expectedField.stringValue = profile.expectedExitIp
            tlsField.stringValue = profile.tlsServerName
            errorLabel.stringValue = ""
            spinner.stopAnimation(nil)
        }
    }

    @objc private func onCancel() { close() }

    @objc private func onSave() {
        guard let port = Int(portField.stringValue), port > 0 else {
            errorLabel.stringValue = "Проверьте настройки"
            return
        }
        var candidate = profile
        candidate.protocol_ = protoPopup.selectedItem?.title ?? "socks5"
        candidate.serverIp = ipField.stringValue
        candidate.serverPort = port
        candidate.username = userField.stringValue
        candidate.password = passField.stringValue
        candidate.expectedExitIp = expectedField.stringValue
        candidate.tlsServerName = tlsField.stringValue
        do {
            try assertProfile(candidate)
        } catch let error as STError {
            if error.description.contains("password") && passField.stringValue.isEmpty {
                // Пустой пароль — демон подставит сохранённый и проверит там.
            } else {
                errorLabel.stringValue = error.description
                return
            }
        } catch {
            errorLabel.stringValue = "Проверьте настройки"
            return
        }
        errorLabel.stringValue = ""
        spinner.startAnimation(nil)
        Task {
            defer { spinner.stopAnimation(nil) }
            guard let data = try? JSONEncoder().encode(candidate),
                  let obj = try? JSONSerialization.jsonObject(with: data) else { return }
            let res = await model.command("save_profile", extra: ["profile": obj], timeout: 30)
            if res["ok"] as? Bool == true {
                close()
            }
        }
    }
}
