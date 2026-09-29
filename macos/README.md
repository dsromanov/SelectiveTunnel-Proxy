# SelectiveTunnel для macOS (Apple Silicon)

Порт Windows-клиента 2.0 на macOS. Та же идея: выбранные домены (ChatGPT/OpenAI/Figma — список в `policy/domains.json`) идут через один SOCKS5/HTTP/HTTPS-прокси, остальной трафик — напрямую. Движок — тот же sing-box 1.14.0, только на `utun` вместо Wintun.

## Что внутри

| Часть | Реализация |
|---|---|
| GUI | `SelectiveTunnel.app` — AppKit-окно + иконка в меню-баре (аналог трея) |
| Фоновая служба | `selectivetunnel-daemon` — LaunchDaemon `com.selectivetunnel.daemon` от root |
| IPC | Unix-сокет `/Library/Application Support/SelectiveTunnel/run/control.sock`, тот же JSON-протокол (`status`, `connect`, `block`, `refresh`, `verify`, `save_profile`, `import_policy`, плюс `get_profile`, `diagnose`) |
| DNS-политика | `/etc/resolver/<домен>` → `127.0.0.53` порт 53 (аналог NRPT на Windows) |
| TUN | sing-box `tun` inbound → `utun`, `auto_route` только для FakeIP-диапазонов |
| Конфиг движка | генерируется в памяти и подаётся в `sing-box run -c stdin` — логин/пароль в конфиг на диске не лежат |
| Профиль | `connection.json` с правами `0600` root в `/Library/Application Support/SelectiveTunnel` (вместо DPAPI) |

## Требования

- macOS 13 (Ventura) или новее, Apple Silicon (arm64)
- Xcode Command Line Tools: `xcode-select --install`

## Сборка и установка

```bash
cd macos
bash scripts/build.sh                    # собирает .app и демон в macos/dist/
sudo bash scripts/install.sh             # ставит демон, sing-box, политику и .app в /Applications
```

После установки откройте `/Applications/SelectiveTunnel.app`:

1. **«Прокси»** — введите логин и пароль прокси (IP `176.119.140.14`, порт SOCKS5 `14073` или HTTP `4073` уже подставлены), «Сохранить».
2. **«Через прокси»**.
3. **«Проверить IP»** — покажет egress через прокси и напрямую.

Кнопка **«Заблокировать»** глушит выбранные домены (DNS уходит на «мёртвый» `127.0.0.53`), остальной интернет не затрагивается.

## Удаление

```bash
sudo bash macos/scripts/uninstall.sh
```

Останавливает демон, снимает файлы `/etc/resolver`, чистит добавленные исключения системного прокси, удаляет данные и приложение.

## Файлы на системе

```
/Library/Application Support/SelectiveTunnel/
    bin/selectivetunnel-daemon   демон (root)
    bin/sing-box                 движок
    run/control.sock             IPC-сокет (0666)
    connection.json              профиль прокси (0600)
    policy.json                  список доменов
    desired.json                 режим: connected / blocked
    status.json                  состояние для GUI
    guards.json                  домены, для которых созданы /etc/resolver-файлы
/etc/resolver/<домен>            → nameserver 127.0.0.53, port 53
/Library/LaunchDaemons/com.selectivetunnel.daemon.plist
/Library/Logs/SelectiveTunnel/   логи демона
```

## Совместимость с Happ / другими VPN

- Клиент не ставит свой системный прокси и не заворачивает `0.0.0.0/0` — TUN-интерфейс маршрутизирует только FakeIP-подсети `100.82.0.0/16` и `fd71:5e1e:c710::/48`.
- Если Happ включил системный прокси, демон добавляет домены политики в bypass-список сетевых служб (`networksetup -setproxybypassdomains`), чтобы они шли в TUN.
- Если Happ в TUN-режиме перехватывает DNS — добавьте обход `openai.com` / `chatgpt.com` / `figma.com` в Happ, как и на Windows.

## Ограничения порта

- **`/etc/resolver` работает только для приложений, использующих системный резолвер.** Приложение с собственным DNS-клиентом/DoH может обойти его — тогда домен не попадёт в туннель.
- Системный DNS на `127.0.0.53:53` для прочих доменов не меняется — только перечисленные в политике.
- Подписанный фид политики (`policy_url` + RSA-подпись) поддерживается — проверка идёт через Security.framework.
- IPv4-only режим: создайте файл `/Library/Application Support/SelectiveTunnel/tun-ipv4-only.flag` и перезапустите демон (`sudo launchctl kickstart -k system/com.selectivetunnel.daemon`).

## Сборка без установки (отладка)

```bash
cd macos
swift build -c release --arch arm64      # бинарники в .build/arm64-apple-macosx/release/
```

Демон можно запустить вручную для отладки:

```bash
sudo .build/arm64-apple-macosx/release/SelectiveTunnelDaemon
```

(предварительно создав `/Library/Application Support/SelectiveTunnel` с `policy.json`.)
