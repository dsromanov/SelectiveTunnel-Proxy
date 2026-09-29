#!/bin/bash
# Установка SelectiveTunnel на macOS arm64.
# Запуск из корня репозитория:  sudo bash macos/scripts/install.sh
set -euo pipefail
cd "$(dirname "$0")/.."

DATA="/Library/Application Support/SelectiveTunnel"
LOGS="/Library/Logs/SelectiveTunnel"
PLIST="/Library/LaunchDaemons/com.selectivetunnel.daemon.plist"
LABEL="com.selectivetunnel.daemon"
SB_VER="1.14.0"
SB_TAR="sing-box-${SB_VER}-darwin-arm64.tar.gz"
SB_URL="https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/${SB_TAR}"
SB_SHA="a150c94012ff768b7261939cd236b9c8554127f45137230295d23a5660225cc9"

if [[ $EUID -ne 0 ]]; then
    echo "Запустите от root: sudo bash macos/scripts/install.sh" >&2
    exit 1
fi
if [[ "$(uname -m)" != "arm64" ]]; then
    echo "Поддерживается только Apple Silicon (arm64)." >&2
    exit 1
fi

# Сборка — от имени вызвавшего пользователя, чтобы не мусорить root-артефактами.
if [[ ! -d "dist/SelectiveTunnel.app" || ! -x "dist/selectivetunnel-daemon" ]]; then
    echo "==> build"
    if [[ -n "${SUDO_USER:-}" ]]; then
        sudo -u "$SUDO_USER" bash scripts/build.sh
    else
        bash scripts/build.sh
    fi
fi

echo "==> install files"
install -d -m 755 -o root -g wheel "$DATA" "$DATA/bin" "$DATA/run" "$LOGS"
install -m 755 -o root -g wheel dist/selectivetunnel-daemon "$DATA/bin/selectivetunnel-daemon"

if [[ ! -x "$DATA/bin/sing-box" ]]; then
    echo "==> sing-box $SB_VER (darwin-arm64)"
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    curl -fsSL --retry 3 -o "$TMP/$SB_TAR" "$SB_URL"
    echo "$SB_SHA  $TMP/$SB_TAR" | shasum -a 256 -c - >/dev/null
    tar -xzf "$TMP/$SB_TAR" -C "$TMP" "sing-box-${SB_VER}-darwin-arm64/sing-box"
    install -m 755 -o root -g wheel "$TMP/sing-box-${SB_VER}-darwin-arm64/sing-box" "$DATA/bin/sing-box"
fi

if [[ ! -f "$DATA/policy.json" ]]; then
    install -m 644 -o root -g wheel ../policy/domains.json "$DATA/policy.json"
fi
if [[ ! -f "$DATA/desired.json" ]]; then
    printf '{"mode":"blocked"}' > "$DATA/desired.json"
    chmod 644 "$DATA/desired.json"
fi

# Проверка портов (аналог AssertPortsFree на Windows); свой sing-box не считаем.
if /usr/sbin/lsof -nP -iUDP@127.0.0.53:53 2>/dev/null | grep -v sing-box | grep -q . || \
   /usr/sbin/lsof -nP -iTCP@127.0.0.53:53 -sTCP:LISTEN 2>/dev/null | grep -v sing-box | grep -q .; then
    echo "warning: порт 53 на 127.0.0.53 занят — локальный DNS-софт надо перенастроить." >&2
fi
if /usr/sbin/lsof -nP -iTCP@127.0.0.1:17891 -sTCP:LISTEN 2>/dev/null | grep -v sing-box | grep -q .; then
    echo "warning: диагностический порт 17891 занят." >&2
fi

echo "==> app"
rsync -a --delete "dist/SelectiveTunnel.app" /Applications/

echo "==> launchd"
install -m 644 -o root -g wheel "Resources/com.selectivetunnel.daemon.plist" "$PLIST"
# Файлы из скачанного архива имеют xattr com.apple.quarantine — launchd отказывает
# такому демону (error 155 "quarantined program"). Снимаем карантин со всего.
xattr -c "$PLIST" 2>/dev/null || true
xattr -dr com.apple.quarantine "$DATA" 2>/dev/null || true
xattr -dr com.apple.quarantine "/Applications/SelectiveTunnel.app" 2>/dev/null || true
plutil -lint "$PLIST"
launchctl bootout "system/$LABEL" 2>/dev/null || true
if ! launchctl bootstrap system "$PLIST"; then
    launchctl enable "system/$LABEL" 2>/dev/null || true
    launchctl bootstrap system "$PLIST"
fi
sleep 1
if ! launchctl print "system/$LABEL" >/dev/null 2>&1; then
    echo "error: демон не загрузился. Диагностика:" >&2
    echo "  sudo launchctl print system/$LABEL" >&2
    echo "  sudo \"$DATA/bin/selectivetunnel-daemon\"" >&2
    exit 1
fi
if [[ ! -S "$DATA/run/control.sock" ]]; then
    echo "warning: сокет демона не появился — смотрите $LOGS/daemon.err.log" >&2
fi

echo ""
echo "Готово. Откройте /Applications/SelectiveTunnel.app:"
echo "  1) «Прокси» — введите логин и пароль прокси, «Сохранить»."
echo "  2) «Через прокси»."
echo "  3) «Проверить IP»."
