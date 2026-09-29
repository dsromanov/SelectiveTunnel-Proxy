#!/bin/bash
# Удаление SelectiveTunnel с macOS.
# Запуск:  sudo bash macos/scripts/uninstall.sh
set -uo pipefail

DATA="/Library/Application Support/SelectiveTunnel"
LOGS="/Library/Logs/SelectiveTunnel"
PLIST="/Library/LaunchDaemons/com.selectivetunnel.daemon.plist"
LABEL="com.selectivetunnel.daemon"
APP="/Applications/SelectiveTunnel.app"

if [[ $EUID -ne 0 ]]; then
    echo "Запустите от root: sudo bash macos/scripts/uninstall.sh" >&2
    exit 1
fi

echo "==> stop daemon"
launchctl bootout "system/$LABEL" 2>/dev/null || launchctl unload "$PLIST" 2>/dev/null || true
rm -f "$PLIST"
pkill -f "$DATA/bin/sing-box" 2>/dev/null || true

echo "==> remove loopback alias"
/sbin/ifconfig lo0 -alias 127.0.0.53 2>/dev/null || true

echo "==> remove DNS resolvers"
# Собираем домены из имён файлов, которыми управлял демон (маркер в первой строке).
domains=()
if [[ -d /etc/resolver ]]; then
    for f in /etc/resolver/*; do
        [[ -f "$f" ]] || continue
        if head -1 "$f" | grep -q "^# SelectiveTunnel"; then
            domains+=("$(basename "$f")")
            rm -f "$f"
        fi
    done
fi

echo "==> restore system proxy bypass"
# Убираем наши домены из исключений системного прокси, если демон их туда добавлял.
if [[ ${#domains[@]} -gt 0 ]]; then
    while IFS= read -r service; do
        [[ "$service" == \** || -z "$service" || "$service" == An\ asterisk* ]] && continue
        enabled=0
        for opt in -getwebproxy -getsecurewebproxy -getsocksfirewallproxy; do
            if /usr/sbin/networksetup "$opt" "$service" 2>/dev/null | grep -q "Enabled: Yes"; then
                enabled=1; break
            fi
        done
        [[ $enabled -eq 1 ]] || continue
        kept=()
        while IFS= read -r entry; do
            skip=0
            for d in "${domains[@]}"; do
                [[ "$entry" == "$d" || "$entry" == "*.$d" ]] && { skip=1; break; }
            done
            [[ $skip -eq 0 && -n "$entry" && "$entry" != *"aren't any bypass"* ]] && kept+=("$entry")
        done < <(/usr/sbin/networksetup -getproxybypassdomains "$service" 2>/dev/null)
        if [[ ${#kept[@]} -gt 0 ]]; then
            /usr/sbin/networksetup -setproxybypassdomains "$service" "${kept[@]}" 2>/dev/null || true
        else
            /usr/sbin/networksetup -setproxybypassdomains "$service" "" 2>/dev/null || true
        fi
    done < <(/usr/sbin/networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
fi

echo "==> remove files"
rm -rf "$DATA" "$LOGS"
rm -rf "$APP"

/usr/bin/dscacheutil -flushcache
/usr/bin/killall -HUP mDNSResponder 2>/dev/null || true

echo "Готово. SelectiveTunnel удалён."
