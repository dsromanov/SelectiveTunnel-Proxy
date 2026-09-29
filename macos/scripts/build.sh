#!/bin/bash
# Сборка SelectiveTunnel для macOS arm64: SelectiveTunnel.app + selectivetunnel-daemon.
# Требуется Xcode CLT (xcode-select --install) на Apple Silicon.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "$(uname -m)" != "arm64" ]]; then
    echo "warning: this build targets Apple Silicon (arm64)" >&2
fi

echo "==> swift build -c release --arch arm64"
swift build -c release --arch arm64
BIN="$(swift build -c release --arch arm64 --show-bin-path)"

DIST="dist"
APP="$DIST/SelectiveTunnel.app"
mkdir -p "$DIST"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$BIN/SelectiveTunnel" "$APP/Contents/MacOS/SelectiveTunnel"
cp "Resources/Info.plist" "$APP/Contents/Info.plist"
cp "../policy/domains.json" "$APP/Contents/Resources/domains.json"
# ad-hoc подпись — достаточно для локального запуска на своём Mac.
codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || true

cp "$BIN/SelectiveTunnelDaemon" "$DIST/selectivetunnel-daemon"

echo "==> done"
echo "  $APP"
echo "  $DIST/selectivetunnel-daemon"
