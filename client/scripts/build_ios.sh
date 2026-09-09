#!/usr/bin/env bash
set -euo pipefail

# build_ios.sh — сборка iOS Runner.app и упаковка в Ligament-2FA.ipa
# Поддерживает локальную сборку на macOS с Xcode без обязательного Apple Team ID (--no-codesign)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${CLIENT_DIR}/dist"
OUTPUT_IPA="${DIST_DIR}/Ligament-2FA.ipa"
APP_SRC="${CLIENT_DIR}/build/ios/iphoneos/Runner.app"

mkdir -p "${DIST_DIR}"

echo "========================================================"
echo " Сборка iOS пакета: Ligament 2FA (.ipa)"
echo "========================================================"

if [[ ! -d "${APP_SRC}" ]]; then
  echo "--> Компиляция Flutter iOS Release (device)..."
  (cd "${CLIENT_DIR}" && flutter build ios --release --no-codesign)
fi

if [[ ! -d "${APP_SRC}" ]]; then
  echo "ОШИБКА: Бандл ${APP_SRC} не найден после сборки."
  exit 1
fi

echo "--> Упаковка Runner.app в IPA дистрибутив..."
TMP_DIR="$(mktemp -d -t ligament_ipa_XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/Payload"
cp -R "${APP_SRC}" "${TMP_DIR}/Payload/"

(cd "${TMP_DIR}" && zip -qry "${OUTPUT_IPA}" Payload)

echo ""
echo "========================================================"
echo " УСПЕШНО СОБРАН IOS IPA ДИСТРИБУТИВ:"
echo " Файл:   ${OUTPUT_IPA}"
echo " Размер: $(du -sh "${OUTPUT_IPA}" | cut -f1)"
echo "========================================================"
echo "Способы установки на iPhone / iPad:"
echo " 1. Через Xcode: Window -> Devices and Simulators -> Installed Apps (+)"
echo " 2. Через Apple Configurator 2"
echo " 3. Через корпоративный MDM / AltStore / Sideloadly / TrollStore"

chmod +x "${OUTPUT_IPA}" 2>/dev/null || true
