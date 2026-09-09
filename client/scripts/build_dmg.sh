#!/usr/bin/env bash
set -euo pipefail

# build_dmg.sh — сборка дистрибутива Ligament 2FA Authenticator в формате macOS DMG
# Поддерживает как стандартную утилиту macOS hdiutil, так и create-dmg (если установлена).

APP_NAME="Ligament 2FA"
BUNDLE_NAME="Ligament 2FA.app"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${CLIENT_DIR}/build/macos/Build/Products/Release"
OUTPUT_DIR="${CLIENT_DIR}/dist"
DMG_NAME="Ligament-2FA-macOS.dmg"
FINAL_DMG="${OUTPUT_DIR}/${DMG_NAME}"

echo "========================================================"
echo " Сборка macOS DMG пакета: ${APP_NAME}"
echo "========================================================"

mkdir -p "${OUTPUT_DIR}"

# 1. Проверяем наличие скомпилированного .app бандла
APP_PATH="${BUILD_DIR}/${BUNDLE_NAME}"

if [[ ! -d "${APP_PATH}" ]]; then
  echo "--> .app бандл не найден в ${APP_PATH}"
  if command -v flutter &> /dev/null; then
    echo "--> Запуск компиляции Flutter macOS Release..."
    (cd "${CLIENT_DIR}" && flutter build macos --release)
  else
    echo "ОШИБКА: Flutter SDK не найден в PATH. Скомпилируйте приложение командой:"
    echo "  cd client && flutter build macos --release"
    exit 1
  fi
fi

if [[ ! -d "${APP_PATH}" ]]; then
  echo "ОШИБКА: Не удалось найти бандл ${APP_PATH} после сборки."
  exit 1
fi

echo "--> Найден бандл приложения: ${APP_PATH}"

# 2. Подготовка каталога staging
STAGING_DIR="$(mktemp -d -t ligament_dmg_XXXXXX)"
trap 'rm -rf "${STAGING_DIR}"' EXIT

echo "--> Подготовка staging директории: ${STAGING_DIR}"
cp -R "${APP_PATH}" "${STAGING_DIR}/"

# Создаем символическую ссылку на /Applications для удобной установки Drag & Drop
ln -s /Applications "${STAGING_DIR}/Applications"

# Удаляем предыдущий DMG, если существовал
rm -f "${FINAL_DMG}"

# 3. Сборка DMG
if command -v create-dmg &> /dev/null; then
  echo "--> Сборка через утилиту create-dmg (с оформлением окна)..."
  create-dmg \
    --volname "${APP_NAME}" \
    --window-pos 200 120 \
    --window-size 600 400 \
    --icon-size 100 \
    --icon "${BUNDLE_NAME}" 140 180 \
    --app-drop-link 460 180 \
    --hide-extension "${BUNDLE_NAME}" \
    --no-internet-enable \
    "${FINAL_DMG}" \
    "${STAGING_DIR}" || {
      echo "--> Предупреждение: create-dmg завершился с кодом ошибки, откат на hdiutil..."
      rm -f "${FINAL_DMG}"
      hdiutil create -volname "${APP_NAME}" -srcfolder "${STAGING_DIR}" -ov -format UDZO "${FINAL_DMG}"
    }
else
  echo "--> Сборка через нативную утилиту macOS hdiutil (формат UDZO сжатый)..."
  hdiutil create \
    -volname "${APP_NAME}" \
    -srcfolder "${STAGING_DIR}" \
    -ov \
    -format UDZO \
    "${FINAL_DMG}"
fi

# 4. Проверка и вывод результата
if [[ -f "${FINAL_DMG}" ]]; then
  DMG_SIZE="$(du -h "${FINAL_DMG}" | awk '{print $1}')"
  echo "========================================================"
  echo " УСПЕШНО СОБРАН DMG ДИСТРИБУТИВ:"
  echo " Файл:    ${FINAL_DMG}"
  echo " Размер:  ${DMG_SIZE}"
  echo "========================================================"
  echo "Установка пользователем: дважды кликнуть ${DMG_NAME} и перетащить"
  echo "${APP_NAME} в папку Программы (Applications)."
else
  echo "ОШИБКА: DMG файл не был создан."
  exit 1
fi
