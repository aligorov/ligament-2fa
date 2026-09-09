#!/usr/bin/env bash
set -euo pipefail

# build_apk.sh — сборка Android APK дистрибутива Ligament 2FA
# Поддерживает локальную сборку (при наличии Android SDK) и сборку через Docker.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${CLIENT_DIR}/dist"
OUTPUT_APK="${DIST_DIR}/Ligament-2FA.apk"

mkdir -p "${DIST_DIR}"

echo "========================================================"
echo " Сборка Android APK пакета: Ligament 2FA"
echo "========================================================"

build_locally() {
  echo "--> Локальная сборка Flutter Android Release..."
  (cd "${CLIENT_DIR}" && flutter build apk --release)
  
  SRC_APK="${CLIENT_DIR}/build/app/outputs/flutter-apk/app-release.apk"
  if [[ -f "${SRC_APK}" ]]; then
    cp "${SRC_APK}" "${OUTPUT_APK}"
    echo ""
    echo "========================================================"
    echo " УСПЕШНО СОБРАН ANDROID APK ДИСТРИБУТИВ:"
    echo " Файл:   ${OUTPUT_APK}"
    echo " Размер: $(du -sh "${OUTPUT_APK}" | cut -f1)"
    echo "========================================================"
    return 0
  else
    echo "ОШИБКА: Файл ${SRC_APK} не найден после сборки."
    return 1
  fi
}

build_in_docker() {
  echo "--> Запуск сборки Android APK внутри контейнера Docker (Android SDK + OpenJDK)..."
  docker run --rm \
    -v "${CLIENT_DIR}":/workspace \
    -w /workspace \
    ghcr.io/cirruslabs/flutter:latest \
    bash -c "flutter config --no-analytics && flutter pub get && flutter build apk --release"

  SRC_APK="${CLIENT_DIR}/build/app/outputs/flutter-apk/app-release.apk"
  if [[ -f "${SRC_APK}" ]]; then
    cp "${SRC_APK}" "${OUTPUT_APK}"
    echo ""
    echo "========================================================"
    echo " УСПЕШНО СОБРАН ANDROID APK ДИСТРИБУТИВ:"
    echo " Файл:   ${OUTPUT_APK}"
    echo " Размер: $(du -sh "${OUTPUT_APK}" | cut -f1)"
    echo "========================================================"
    return 0
  else
    echo "ОШИБКА: Не удалось собрать APK в контейнере."
    return 1
  fi
}

# 1. Проверяем локальные Java и Android SDK
CAN_BUILD_LOCAL=false
if command -v flutter &> /dev/null && command -v java &> /dev/null; then
  if java -version &> /dev/null; then
    CAN_BUILD_LOCAL=true
  fi
fi

if [[ "${CAN_BUILD_LOCAL}" == "true" ]]; then
  build_locally
elif command -v docker &> /dev/null && docker info &> /dev/null; then
  echo "--> Локальный Java/Android SDK не настроен, переключение на Docker сборку..."
  build_in_docker
else
  echo ""
  echo "ОШИБКА: Не найдены компоненты для сборки Android APK."
  echo "Для локальной сборки установите OpenJDK 17 и Android SDK:"
  echo "  macOS: brew install openjdk@17 && flutter doctor"
  echo "Либо запустите Docker Desktop для автономной сборки в контейнере."
  exit 1
fi
