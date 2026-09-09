# Ligament 2FA Authenticator — Кроссплатформенный клиент (Windows, macOS, Android, iOS)

Клиентское приложение корпоративной системы двухфакторной аутентификации **Ligament 2FA**.
Разработано на Flutter / Dart для Windows Desktop, macOS Desktop, Android и iOS с единой кодовой базой и нативной интеграцией с ОС.

## Ключевые возможности

1. **Мгновенные Push-подтверждения (2FA Approval)**:
   - При входящем запросе авторизации (RADIUS VPN, OIDC SSO, Web) окно приложения автоматически всплывает поверх всех окон (`AlwaysOnTop`), перехватывает фокус, мигает иконкой на панели задач Windows (`FlashTaskbar`) и воспроизводит звуковой сигнал.
   - На macOS поддерживается работа в фоновом режиме (меню-бар / Dock), автоматический переход на передний план и подтверждение через Touch ID.
   - На мобильных устройствах используются приоритетные уведомления (Android Full-Screen Intent и iOS Time-Sensitive Alerts).
2. **Защита от Push-утомления (Anti-Fatigue Number Matching)**:
   - На экране логина отображается случайное 2-значное число (например `42`). В приложении пользователю необходимо выбрать совпадающее число из вариантов, исключая случайные или обманные подтверждения.
3. **Аудит безопасности и Телеметрия (Device Posture)**:
   - **Windows**: проверка статуса шифрования BitLocker (`manage-bde`), антивируса Windows Defender (`Get-MpComputerStatus`), сетевого экрана Windows Firewall (`netsh`).
   - **macOS**: проверка шифрования FileVault (`fdesetup`), антивирусной подсистемы Gatekeeper (`spctl`), сетевого экрана macOS Firewall (`socketfilterfw`), биометрии Touch ID.
   - **Android / iOS**: детекция Root / Jailbreak и целостности ОС.
   - Задержка доставки push-канала (SLA) и привязка к сессии сотрудника.
   - Отображение статуса в личном кабинете пользователя (`/me/devices`) и панели администратора (`/admin/users`).
4. **Централизованное корпоративное управление (GPO & macOS MDM)**:
   - **Windows GPO**: шаблоны в `deploy/gpo/` (`Ligament2FA.admx`, `ru-RU/Ligament2FA.adml`, `en-US/Ligament2FA.adml`).
   - **macOS MDM**: профиль конфигурации в `deploy/macos/com.ligament.twofa.mobileconfig` для Jamf Pro, Microsoft Intune, Kandji, SimpleMDM.
   - Задает принудительный URL сервера (пользователь не может изменить), запрещает закрытие приложения (`AllowExit=0`), принуждает биометрию (Windows Hello / Touch ID) и блокирует доступ при выключенном шифровании диска (BitLocker / FileVault).
5. **Каталог корпоративных OIDC-приложений (SSO Launchpad)**:
   - Пользователю доступен персональный список разрешенных сервисов компании для перехода в один клик.
6. **Журнал входов и экстренный сброс**:
   - Список недавних попыток авторизации с IP-адресами и статусом. Кнопка **«Это были не вы?»** для мгновенного отзыва сессии.

---

## Сборка приложения

### Требования
- Flutter SDK 3.2.0+
- Для Windows: Visual Studio 2022 с компонентом «Разработка классических приложений на C++».
- Для macOS: macOS с установленным Xcode 15+, утилита `hdiutil` (встроена) или `create-dmg`.
- Для Android: Android Studio / Android SDK.
- Для iOS: macOS с установленным Xcode 15+.

### Команды сборки

#### 1. Сборка для macOS (DMG)
Сборка выполняется на macOS (Intel или Apple Silicon):
```bash
cd client
flutter pub get
flutter build macos --release
./scripts/build_dmg.sh
# Готовый DMG дистрибутив: client/dist/Ligament-2FA-macOS.dmg
```

#### 2. Сборка для Android (APK / AAB)

**Вариант А: Локальная сборка (если установлены OpenJDK 17 и Android SDK)**
1. Проверьте готовность окружения:
   ```bash
   flutter doctor
   ```
2. Скомпилируйте релизный APK или универсальный скрипт:
   ```bash
   cd client
   ./scripts/build_apk.sh
   # Либо напрямую командой Flutter:
   flutter build apk --release
   # Или раздельные легковесные APK под каждую архитектуру (ARM64, ARMv7, x86_64):
   flutter build apk --split-per-abi --release
   ```
   Готовые файлы:
   - `client/dist/Ligament-2FA.apk`
   - `client/build/app/outputs/flutter-apk/app-release.apk`

**Вариант Б: Автономная сборка в Docker (без установки Android Studio на компьютер)**
Если на компьютере установлен Docker, запустите скрипт:
```bash
cd client
./scripts/build_apk.sh
```
Скрипт автоматически скачает официальный образ с Flutter и Android SDK, скомпилирует приложение и сохранит `client/dist/Ligament-2FA.apk`.

#### 3. Сборка для Windows (MSI Installer для GPO / Active Directory)
Сборка выполняется на рабочей станции Windows:
1. **Необходимые компоненты**:
   - **Flutter SDK**: [flutter.dev](https://docs.flutter.dev/get-started/install/windows)
   - **Visual Studio 2022** (компонент «Разработка классических приложений на C++»)
   - **WiX Toolset** (утилита для создания MSI):
     ```powershell
     winget install WiX.Toolset
     ```
2. **Автоматическая сборка MSI**:
   Запустите PowerShell-скрипт из каталога `client`:
   ```powershell
   cd client
   .\scripts\build_msi.ps1
   ```
   Скрипт автоматически:
   - Скомпилирует релизные бинарники: `flutter build windows --release`.
   - Соберёт компоненты через WiX Heat.
   - Слинкует MSI-установщик: `client\dist\Ligament-2FA-Windows-x64.msi`.
3. **Тихая установка через Active Directory GPO / SCCM / Intune**:
   ```cmd
   msiexec /i Ligament-2FA-Windows-x64.msi /qn
   ```

---

## Развертывание корпоративных политик

### 1. Windows Active Directory (GPO)
1. Скопируйте `deploy/gpo/Ligament2FA.admx` в `C:\Windows\PolicyDefinitions\` (или Central Store: `\\domain.corp\sysvol\domain.corp\Policies\PolicyDefinitions\`).
2. Скопируйте `deploy/gpo/ru-RU/Ligament2FA.adml` в папку `ru-RU\` и `en-US/Ligament2FA.adml` в `en-US\`.
3. Откройте `gpedit.msc` или Консоль управления групповыми политиками (`gpmc.msc`).
4. Перейдите в: **Конфигурация компьютера (или пользователя) -> Административные шаблоны -> Ligament 2FA Authenticator**.

### 2. Apple macOS MDM (Jamf, Intune, Kandji)
1. Импортируйте профиль конфигурации `deploy/macos/com.ligament.twofa.mobileconfig` в вашу систему управления парком Mac (MDM).
2. Для локального тестирования на рабочем месте:
   ```bash
   sudo /usr/bin/profiles -I -F deploy/macos/com.ligament.twofa.mobileconfig
   ```
3. Все политики (`ServerURL`, `AllowExit`, `RequireTouchID`, `RequireFileVault`, `RequireFirewall`) будут автоматически применены и заблокированы от ручного изменения пользователем.
