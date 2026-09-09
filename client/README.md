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

```bash
cd client
flutter pub get

# 1. Сборка для Windows Desktop (x64)
flutter build windows --release

# 2. Сборка для macOS и упаковка в DMG
flutter build macos --release
./scripts/build_dmg.sh
# Готовый DMG дистрибутив: client/dist/Ligament-2FA-macOS.dmg

# 3. Сборка для Android APK / App Bundle
flutter build apk --release
flutter build appbundle --release

# 4. Сборка для iOS (IPA)
flutter build ipa --release
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
