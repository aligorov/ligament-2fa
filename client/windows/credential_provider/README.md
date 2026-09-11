# Ligament 2FA Windows Credential Provider

Нативный модуль Windows Credential Provider (C++ DLL) для двухфакторной аутентификации RDP и локального входа Windows с поддержкой **FIDO2 / YubiKey (через Win32 WebAuthn API и RDP WebAuthn Redirection)**, **Telegram Push**, **десктопного приложения Ligament** и **TOTP**.

## Возможности

1. **RDP WebAuthn Redirection для FIDO2 / YubiKey:**
   - Поддерживает физические ключи YubiKey 5 Series, Security Key NFC, Feitian, SoloKeys.
   - Запрос на подтверждение пробрасывается на монитор клиента через виртуальный канал RDP (`redirectwebauthn:i:1`).
   - Ключ начинает мигать на локальном компьютере сотрудника до физического касания пальцем.
2. **Out-of-band Push (Telegram / Ligament Authenticator):**
   - При нажатии «Войти» провайдер отправляет имя пользователя и пароль на `/api/v1/auth/start` (сервер проверяет пароль и сам выбирает канал доставки — Telegram или приложение Ligament).
   - Ожидание решения происходит в фоновом потоке рабочего процесса через `/api/v1/auth/poll` (статусы `approved` / `denied` / `pending` / `expired`); экран входа Windows не блокируется.
   - Отказ, истечение срока или таймаут отображаются сообщением на тайле; повторное нажатие «Войти» отправляет новый Push-запрос.
3. **Резервные коды и OTP:**
   - Ввод 6-значных кодов TOTP (Google Authenticator) или прямое касание YubiKey в режиме YubiKey OTP (Modhex 44 символа).
4. **Аварийный обход (Break-Glass Accounts):**
   - Белый список локальных администраторов (`BypassAccounts`), освобожденных от 2FA на случай аварии.
   - Политика Fail-Close / Fail-Open при сетевых сбоях.

## Сборка (Windows, Visual Studio 2022)

```cmd
cd client\windows\credential_provider
mkdir build && cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
cmake --build . --config Release
```

Готовая библиотека: `build\Release\LigamentCredentialProvider.dll`.

Важно: исходники сохранены в UTF-8 (с BOM), а CMake автоматически добавляет флаг MSVC `/utf-8`. Без него русские строки тайла компилируются по системной кодовой странице машины сборки (например, CP1252 на en-US CI-раннере) и в DLL попадают кракозябрами. При сборке другими тулчеймами убедитесь, что исходники читаются как UTF-8.

## Ручная регистрация и тестирование

Для регистрации в тестовой системе (от имени Администратора):

```cmd
regsvr32.exe build\Release\LigamentCredentialProvider.dll
```

Для удаления регистрации:

```cmd
regsvr32.exe /u build\Release\LigamentCredentialProvider.dll
```

## Конфигурация в реестре

Модуль читает настройки из ветки GPO `HKLM\SOFTWARE\Policies\Ligament\2FA` (или локальной `HKLM\SOFTWARE\Ligament\2FA`):

| Параметр | Тип | По умолчанию | Описание |
|---|---|---|---|
| `ServerURL` | `REG_SZ` | `https://twofa.corp.local` | Базовый URL сервера Ligament |
| `RDP2FAEnabled` | `REG_DWORD` | `1` | Включить 2FA для RDP-подключений |
| `Console2FAEnabled` | `REG_DWORD` | `0` | Включить 2FA для локального входа (Console) |
| `FIDO2Enabled` | `REG_DWORD` | `1` | Разрешить вход по аппаратным ключам FIDO2/YubiKey |
| `PushTimeoutSeconds` | `REG_DWORD` | `45` | Таймаут ожидания Push в секундах |
| `FailClose` | `REG_DWORD` | `1` | 1 = Блокировать вход при недоступности сервера 2FA; 0 = Пропускать ВСЕХ пользователей при недоступности сервера (не только администраторов) |
| `BypassAccounts` | `REG_SZ` | `""` | Список логинов через запятую (например: `Administrator,admin`); записи матчатся по полному имени и по локальной части UPN (`administrator@corp.local` → `administrator`) |
| `AllowSelfSigned` | `REG_DWORD` | `0` | 1 = Доверять самоподписанному сертификату сервера: игнорируется только неизвестый издатель (CA); имя сертификата (CN/SAN) и срок действия проверяются всегда |

## Быстрая настройка реестра

В поставке (ZIP) лежит `ligament-cp-settings.reg`: открой в Блокноте, впиши
свой `ServerURL`, сохрани и запусти двойным кликом (права администратора).
Файл создаёт ветку `HKLM\SOFTWARE\Policies\Ligament\2FA` со всеми параметрами
(ServerURL, FailClose, RDP2FAEnabled, Console2FAEnabled, FIDO2Enabled,
PushTimeoutSeconds; закомментированы AllowSelfSigned и BypassAccounts).
Без заданного ServerURL и при FailClose=1 вход по RDP заблокирован.
