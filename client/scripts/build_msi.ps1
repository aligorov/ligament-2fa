# build_msi.ps1 — Автоматическая сборка Windows MSI-пакета и RDP Credential Provider для Ligament 2FA
# Запуск в PowerShell:
#   .\scripts\build_msi.ps1
#
# Требования на Windows:
#   1. Flutter SDK: flutter doctor
#   2. CMake & MSVC (C++ Build Tools)
#   3. WiX Toolset: winget install WiX.Toolset (или https://wixtoolset.org)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ClientDir = Split-Path -Parent $ScriptDir
$BuildReleaseDir = "$ClientDir\build\windows\x64\runner\Release"
$DistDir = "$ClientDir\dist"
$OutputMsi = "$DistDir\Ligament-2FA-Windows-x64.msi"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " Сборка Windows MSI пакета и RDP 2FA: Ligament 2FA" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# 1. Сборка релизной версии Flutter для Windows
Set-Location $ClientDir
$env:CL = "$env:CL /D_SILENCE_EXPERIMENTAL_COROUTINE_DEPRECATION_WARNINGS"
Write-Host "`n[1/5] Компиляция Flutter Windows Release..." -ForegroundColor Yellow
flutter build windows --release

if (-not (Test-Path "$BuildReleaseDir\ligament_authenticator.exe")) {
    Write-Error "Ошибка: Бинарный файл $BuildReleaseDir\ligament_authenticator.exe не найден!"
}

# 2. Сборка Windows Credential Provider (RDP 2FA C++ DLL)
$CpDir = "$ClientDir\windows\credential_provider"
if (Test-Path "$CpDir\CMakeLists.txt") {
    Write-Host "`n[2/5] Компиляция Windows Credential Provider (RDP 2FA C++ DLL)..." -ForegroundColor Yellow
    cmake -B "$CpDir\build" -S "$CpDir" -A x64
    cmake --build "$CpDir\build" --config Release
    
    if (Test-Path "$CpDir\build\Release\LigamentCredentialProvider.dll") {
        Write-Host " Успешно скомпилирована библиотека: LigamentCredentialProvider.dll" -ForegroundColor Green
    } else {
        Write-Error "Ошибка: LigamentCredentialProvider.dll не скомпилировалась!"
    }
}

# 3. Создание каталога дистрибутивов и автономного RDP-пакета
if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir | Out-Null
}

if (Test-Path "$CpDir\build\Release\LigamentCredentialProvider.dll") {
    $RdpDistDir = [System.IO.Path]::GetTempPath() + "LigamentRdp_" + [System.Guid]::NewGuid().ToString("N")
    New-Item -ItemType Directory -Path $RdpDistDir | Out-Null
    Copy-Item "$CpDir\build\Release\LigamentCredentialProvider.dll" "$RdpDistDir\"
    if (Test-Path "$CpDir\README.md") {
        Copy-Item "$CpDir\README.md" "$RdpDistDir\"
    }
    if (Test-Path "$ClientDir\..\deploy\gpo") {
        New-Item -ItemType Directory -Path "$RdpDistDir\gpo" -Force | Out-Null
        Copy-Item "$ClientDir\..\deploy\gpo\*" "$RdpDistDir\gpo\" -Recurse -Force
    }
    
    $installBat = @"
@echo off
echo ========================================================
echo Installing Ligament 2FA Credential Provider for RDP...
echo ========================================================
copy /Y "%~dp0LigamentCredentialProvider.dll" "%SystemRoot%\System32\LigamentCredentialProvider.dll"
regsvr32.exe /s "%SystemRoot%\System32\LigamentCredentialProvider.dll"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEnableWebAuthn /t REG_DWORD /d 1 /f
echo [OK] Ligament Credential Provider installed and registered.
echo.
echo [!] IMPORTANT: the 2FA server URL is NOT configured yet. Set it before using RDP logon:
echo     reg add "HKLM\SOFTWARE\Policies\Ligament\2FA" /v ServerURL /t REG_SZ /d "https://your-2fa-server" /f
echo     With the default FailClose=1 and no reachable ServerURL, RDP logon will be BLOCKED
echo     (fail-open is off; the default https://twofa.corp.local does not exist).
echo.
"@
    Set-Content -Path "$RdpDistDir\install.bat" -Value $installBat -Encoding Ascii

    $uninstallBat = @"
@echo off
echo ========================================================
echo Uninstalling Ligament 2FA Credential Provider...
echo ========================================================
regsvr32.exe /u /s "%SystemRoot%\System32\LigamentCredentialProvider.dll"
del /F /Q "%SystemRoot%\System32\LigamentCredentialProvider.dll"
echo [OK] Ligament Credential Provider unregistered and removed.
"@
    Set-Content -Path "$RdpDistDir\uninstall.bat" -Value $uninstallBat -Encoding Ascii

    Compress-Archive -Path "$RdpDistDir\*" -DestinationPath "$DistDir\Ligament-2FA-RDP-CredentialProvider-x64.zip" -Force
    Remove-Item -Recurse -Force $RdpDistDir -ErrorAction SilentlyContinue
    Write-Host " Создан автономный RDP пакет: $DistDir\Ligament-2FA-RDP-CredentialProvider-x64.zip" -ForegroundColor Green
}

# 4. Проверка наличия WiX Toolset
$wixInstalled = $false
$heatCmd = ""
$candleCmd = ""
$lightCmd = ""

if (Get-Command "heat.exe" -ErrorAction SilentlyContinue) {
    $heatCmd = "heat.exe"
    $candleCmd = "candle.exe"
    $lightCmd = "light.exe"
    $wixInstalled = $true
} elseif (Test-Path "C:\Program Files (x86)\WiX Toolset v3.11\bin\candle.exe") {
    $wixBin = "C:\Program Files (x86)\WiX Toolset v3.11\bin"
    $heatCmd = "$wixBin\heat.exe"
    $candleCmd = "$wixBin\candle.exe"
    $lightCmd = "$wixBin\light.exe"
    $wixInstalled = $true
} elseif (Test-Path "C:\Program Files (x86)\WiX Toolset v3.14\bin\candle.exe") {
    $wixBin = "C:\Program Files (x86)\WiX Toolset v3.14\bin"
    $heatCmd = "$wixBin\heat.exe"
    $candleCmd = "$wixBin\candle.exe"
    $lightCmd = "$wixBin\light.exe"
    $wixInstalled = $true
}

if (-not $wixInstalled) {
    Write-Host "`n[!] WiX Toolset не найден в системе." -ForegroundColor Red
    Write-Host "Для автоматической сборки MSI установите WiX через winget:" -ForegroundColor Yellow
    Write-Host "  winget install WiX.Toolset" -ForegroundColor Green
    Write-Host "Или скачайте инсталлятор: https://github.com/wixtoolset/wix3/releases" -ForegroundColor Yellow
    Write-Host "`nФайлы скомпилированного приложения готовы в папке:" -ForegroundColor Cyan
    Write-Host "  $BuildReleaseDir" -ForegroundColor White
    exit 1
}

# 5. Упаковка через WiX Toolset
Write-Host "`n[4/5] Анализ и сборка компонентов приложения (WiX Heat)..." -ForegroundColor Yellow
$TempDir = [System.IO.Path]::GetTempPath() + "LigamentWix_" + [System.Guid]::NewGuid().ToString("N")
New-Item -ItemType Directory -Path $TempDir | Out-Null

try {
    # Генерируем фрагмент с файлами релиза Flutter
    & $heatCmd dir "$BuildReleaseDir" -cg AppFiles -dr INSTALLFOLDER -gg -scom -sreg -srd -var "var.SourceDir" -out "$TempDir\Files.wxs"

    Write-Host "`n[5/5] Компиляция WiX XML (Candle) и линковка MSI (Light)..." -ForegroundColor Yellow
    & $candleCmd -arch x64 -dSourceDir="$BuildReleaseDir" "$ClientDir\windows\installer\Product.wxs" "$TempDir\Files.wxs" -out "$TempDir\"
    & $lightCmd -sval -ext WixUIExtension "$TempDir\Product.wixobj" "$TempDir\Files.wixobj" -o "$OutputMsi"

    Write-Host "`n========================================================" -ForegroundColor Green
    Write-Host " УСПЕШНО СОБРАН WINDOWS MSI ДИСТРИБУТИВ (APP + RDP 2FA):" -ForegroundColor Green
    Write-Host " Файл: $OutputMsi" -ForegroundColor White
    Write-Host " Размер: $((Get-Item $OutputMsi).Length / 1MB) МБ" -ForegroundColor White
    Write-Host "========================================================" -ForegroundColor Green
    Write-Host "Тихая установка для Active Directory GPO / SCCM / Intune:" -ForegroundColor Cyan
    Write-Host "  msiexec /i Ligament-2FA-Windows-x64.msi /qn" -ForegroundColor White
} finally {
    Remove-Item -Recurse -Force $TempDir -ErrorAction SilentlyContinue
}
