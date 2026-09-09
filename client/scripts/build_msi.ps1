# build_msi.ps1 — Автоматическая сборка Windows MSI-пакета для Ligament 2FA
# Запуск в PowerShell:
#   .\scripts\build_msi.ps1
#
# Требования на Windows:
#   1. Flutter SDK: flutter doctor
#   2. WiX Toolset: winget install WiX.Toolset (или https://wixtoolset.org)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ClientDir = Split-Path -Parent $ScriptDir
$BuildReleaseDir = "$ClientDir\build\windows\x64\runner\Release"
$DistDir = "$ClientDir\dist"
$OutputMsi = "$DistDir\Ligament-2FA-Windows-x64.msi"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " Сборка Windows MSI пакета: Ligament 2FA" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# 1. Сборка релизной версии Flutter для Windows
Set-Location $ClientDir
$env:CL = "$env:CL /D_SILENCE_EXPERIMENTAL_COROUTINE_DEPRECATION_WARNINGS"
Write-Host "`n[1/4] Компиляция Flutter Windows Release..." -ForegroundColor Yellow
flutter build windows --release

if (-not (Test-Path "$BuildReleaseDir\ligament_authenticator.exe")) {
    Write-Error "Ошибка: Бинарный файл $BuildReleaseDir\ligament_authenticator.exe не найден!"
}

# 2. Создание каталога дистрибутивов
if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir | Out-Null
}

# 3. Проверка наличия WiX Toolset
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

# 4. Упаковка через WiX Toolset
Write-Host "`n[2/4] Анализ и сборка компонентов приложения (WiX Heat)..." -ForegroundColor Yellow
$TempDir = [System.IO.Path]::GetTempPath() + "LigamentWix_" + [System.Guid]::NewGuid().ToString("N")
New-Item -ItemType Directory -Path $TempDir | Out-Null

try {
    # Генерируем фрагмент с файлами релиза
    & $heatCmd dir "$BuildReleaseDir" -cg AppFiles -dr INSTALLFOLDER -gg -scom -sreg -srd -var "var.SourceDir" -out "$TempDir\Files.wxs"

    Write-Host "`n[3/4] Компиляция WiX XML (Candle)..." -ForegroundColor Yellow
    & $candleCmd -dSourceDir="$BuildReleaseDir" "$ClientDir\windows\installer\Product.wxs" "$TempDir\Files.wxs" -out "$TempDir\"

    Write-Host "`n[4/4] Линковка и создание MSI пакета (Light)..." -ForegroundColor Yellow
    & $lightCmd -ext WixUIExtension "$TempDir\Product.wixobj" "$TempDir\Files.wixobj" -o "$OutputMsi"

    Write-Host "`n========================================================" -ForegroundColor Green
    Write-Host " УСПЕШНО СОБРАН WINDOWS MSI ДИСТРИБУТИВ:" -ForegroundColor Green
    Write-Host " Файл: $OutputMsi" -ForegroundColor White
    Write-Host " Размер: $((Get-Item $OutputMsi).Length / 1MB) МБ" -ForegroundColor White
    Write-Host "========================================================" -ForegroundColor Green
    Write-Host "Тихая установка для Active Directory GPO / SCCM / Intune:" -ForegroundColor Cyan
    Write-Host "  msiexec /i Ligament-2FA-Windows-x64.msi /qn" -ForegroundColor White
} finally {
    Remove-Item -Recurse -Force $TempDir -ErrorAction SilentlyContinue
}
