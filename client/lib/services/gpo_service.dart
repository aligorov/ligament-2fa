import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:win32_registry/win32_registry.dart';

/// Сервис чтения корпоративных групповых политик Windows (GPO).
/// Ключ реестра: HKLM\SOFTWARE\Policies\Ligament\2FA
class GPOService {
  static const String _baseKeyPath = r'SOFTWARE\Policies\Ligament\2FA';
  static const String _policiesKeyPath = r'SOFTWARE\Policies\Ligament\2FA\Policies';
  static const String _alertsKeyPath = r'SOFTWARE\Policies\Ligament\2FA\Alerts';
  static const String _telemetryKeyPath = r'SOFTWARE\Policies\Ligament\2FA\Telemetry';

  bool get isWindows => !kIsWeb && Platform.isWindows;
  bool get isMacOS => !kIsWeb && Platform.isMacOS;

  /// Принудительный корпоративный URL сервера Ligament 2FA
  String? get enforcedServerUrl {
    if (isWindows) return _readWindowsString(_baseKeyPath, 'ServerURL');
    if (isMacOS) return _readMacString('ServerURL');
    return null;
  }

  /// Разрешен ли выход из приложения пользователю (0 = запрещен, 1 = разрешен)
  bool get allowExit {
    if (isWindows) {
      final val = _readWindowsDword(_baseKeyPath, 'AllowExit');
      if (val != null) return val == 1;
      return true;
    }
    if (isMacOS) {
      final val = _readMacBool('AllowExit');
      if (val != null) return val;
      return true;
    }
    return true; // по умолчанию разрешен
  }

  /// Автозапуск при входе в систему
  bool get autoStart {
    if (isWindows) {
      final val = _readWindowsDword(_baseKeyPath, 'AutoStart');
      return val == 1;
    }
    if (isMacOS) {
      return _readMacBool('AutoStart') ?? false;
    }
    return false;
  }

  /// Требовать подтверждение через биометрию (Windows Hello / Touch ID)
  bool get requireWindowsHello {
    if (isWindows) {
      final val = _readWindowsDword(_policiesKeyPath, 'RequireWindowsHello');
      return val == 1;
    }
    if (isMacOS) {
      return _readMacBool('RequireTouchID') ?? false;
    }
    return false;
  }

  /// Требовать обязательное шифрование диска (BitLocker / FileVault)
  bool get requireBitLocker {
    if (isWindows) {
      final val = _readWindowsDword(_policiesKeyPath, 'RequireBitLocker');
      return val == 1;
    }
    if (isMacOS) {
      return _readMacBool('RequireFileVault') ?? false;
    }
    return false;
  }

  /// Требовать активный антивирус (Windows Defender / Gatekeeper)
  bool get requireAntivirus {
    if (isWindows) {
      final val = _readWindowsDword(_policiesKeyPath, 'RequireAntivirus');
      return val == 1;
    }
    if (isMacOS) {
      return _readMacBool('RequireGatekeeper') ?? false;
    }
    return false;
  }

  /// Требовать активный брандмауэр / сетевой экран
  bool get requireFirewall {
    if (isWindows) {
      final val = _readWindowsDword(_policiesKeyPath, 'RequireFirewall');
      return val == 1;
    }
    if (isMacOS) {
      return _readMacBool('RequireFirewall') ?? false;
    }
    return false;
  }

  /// Всплывать поверх всех окон при входящем push
  bool get alwaysOnTop {
    if (isWindows) {
      final val = _readWindowsDword(_alertsKeyPath, 'AlwaysOnTop');
      if (val != null) return val == 1;
      return true;
    }
    if (isMacOS) {
      final val = _readMacBool('AlwaysOnTop');
      if (val != null) return val;
      return true;
    }
    return true; // по умолчанию включено
  }

  /// Мигать кнопкой на панели задач (только Windows)
  bool get flashTaskbar {
    if (!isWindows) return true;
    final val = _readWindowsDword(_alertsKeyPath, 'FlashTaskbar');
    if (val != null) return val == 1;
    return true;
  }

  /// Звуковой сигнал оповещения
  bool get playSound {
    if (isWindows) {
      final val = _readWindowsDword(_alertsKeyPath, 'PlaySound');
      if (val != null) return val == 1;
      return true;
    }
    if (isMacOS) {
      final val = _readMacBool('PlaySound');
      if (val != null) return val;
      return true;
    }
    return true;
  }

  /// Включен ли сбор телеметрии
  bool get collectTelemetry {
    if (isWindows) {
      final val = _readWindowsDword(_telemetryKeyPath, 'Enabled');
      if (val != null) return val == 1;
      return true;
    }
    if (isMacOS) {
      final val = _readMacBool('CollectTelemetry');
      if (val != null) return val;
      return true;
    }
    return true;
  }

  /// Периодичность отправки телеметрии (сек)
  int get telemetryIntervalSeconds {
    if (isWindows) {
      final val = _readWindowsDword(_telemetryKeyPath, 'IntervalSeconds');
      if (val != null && val > 0) return val;
      return 300;
    }
    if (isMacOS) {
      final val = _readMacInt('TelemetryIntervalSeconds');
      if (val != null && val > 0) return val;
      return 300;
    }
    return 300;
  }

  // --- Windows Registry Helpers ---

  String? _readWindowsString(String subkey, String valueName) {
    try {
      final key = Registry.openPath(RegistryHive.localMachine, path: subkey);
      final value = key.getValueAsString(valueName);
      key.close();
      if (value != null && value.trim().isNotEmpty) {
        return value.trim();
      }
    } catch (_) {}

    // Fallback: if queried under Policies, check local HKLM\SOFTWARE\Ligament\2FA
    if (subkey.startsWith(r'SOFTWARE\Policies\Ligament\2FA')) {
      try {
        final fallbackSubkey = subkey.replaceFirst(
            r'SOFTWARE\Policies\Ligament\2FA', r'SOFTWARE\Ligament\2FA');
        final key =
            Registry.openPath(RegistryHive.localMachine, path: fallbackSubkey);
        final value = key.getValueAsString(valueName);
        key.close();
        if (value != null && value.trim().isNotEmpty) {
          return value.trim();
        }
      } catch (_) {}
    }
    return null;
  }

  int? _readWindowsDword(String subkey, String valueName) {
    try {
      final key = Registry.openPath(RegistryHive.localMachine, path: subkey);
      final value = key.getValueAsInt(valueName);
      key.close();
      return value;
    } catch (_) {}

    // Fallback: if queried under Policies, check local HKLM\SOFTWARE\Ligament\2FA
    if (subkey.startsWith(r'SOFTWARE\Policies\Ligament\2FA')) {
      try {
        final fallbackSubkey = subkey.replaceFirst(
            r'SOFTWARE\Policies\Ligament\2FA', r'SOFTWARE\Ligament\2FA');
        final key =
            Registry.openPath(RegistryHive.localMachine, path: fallbackSubkey);
        final value = key.getValueAsInt(valueName);
        key.close();
        return value;
      } catch (_) {}
    }
    return null;
  }

  // --- macOS MDM / Managed Preferences Helpers ---

  String? _readMacString(String key) {
    try {
      // 1. Попытка прочитать из Managed Preferences (Apple MDM profile)
      const managedPath = '/Library/Managed Preferences/com.ligament.twofa.plist';
      if (File(managedPath).existsSync()) {
        final res = Process.runSync('defaults', ['read', managedPath, key]);
        if (res.exitCode == 0 && res.stdout.toString().trim().isNotEmpty) {
          return res.stdout.toString().trim();
        }
      }
      // 2. Стандартный домен com.ligament.twofa
      final res = Process.runSync('defaults', ['read', 'com.ligament.twofa', key]);
      if (res.exitCode == 0 && res.stdout.toString().trim().isNotEmpty) {
        return res.stdout.toString().trim();
      }
    } catch (_) {}
    return null;
  }

  bool? _readMacBool(String key) {
    final str = _readMacString(key);
    if (str == null) return null;
    final lower = str.toLowerCase().trim();
    if (lower == '1' || lower == 'true' || lower == 'yes') return true;
    if (lower == '0' || lower == 'false' || lower == 'no') return false;
    return null;
  }

  int? _readMacInt(String key) {
    final str = _readMacString(key);
    if (str == null) return null;
    return int.tryParse(str.trim());
  }
}
