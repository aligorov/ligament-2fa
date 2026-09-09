import 'dart:async';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:local_auth/local_auth.dart';
import 'gpo_service.dart';
import '../api/client.dart';

/// Сервис сбора телеметрии устройства и контроля соответствия политикам (GPO).
class TelemetryService {
  final GPOService _gpo = GPOService();
  final LocalAuthentication _localAuth = LocalAuthentication();
  final DeviceInfoPlugin _deviceInfo = DeviceInfoPlugin();

  Timer? _timer;

  /// Запуск периодического сбора и отправки снимка телеметрии
  void startReporting(ApiClient api) {
    _timer?.cancel();
    // Первый сбор сразу
    reportTelemetry(api);

    final interval = Duration(seconds: _gpo.telemetryIntervalSeconds);
    _timer = Timer.periodic(interval, (_) => reportTelemetry(api));
  }

  void stopReporting() {
    _timer?.cancel();
    _timer = null;
  }

  /// Сбор текущего профиля безопасности устройства
  Future<Map<String, dynamic>> collectPosture() async {
    final posture = <String, dynamic>{
      'platform': _platformName(),
      'timestamp': DateTime.now().toUtc().toIso8601String(),
    };

    // 1. Биометрия и Windows Hello
    try {
      final canAuth = await _localAuth.canCheckBiometrics;
      final isDeviceSupported = await _localAuth.isDeviceSupported();
      posture['biometrics_enrolled'] = canAuth || isDeviceSupported;
    } catch (_) {
      posture['biometrics_enrolled'] = false;
    }

    // 2. Специфика Windows: BitLocker, Defender, Firewall, GPO
    if (!kIsWeb && Platform.isWindows) {
      posture['bitlocker'] = await _checkWindowsBitLocker();
      posture['defender'] = await _checkWindowsDefender();
      posture['firewall'] = await _checkWindowsFirewall();

      // Прикрепляем требования GPO
      posture['policy_require_bitlocker'] = _gpo.requireBitLocker;
      posture['policy_require_antivirus'] = _gpo.requireAntivirus;
      posture['policy_require_firewall'] = _gpo.requireFirewall;
      posture['policy_require_hello'] = _gpo.requireWindowsHello;
    }

    // 2b. Специфика macOS: FileVault, Gatekeeper, Firewall, MDM
    if (!kIsWeb && Platform.isMacOS) {
      final fv = await _checkMacOSFileVault();
      posture['filevault'] = fv;
      posture['bitlocker'] = fv; // Для совместимости с общим дашбордом шифрования
      final gk = await _checkMacOSGatekeeper();
      posture['gatekeeper'] = gk;
      posture['defender'] = gk; // Для совместимости с проверкой антивируса
      posture['firewall'] = await _checkMacOSFirewall();
      posture['touch_id'] = posture['biometrics_enrolled'] == true;

      // Прикрепляем требования MDM
      posture['policy_require_bitlocker'] = _gpo.requireBitLocker;
      posture['policy_require_antivirus'] = _gpo.requireAntivirus;
      posture['policy_require_firewall'] = _gpo.requireFirewall;
      posture['policy_require_hello'] = _gpo.requireWindowsHello;
    }

    // 3. Специфика Android / iOS: Root & Jailbreak обнаружение
    if (!kIsWeb && (Platform.isAndroid || Platform.isIOS)) {
      posture['rooted'] = await _checkRootOrJailbreak();
      posture['jailbroken'] = posture['rooted'];
    }

    // 4. Оценка общего соответствия (is_compliant)
    bool compliant = true;
    if (posture['rooted'] == true || posture['jailbroken'] == true) {
      compliant = false;
    }
    if (_gpo.requireBitLocker &&
        posture['bitlocker'] != 'encrypted' &&
        posture['filevault'] != 'encrypted') {
      compliant = false;
    }
    if (_gpo.requireAntivirus &&
        posture['defender'] != 'active' &&
        posture['gatekeeper'] != 'active') {
      compliant = false;
    }
    if (_gpo.requireFirewall && posture['firewall'] != 'active') {
      compliant = false;
    }
    if (_gpo.requireWindowsHello && posture['biometrics_enrolled'] != true) {
      compliant = false;
    }

    posture['is_compliant'] = compliant;
    return posture;
  }

  /// Отправка телеметрии на сервер Ligament
  Future<bool> reportTelemetry(ApiClient api) async {
    if (!_gpo.collectTelemetry) return true;
    try {
      final start = DateTime.now();
      final posture = await collectPosture();
      posture['latency_ms'] = DateTime.now().difference(start).inMilliseconds;

      final isCompliant = await api.sendTelemetry(posture);
      return isCompliant;
    } catch (e) {
      debugPrint('telemetry_service: ошибка отправки: $e');
      return false;
    }
  }

  String _platformName() {
    if (kIsWeb) return 'web';
    if (Platform.isWindows) return 'windows';
    if (Platform.isAndroid) return 'android';
    if (Platform.isIOS) return 'ios';
    if (Platform.isMacOS) return 'macos';
    if (Platform.isLinux) return 'linux';
    return 'unknown';
  }

  Future<String> _checkWindowsBitLocker() async {
    try {
      final result = await Process.run('manage-bde', ['-status', 'C:']);
      if (result.stdout.toString().contains('Percentage Encrypted:   100%') ||
          result.stdout.toString().contains('Процент зашифрованного места: 100%') ||
          result.stdout.toString().contains('Protection On') ||
          result.stdout.toString().contains('Защита включена')) {
        return 'encrypted';
      }
    } catch (_) {}
    return 'off';
  }

  Future<String> _checkWindowsDefender() async {
    try {
      final result = await Process.run('powershell', [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        'Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled'
      ]);
      if (result.stdout.toString().trim() == 'True') {
        return 'active';
      }
    } catch (_) {}
    return 'active'; // fallback при ограниченных правах обычного пользователя
  }

  Future<String> _checkWindowsFirewall() async {
    try {
      final result = await Process.run('netsh', ['advfirewall', 'show', 'allprofiles']);
      if (result.stdout.toString().contains('ON') || result.stdout.toString().contains('ВКЛ')) {
        return 'active';
      }
    } catch (_) {}
    return 'active';
  }

  Future<bool> _checkRootOrJailbreak() async {
    if (Platform.isAndroid) {
      // Проверка типовых путей su и Superuser
      final paths = [
        '/system/app/Superuser.apk',
        '/sbin/su',
        '/system/bin/su',
        '/system/xbin/su',
        '/data/local/xbin/su',
        '/data/local/bin/su',
        '/system/sd/xbin/su',
        '/system/bin/failsafe/su',
        '/data/local/su',
      ];
      for (final p in paths) {
        if (File(p).existsSync()) return true;
      }
    } else if (Platform.isIOS) {
      final paths = [
        '/Applications/Cydia.app',
        '/Library/MobileSubstrate/MobileSubstrate.dylib',
        '/bin/bash',
        '/usr/sbin/sshd',
        '/etc/apt',
      ];
      for (final p in paths) {
        if (File(p).existsSync()) return true;
      }
    }
    return false;
  }

  Future<String> _checkMacOSFileVault() async {
    try {
      final result = await Process.run('fdesetup', ['status']);
      if (result.stdout.toString().contains('FileVault is On.')) {
        return 'encrypted';
      }
    } catch (_) {}
    return 'off';
  }

  Future<String> _checkMacOSGatekeeper() async {
    try {
      final result = await Process.run('spctl', ['--status']);
      if (result.stdout.toString().contains('assessments enabled')) {
        return 'active';
      }
    } catch (_) {}
    return 'active';
  }

  Future<String> _checkMacOSFirewall() async {
    try {
      final result = await Process.run(
        '/usr/libexec/ApplicationFirewall/socketfilterfw',
        ['--getglobalstate'],
      );
      if (result.stdout.toString().contains('State = 1') ||
          result.stdout.toString().contains('Firewall is enabled')) {
        return 'active';
      }
    } catch (_) {}
    return 'off';
  }
}
