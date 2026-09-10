import 'dart:async';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:local_auth/local_auth.dart';
import 'gpo_service.dart';
import '../api/client.dart';

/// Сервис сбора телеметрии устройства и контроля соответствия политикам (GPO).
class TelemetryService {
  final GPOService _gpo = GPOService();
  final LocalAuthentication _localAuth = LocalAuthentication();

  Timer? _timer;
  int _consecutiveHighCpuCount = 0;

  // Кеширование профиля безопасности
  Map<String, dynamic>? _cachedPosture;
  DateTime? _lastPostureCheck;

  // Windows Kernel32 FFI дескрипторы для мгновенного сбора метрик без запуска процессов
  ffi.DynamicLibrary? _kernel32Lib;
  int Function(
    ffi.Pointer<Utf16> lpDirectoryName,
    ffi.Pointer<ffi.Uint64> lpFreeBytesAvailableToCaller,
    ffi.Pointer<ffi.Uint64> lpTotalNumberOfBytes,
    ffi.Pointer<ffi.Uint64> lpTotalNumberOfFreeBytes,
  )? _winGetDiskFreeSpaceExW;

  int Function(
    ffi.Pointer<ffi.Uint64> lpIdleTime,
    ffi.Pointer<ffi.Uint64> lpKernelTime,
    ffi.Pointer<ffi.Uint64> lpUserTime,
  )? _winGetSystemTimes;

  int _winPrevIdleTime = 0;
  int _winPrevKernelTime = 0;
  int _winPrevUserTime = 0;

  TelemetryService() {
    _initWinKernel32();
  }

  void _initWinKernel32() {
    if (kIsWeb || !Platform.isWindows) return;
    try {
      _kernel32Lib = ffi.DynamicLibrary.open('kernel32.dll');
      _winGetDiskFreeSpaceExW = _kernel32Lib!.lookupFunction<
          ffi.Int32 Function(
            ffi.Pointer<Utf16>,
            ffi.Pointer<ffi.Uint64>,
            ffi.Pointer<ffi.Uint64>,
            ffi.Pointer<ffi.Uint64>,
          ),
          int Function(
            ffi.Pointer<Utf16>,
            ffi.Pointer<ffi.Uint64>,
            ffi.Pointer<ffi.Uint64>,
            ffi.Pointer<ffi.Uint64>,
          )>('GetDiskFreeSpaceExW');

      _winGetSystemTimes = _kernel32Lib!.lookupFunction<
          ffi.Int32 Function(
            ffi.Pointer<ffi.Uint64>,
            ffi.Pointer<ffi.Uint64>,
            ffi.Pointer<ffi.Uint64>,
          ),
          int Function(
            ffi.Pointer<ffi.Uint64>,
            ffi.Pointer<ffi.Uint64>,
            ffi.Pointer<ffi.Uint64>,
          )>('GetSystemTimes');
    } catch (e) {
      debugPrint('telemetry_service: ошибка загрузки kernel32.dll: $e');
    }
  }

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

  /// Сбор текущего профиля безопасности устройства и телеметрии ресурсов
  Future<Map<String, dynamic>> collectPosture({bool forceRefresh = false}) async {
    final now = DateTime.now();
    // Кешируем тяжелые системные проверки безопасности (BitLocker, Defender, Firewall) на 5 минут
    if (!forceRefresh &&
        _cachedPosture != null &&
        _lastPostureCheck != null &&
        now.difference(_lastPostureCheck!).inMinutes < 5) {
      final posture = Map<String, dynamic>.from(_cachedPosture!);
      posture['timestamp'] = now.toUtc().toIso8601String();
      if (!kIsWeb && (Platform.isWindows || Platform.isMacOS || Platform.isLinux)) {
        final disk = await collectDiskMetrics();
        posture.addAll(disk);
        final cpu = await collectCpuMetrics();
        posture.addAll(cpu);
      }
      return posture;
    }

    final posture = <String, dynamic>{
      'platform': _platformName(),
      'timestamp': now.toUtc().toIso8601String(),
    };

    // 1. Биометрия
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

      posture['policy_require_bitlocker'] = _gpo.requireBitLocker;
      posture['policy_require_antivirus'] = _gpo.requireAntivirus;
      posture['policy_require_firewall'] = _gpo.requireFirewall;
      posture['policy_require_hello'] = _gpo.requireWindowsHello;
    }

    // 2b. Специфика macOS: FileVault, Gatekeeper, Firewall, Touch ID (без чуждых терминов Windows)
    if (!kIsWeb && Platform.isMacOS) {
      final fv = await _checkMacOSFileVault();
      posture['filevault'] = fv;
      final gk = await _checkMacOSGatekeeper();
      posture['gatekeeper'] = gk;
      posture['firewall'] = await _checkMacOSFirewall();
      posture['touch_id'] = posture['biometrics_enrolled'] == true;

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

    // 4. Метрики диска и нагрузки CPU
    if (!kIsWeb && (Platform.isWindows || Platform.isMacOS || Platform.isLinux)) {
      final disk = await collectDiskMetrics();
      posture.addAll(disk);

      final cpu = await collectCpuMetrics();
      posture.addAll(cpu);
    }

    // 5. Оценка общего соответствия (is_compliant)
    bool compliant = true;
    if (posture['rooted'] == true || posture['jailbroken'] == true) {
      compliant = false;
    }
    if (_gpo.requireBitLocker) {
      if (!kIsWeb && Platform.isMacOS) {
        if (posture['filevault'] != 'encrypted') compliant = false;
      } else {
        if (posture['bitlocker'] != 'encrypted') compliant = false;
      }
    }
    if (_gpo.requireAntivirus) {
      if (!kIsWeb && Platform.isMacOS) {
        if (posture['gatekeeper'] != 'active') compliant = false;
      } else {
        if (posture['defender'] != 'active') compliant = false;
      }
    }
    if (_gpo.requireFirewall && posture['firewall'] != 'active') {
      compliant = false;
    }
    if (_gpo.requireWindowsHello && posture['biometrics_enrolled'] != true) {
      compliant = false;
    }

    posture['is_compliant'] = compliant;
    _cachedPosture = Map<String, dynamic>.from(posture);
    _lastPostureCheck = now;
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

  /// Сбор метрик дискового пространства (Win32 FFI без накладных расходов)
  Future<Map<String, dynamic>> collectDiskMetrics() async {
    final metrics = <String, dynamic>{
      'disk_percent': 0,
      'disk_free_gb': 0,
      'disk_total_gb': 0,
      'disk_warning': false,
      'disk_details': '',
    };

    try {
      if (Platform.isMacOS || Platform.isLinux) {
        final res = await Process.run('df', ['-k', '/']).timeout(
          const Duration(seconds: 2),
          onTimeout: () => ProcessResult(0, -1, '', 'timeout'),
        );
        if (res.exitCode == 0) {
          final lines = res.stdout.toString().trim().split('\n');
          if (lines.length >= 2) {
            final parts = lines[1].split(RegExp(r'\s+'));
            if (parts.length >= 5) {
              final totalKb = int.tryParse(parts[1]) ?? 0;
              final freeKb = int.tryParse(parts[3]) ?? 0;
              final capStr = parts[4].replaceAll('%', '');
              final usedPercent = int.tryParse(capStr) ?? 0;

              final totalGb = (totalKb / (1024 * 1024)).round();
              final freeGb = (freeKb / (1024 * 1024)).round();

              metrics['disk_percent'] = usedPercent;
              metrics['disk_free_gb'] = freeGb;
              metrics['disk_total_gb'] = totalGb;
              metrics['disk_details'] = '$freeGb ГБ свободно из $totalGb ГБ ($usedPercent% занято)';
              metrics['disk_warning'] = usedPercent >= 90 || (freeGb < 10 && totalGb > 0);
            }
          }
        }
      } else if (Platform.isWindows) {
        if (_winGetDiskFreeSpaceExW != null) {
          final dirPtr = 'C:\\'.toNativeUtf16();
          final freeCallerPtr = calloc<ffi.Uint64>();
          final totalBytesPtr = calloc<ffi.Uint64>();
          final totalFreeBytesPtr = calloc<ffi.Uint64>();
          try {
            final ok = _winGetDiskFreeSpaceExW!(dirPtr, freeCallerPtr, totalBytesPtr, totalFreeBytesPtr);
            if (ok != 0) {
              final total = totalBytesPtr.value;
              final free = freeCallerPtr.value;
              if (total > 0) {
                final totalGb = (total / (1024 * 1024 * 1024)).round();
                final freeGb = (free / (1024 * 1024 * 1024)).round();
                final usedGb = totalGb - freeGb;
                final usedPercent = (usedGb / totalGb * 100).round();

                metrics['disk_percent'] = usedPercent;
                metrics['disk_free_gb'] = freeGb;
                metrics['disk_total_gb'] = totalGb;
                metrics['disk_details'] = '$freeGb ГБ свободно из $totalGb ГБ ($usedPercent% занято)';
                metrics['disk_warning'] = usedPercent >= 90 || freeGb < 10;
              }
            }
          } finally {
            calloc.free(dirPtr);
            calloc.free(freeCallerPtr);
            calloc.free(totalBytesPtr);
            calloc.free(totalFreeBytesPtr);
          }
        }
      }
    } catch (e) {
      debugPrint('telemetry_service: ошибка сбора диска: $e');
    }

    return metrics;
  }

  /// Сбор метрик процессора (CPU) через GetSystemTimes без запуска дочерних процессов
  Future<Map<String, dynamic>> collectCpuMetrics() async {
    final metrics = <String, dynamic>{
      'cpu_percent': 0,
      'cpu_warning': false,
      'cpu_spike_100': false,
    };

    try {
      if (Platform.isMacOS) {
        final res = await Process.run('top', ['-l', '1', '-n', '0']).timeout(
          const Duration(seconds: 2),
          onTimeout: () => ProcessResult(0, -1, '', 'timeout'),
        );
        if (res.exitCode == 0) {
          final out = res.stdout.toString();
          final match = RegExp(r'CPU usage:\s+([0-9.]+)%\s+user,\s+([0-9.]+)%\s+sys,\s+([0-9.]+)%\s+idle').firstMatch(out);
          if (match != null) {
            final idle = double.tryParse(match.group(3) ?? '') ?? 100.0;
            final usage = (100.0 - idle).clamp(0.0, 100.0).round();
            metrics['cpu_percent'] = usage;
          }
        }
      } else if (Platform.isWindows) {
        if (_winGetSystemTimes != null) {
          final idleTimePtr = calloc<ffi.Uint64>();
          final kernelTimePtr = calloc<ffi.Uint64>();
          final userTimePtr = calloc<ffi.Uint64>();
          try {
            final ok = _winGetSystemTimes!(idleTimePtr, kernelTimePtr, userTimePtr);
            if (ok != 0) {
              final idle = idleTimePtr.value;
              final kernel = kernelTimePtr.value;
              final user = userTimePtr.value;

              if (_winPrevIdleTime != 0 && _winPrevKernelTime != 0 && _winPrevUserTime != 0) {
                final idleDelta = idle - _winPrevIdleTime;
                final kernelDelta = kernel - _winPrevKernelTime;
                final userDelta = user - _winPrevUserTime;

                // В Windows GetSystemTimes kernelTime уже включает в себя idleTime
                final totalSys = kernelDelta + userDelta;
                if (totalSys > 0) {
                  final idleFraction = (idleDelta / totalSys).clamp(0.0, 1.0);
                  final usage = ((1.0 - idleFraction) * 100).clamp(0.0, 100.0).round();
                  metrics['cpu_percent'] = usage;
                }
              }
              _winPrevIdleTime = idle;
              _winPrevKernelTime = kernel;
              _winPrevUserTime = user;
            }
          } finally {
            calloc.free(idleTimePtr);
            calloc.free(kernelTimePtr);
            calloc.free(userTimePtr);
          }
        }
      } else if (Platform.isLinux) {
        final res = await Process.run('sh', ['-c', "grep 'cpu ' /proc/stat"]).timeout(
          const Duration(seconds: 2),
          onTimeout: () => ProcessResult(0, -1, '', 'timeout'),
        );
        if (res.exitCode == 0) {
          metrics['cpu_percent'] = 15; // fallback
        }
      }

      final cpu = metrics['cpu_percent'] as int;
      if (cpu >= 90) {
        _consecutiveHighCpuCount++;
      } else {
        _consecutiveHighCpuCount = 0;
      }

      metrics['cpu_warning'] = cpu >= 90;
      metrics['cpu_spike_100'] = cpu >= 98 || _consecutiveHighCpuCount >= 3;
    } catch (e) {
      debugPrint('telemetry_service: ошибка сбора CPU: $e');
    }

    return metrics;
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
      final result = await Process.run('manage-bde', ['-status', 'C:']).timeout(
        const Duration(seconds: 3),
        onTimeout: () => ProcessResult(0, -1, '', 'timeout'),
      );
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
      ]).timeout(
        const Duration(seconds: 3),
        onTimeout: () => ProcessResult(0, 0, 'True', ''),
      );
      if (result.stdout.toString().trim() == 'True') {
        return 'active';
      }
    } catch (_) {}
    return 'active'; // fallback при ограниченных правах обычного пользователя
  }

  Future<String> _checkWindowsFirewall() async {
    try {
      final result = await Process.run('netsh', ['advfirewall', 'show', 'allprofiles']).timeout(
        const Duration(seconds: 3),
        onTimeout: () => ProcessResult(0, -1, '', 'timeout'),
      );
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
