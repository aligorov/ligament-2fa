import 'dart:async';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:local_auth/local_auth.dart';
import 'package:device_info_plus/device_info_plus.dart';

import '../api/client.dart';
import 'alert_service.dart';
import 'gpo_service.dart';
import 'telemetry_service.dart';
import 'ws_service.dart';

class AuthState extends ChangeNotifier {
  final GPOService gpo = GPOService();
  final AlertService alert = AlertService();
  final TelemetryService telemetry = TelemetryService();
  final WebSocketService ws = WebSocketService();
  final LocalAuthentication localAuth = LocalAuthentication();

  ApiClient? api;
  String? serverUrl;
  String? token;
  Map<String, dynamic>? currentUser;

  List<Map<String, dynamic>> pendingChallenges = [];
  List<Map<String, dynamic>> allowedApps = [];
  List<Map<String, dynamic>> history = [];
  Map<String, dynamic>? currentPosture;
  bool isCompliant = true;
  bool isOnline = false;

  Map<String, dynamic>? activePrompt;
  final Set<String> _resolvedChallengeIds = {};

  bool get isLoggedIn => token != null && currentUser != null;

  void dismissPrompt([String? challengeId]) {
    if (challengeId != null && challengeId.isNotEmpty) {
      _resolvedChallengeIds.add(challengeId);
    } else if (activePrompt != null) {
      final cid = activePrompt!['challenge_id']?.toString();
      if (cid != null && cid.isNotEmpty) _resolvedChallengeIds.add(cid);
    }
    activePrompt = null;
    alert.resetWindowPriority();
    notifyListeners();
  }

  Future<void> init() async {
    final prefs = await SharedPreferences.getInstance();

    // Если GPO принудительно задает ServerURL, используем его
    serverUrl = gpo.enforcedServerUrl ?? prefs.getString('server_url');

    final savedToken = prefs.getString('auth_token');

    if (serverUrl != null && savedToken != null) {
      api = ApiClient(baseUrl: serverUrl!, token: savedToken);
      token = savedToken;

      try {
        currentUser = await api!.getProfile();
        _setupServices();
        await refreshAll();
      } catch (e) {
        debugPrint('auth_state: токен недействителен или сервер недоступен: $e');
        // Если ошибка 401, сбрасываем токен
        if (e is ApiException && e.statusCode == 401) {
          await logout();
        }
      }
    }

    notifyListeners();
  }

  void _setupServices() {
    if (api == null || token == null || serverUrl == null) return;

    // 1. WebSocket для мгновенных push-оповещений
    ws.onPrompt = (prompt) {
      final cid = prompt['challenge_id']?.toString();
      if (cid != null && _resolvedChallengeIds.contains(cid)) {
        return;
      }
      activePrompt = prompt;
      alert.triggerAlert(
        title: 'Запрос на авторизацию: ${prompt['service'] ?? 'Ligament 2FA'}',
        body: 'Инициатор: ${prompt['who'] ?? 'Сотрудник'} (IP: ${prompt['ip'] ?? '—'})',
        challengeId: cid,
      );
      loadPendingChallenges();
      notifyListeners();
    };

    ws.onConnected = () {
      isOnline = true;
      notifyListeners();
    };

    ws.onDisconnected = () {
      isOnline = false;
      notifyListeners();
    };

    ws.connect(baseUrl: serverUrl!, token: token!);

    // 2. Телеметрия и контроль комплаенса
    telemetry.startReporting(api!);
  }

  Future<void> setServerUrl(String url) async {
    serverUrl = url.trim();
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('server_url', serverUrl!);
    api = ApiClient(baseUrl: serverUrl!);
    notifyListeners();
  }

  Future<void> login(String username, String password) async {
    if (serverUrl == null || serverUrl!.isEmpty) {
      throw Exception('Не указан адрес сервера');
    }

    api ??= ApiClient(baseUrl: serverUrl!);

    // Собираем базовую информацию об устройстве
    final deviceInfo = DeviceInfoPlugin();
    String deviceName = 'Device';
    String osVersion = '';
    String platform = 'unknown';

    if (!kIsWeb) {
      if (Platform.isWindows) {
        platform = 'windows';
        final wInfo = await deviceInfo.windowsInfo;
        deviceName = wInfo.computerName;
        osVersion = wInfo.displayVersion;
      } else if (Platform.isAndroid) {
        platform = 'android';
        final aInfo = await deviceInfo.androidInfo;
        deviceName = '${aInfo.brand} ${aInfo.model}';
        osVersion = 'Android ${aInfo.version.release}';
      } else if (Platform.isIOS) {
        platform = 'ios';
        final iInfo = await deviceInfo.iosInfo;
        deviceName = iInfo.name;
        osVersion = '${iInfo.systemName} ${iInfo.systemVersion}';
      }
    }

    final initialPosture = await telemetry.collectPosture();

    final resp = await api!.login(
      username: username,
      password: password,
      deviceName: deviceName,
      platform: platform,
      osVersion: osVersion,
      appVersion: '1.0.0',
      securityPosture: initialPosture,
    );

    token = resp['token'] as String;
    currentUser = resp['user'] as Map<String, dynamic>;
    currentPosture = resp['security_posture'] as Map<String, dynamic>?;
    isCompliant = currentPosture?['is_compliant'] == true;

    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('auth_token', token!);
    await prefs.setString('server_url', serverUrl!);

    _setupServices();
    await refreshAll();
    notifyListeners();
  }

  Future<void> logout() async {
    try {
      await api?.logout();
    } catch (_) {}

    ws.disconnect();
    telemetry.stopReporting();

    token = null;
    currentUser = null;
    api = null;
    activePrompt = null;
    pendingChallenges.clear();
    allowedApps.clear();
    history.clear();

    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('auth_token');
    notifyListeners();
  }

  Future<void> refreshAll() async {
    if (!isLoggedIn) return;
    await Future.wait([
      loadPendingChallenges(),
      loadAllowedApps(),
      loadHistory(),
      checkPosture(),
    ]);
  }

  Future<void> loadPendingChallenges() async {
    if (api == null) return;
    try {
      final list = await api!.getPendingChallenges();
      pendingChallenges = list.where((c) {
        final id = c['id']?.toString();
        return id != null && !_resolvedChallengeIds.contains(id);
      }).toList();

      if (pendingChallenges.isEmpty) {
        activePrompt = null;
        alert.resetWindowPriority();
      } else if (activePrompt == null) {
        final first = pendingChallenges.first;
        final meta = first['metadata'] as Map<String, dynamic>? ?? {};
        activePrompt = {
          'challenge_id': first['id'],
          'who': meta['username'] ?? currentUser?['username'],
          'ip': meta['ip'] ?? '—',
          'ua': meta['ua'] ?? '—',
          'service': first['purpose'] ?? '2FA Login',
          'number_match': meta['number_match'],
          'expires_in_seconds': first['expires_in_seconds'],
        };
      }
      notifyListeners();
    } catch (e) {
      debugPrint('auth_state: ошибка загрузки челленджей: $e');
    }
  }

  Future<void> loadAllowedApps() async {
    if (api == null) return;
    try {
      allowedApps = await api!.getAllowedApps();
      notifyListeners();
    } catch (e) {
      debugPrint('auth_state: ошибка загрузки приложений: $e');
    }
  }

  Future<void> loadHistory() async {
    if (api == null) return;
    try {
      history = await api!.getHistory();
      notifyListeners();
    } catch (e) {
      debugPrint('auth_state: ошибка загрузки истории: $e');
    }
  }

  Future<void> checkPosture() async {
    if (api == null) return;
    try {
      currentPosture = await telemetry.collectPosture();
      isCompliant = currentPosture?['is_compliant'] == true;
      notifyListeners();
    } catch (_) {}
  }

  /// Решение по push-запросу: подтвердить (approve) или отклонить (deny)
  Future<void> submitDecision({
    required String challengeId,
    required bool approve,
    String? selectedNumberMatch,
  }) async {
    if (api == null) return;

    if (challengeId.isNotEmpty) {
      _resolvedChallengeIds.add(challengeId);
    }
    activePrompt = null;
    await alert.resetWindowPriority();

    if (approve) {
      // 1. Если включена GPO политика Windows Hello или системная биометрия
      if (gpo.requireWindowsHello) {
        final didAuth = await localAuth.authenticate(
          localizedReason: 'Подтвердите вход в корпоративную систему с помощью Windows Hello',
          options: const AuthenticationOptions(biometricOnly: false, stickyAuth: true),
        );
        if (!didAuth) {
          throw Exception('Подтверждение Windows Hello отклонено');
        }
      }

      // 2. Отправка подтверждения
      await api!.challengeDecision(
        challengeId: challengeId,
        decision: 'approve',
        numberMatch: selectedNumberMatch,
      );
    } else {
      await api!.challengeDecision(
        challengeId: challengeId,
        decision: 'deny',
      );
    }

    await loadPendingChallenges();
    await loadHistory();
    notifyListeners();
  }
}
