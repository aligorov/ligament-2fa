import 'dart:async';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:local_auth/local_auth.dart';
import 'package:device_info_plus/device_info_plus.dart';

import '../api/client.dart';
import 'alert_service.dart';
import 'gpo_service.dart';
import 'support_service.dart';
import 'telemetry_service.dart';
import 'ws_service.dart';

class AuthState extends ChangeNotifier {
  final GPOService gpo = GPOService();
  final AlertService alert = AlertService();
  final TelemetryService telemetry = TelemetryService();
  final WebSocketService ws = WebSocketService();
  final LocalAuthentication localAuth = LocalAuthentication();
  final SupportService support = SupportService();

  ApiClient? api;
  String? serverUrl;
  String? token;
  Map<String, dynamic>? currentUser;

  List<Map<String, dynamic>> pendingChallenges = [];
  List<Map<String, dynamic>> allowedApps = [];
  List<Map<String, dynamic>> history = [];
  List<Map<String, dynamic>> supportQueue = [];
  Map<String, dynamic>? currentPosture;
  bool isCompliant = true;
  bool isOnline = false;

  Map<String, dynamic>? activePrompt;
  Map<String, dynamic>? activeSupportPrompt;
  Timer? _pollingTimer;
  final Set<String> _resolvedChallengeIds = {};

  bool get isLoggedIn => token != null && currentUser != null;

  String get username => currentUser?['username']?.toString() ?? '';
  String get displayName {
    final dn = currentUser?['display_name']?.toString();
    if (dn != null && dn.isNotEmpty) return dn;
    return username;
  }

  bool get isAdmin => currentUser?['role'] == 'admin';

  List<String> get supportRoles {
    final raw = currentUser?['support_roles'];
    if (raw is List) {
      return raw.map((e) => e.toString().toLowerCase()).toList();
    }
    return [];
  }

  bool get isITEngineer => isAdmin || supportRoles.contains('it');
  bool get is1CEngineer => isAdmin || supportRoles.contains('1c');
  bool get isEngineer => isAdmin || supportRoles.isNotEmpty;

  String? get engineerBadge {
    if (isAdmin) return '👑 Администратор';
    if (isITEngineer && is1CEngineer) return '🛠 IT / 1С-инженер';
    if (is1CEngineer) return '📊 1С-инженер';
    if (isITEngineer) return '🖥 IT-инженер';
    if (supportRoles.isNotEmpty) return '🛠 Инженер (${supportRoles.join(", ")})';
    return null;
  }

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

    ws.onSupportPrompt = (prompt) {
      activeSupportPrompt = prompt;
      support.setAuthorizing(
        sessionId: prompt['session_id']?.toString() ?? '',
        category: prompt['category']?.toString(),
        problemSummary: prompt['problem_summary']?.toString(),
        accessMode: prompt['access_mode']?.toString(),
      );
      final cat = prompt['category'] == '1c' ? '1С-поддержка' : 'IT-служба';
      alert.triggerAlert(
        title: 'Удаленная помощь: $cat',
        body: 'Инженер готов подключиться к экрану. Подтвердите контрольное число.',
        challengeId: prompt['session_id']?.toString(),
      );
      notifyListeners();
    };

    ws.onSupportSignal = (signal) {
      support.handleRemoteSignal(signal);
    };

    ws.onSupportEnded = (msg) {
      support.stopScreenSharing();
      activeSupportPrompt = null;
      notifyListeners();
    };

    ws.onSupportIncoming = (msg) {
      if (isEngineer) {
        loadSupportQueue();
        alert.triggerAlert(
          title: 'Новое SOS-обращение: ${msg['category'] == '1c' ? '1С' : 'IT'}',
          body: '${msg['employee_name'] ?? msg['username'] ?? 'Пользователь'}: ${msg['problem_summary'] ?? ''}',
          challengeId: msg['session_id']?.toString(),
        );
      }
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

    // 3. Периодический опрос pending-запросов и сессий поддержки (fallback при временном обрыве WS)
    _pollingTimer?.cancel();
    _pollingTimer = Timer.periodic(const Duration(seconds: 4), (_) async {
      if (isLoggedIn) {
        await loadPendingChallenges();
        await checkSupportSession();
        if (isEngineer) {
          await loadSupportQueue();
        }
      }
    });
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

    final deviceInfo = DeviceInfoPlugin();
    String deviceName = 'Device';
    String osVersion = '';
    String platform = 'unknown';

    if (!kIsWeb) {
      try {
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
        } else if (Platform.isMacOS) {
          platform = 'macos';
          final mInfo = await deviceInfo.macOsInfo;
          deviceName = mInfo.computerName;
          osVersion = 'macOS ${mInfo.majorVersion}.${mInfo.minorVersion}';
        } else if (Platform.isLinux) {
          platform = 'linux';
          final lInfo = await deviceInfo.linuxInfo;
          deviceName = lInfo.name;
          osVersion = 'Linux';
        }
      } catch (_) {}
    }

    final initialPosture = await telemetry.collectPosture();

    final resp = await api!.login(
      username: username,
      password: password,
      deviceName: deviceName,
      platform: platform,
      osVersion: osVersion,
      appVersion: '1.0.1+5',
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
    _pollingTimer?.cancel();
    _pollingTimer = null;
    try {
      await api?.logout();
    } catch (_) {}

    ws.disconnect();
    telemetry.stopReporting();
    support.stopScreenSharing();

    token = null;
    currentUser = null;
    api = null;
    activePrompt = null;
    activeSupportPrompt = null;
    pendingChallenges.clear();
    allowedApps.clear();
    history.clear();
    supportQueue.clear();

    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('auth_token');
    notifyListeners();
  }

  Future<void> refreshAll() async {
    if (!isLoggedIn) return;
    final tasks = <Future>[
      loadPendingChallenges(),
      loadAllowedApps(),
      loadHistory(),
      checkPosture(),
      checkSupportSession(),
    ];
    if (isEngineer) {
      tasks.add(loadSupportQueue());
    }
    await Future.wait(tasks);
  }

  /// Загрузка очереди входящих обращений на поддержку (для инженеров)
  Future<void> loadSupportQueue() async {
    if (api == null || !isEngineer) return;
    try {
      supportQueue = await api!.getSupportQueue();
      notifyListeners();
    } catch (e) {
      debugPrint('auth_state: ошибка загрузки очереди поддержки: $e');
    }
  }

  /// Подключение инженера к удаленной сессии пользователя
  Future<Map<String, dynamic>> connectToSupportSession(String sessionId) async {
    if (api == null) throw Exception('API не инициализирован');
    final adminName = currentUser?['display_name'] ?? currentUser?['username'] ?? 'Инженер поддержки';
    final res = await api!.connectToSupport(sessionId: sessionId, adminName: adminName);
    await loadSupportQueue();
    return res;
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

  /// Отправка SOS-заявки на удаленный доступ
  Future<void> requestSupport({
    required String category,
    required String problemSummary,
    String accessMode = 'full_control',
  }) async {
    if (api == null) throw Exception('API не инициализирован');
    final resp = await api!.requestSupport(
      category: category,
      problemSummary: problemSummary,
      accessMode: accessMode,
    );
    final sessId = resp['id']?.toString() ?? '';
    support.setRequested(
      sessionId: sessId,
      category: category,
      problemSummary: problemSummary,
      accessMode: accessMode,
    );
    notifyListeners();
  }

  /// Подтверждение удаленного доступа инженеру (approve) с проверкой контрольного числа
  Future<void> confirmSupport({
    required String sessionId,
    String? numberMatch,
  }) async {
    if (api == null) throw Exception('API не инициализирован');
    activeSupportPrompt = null;
    await alert.resetWindowPriority();

    // 1. Биометрия / Windows Hello при политике GPO
    if (gpo.requireWindowsHello) {
      final didAuth = await localAuth.authenticate(
        localizedReason: 'Подтвердите разрешение удаленного доступа к экрану',
        options: const AuthenticationOptions(biometricOnly: false, stickyAuth: true),
      );
      if (!didAuth) {
        throw Exception('Биометрическая авторизация отклонена');
      }
    }

    // 2. Отправка одобрения на сервер
    await api!.supportDecision(
      sessionId: sessionId,
      decision: 'approve',
      numberMatch: numberMatch,
    );

    // 3. Запуск трансляции экрана WebRTC
    await support.startScreenSharing(
      sessionId: sessionId,
      api: api!,
      accessMode: support.accessMode,
    );
    notifyListeners();
  }

  /// Отклонение входящего запроса на подключение (deny)
  Future<void> rejectSupport({
    required String sessionId,
  }) async {
    if (api == null) return;
    activeSupportPrompt = null;
    await alert.resetWindowPriority();

    try {
      await api!.supportDecision(
        sessionId: sessionId,
        decision: 'deny',
      );
    } catch (_) {}
    await support.stopScreenSharing();
    notifyListeners();
  }

  bool _isEndingSupport = false;

  /// Завершение сеанса удаленного доступа со стороны пользователя
  Future<void> endSupport() async {
    if (_isEndingSupport) return;
    _isEndingSupport = true;
    try {
      final sessId = support.activeSessionId;
      if (sessId != null && api != null) {
        try {
          await api!.endSupportSession(sessionId: sessId);
        } catch (e) {
          debugPrint('auth_state: ошибка завершения сессии поддержки: $e');
        }
      }
      await support.stopScreenSharing();
      activeSupportPrompt = null;
      notifyListeners();
    } finally {
      _isEndingSupport = false;
    }
  }

  /// Проверка наличия активной сессии поддержки на сервере (периодический поллинг)
  Future<void> checkSupportSession() async {
    if (api == null) return;
    try {
      final sess = await api!.getCurrentSupportSession();
      if (sess != null) {
        final status = sess['status']?.toString();
        final sessionId = sess['id']?.toString() ?? '';
        final category = sess['category']?.toString() ?? 'it';
        final summary = sess['problem_summary']?.toString() ?? '';
        final accessMode = sess['access_mode']?.toString() ?? 'full_control';

        if (status == 'connecting') {
          final numberMatch = sess['number_match']?.toString() ?? '';
          if (numberMatch.isNotEmpty && activeSupportPrompt == null && support.state != SupportSessionState.active) {
            activeSupportPrompt = {
              'session_id': sessionId,
              'category': category,
              'problem_summary': summary,
              'number_match': numberMatch,
              'access_mode': accessMode,
              'admin_name': sess['admin_name'] ?? 'Инженер техподдержки',
            };
            support.setAuthorizing(
              sessionId: sessionId,
              category: category,
              problemSummary: summary,
              accessMode: accessMode,
            );
            final cat = category == '1c' ? '1С-поддержка' : 'IT-служба';
            alert.triggerAlert(
              title: 'Удаленная помощь: $cat',
              body: 'Инженер готов подключиться к экрану. Подтвердите контрольное число.',
              challengeId: sessionId,
            );
            notifyListeners();
          }
        } else if (status == 'requested') {
          if (support.state != SupportSessionState.requested) {
            support.setRequested(
              sessionId: sessionId,
              category: category,
              problemSummary: summary,
              accessMode: accessMode,
            );
            notifyListeners();
          }
        } else if (status == 'ended' || status == 'rejected') {
          if (support.state != SupportSessionState.idle) {
            await support.stopScreenSharing();
          }
          if (activeSupportPrompt != null) {
            activeSupportPrompt = null;
            notifyListeners();
          }
        }
      } else {
        if (support.state == SupportSessionState.requested ||
            support.state == SupportSessionState.authorizing) {
          await support.stopScreenSharing();
          activeSupportPrompt = null;
          notifyListeners();
        }
      }
    } catch (_) {}
  }

  @override
  void dispose() {
    _pollingTimer?.cancel();
    ws.disconnect();
    telemetry.stopReporting();
    support.stopScreenSharing();
    super.dispose();
  }
}
