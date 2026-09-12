import 'dart:convert';
import 'package:http/http.dart' as http;

class ApiException implements Exception {
  final int statusCode;
  final String code;
  final String message;

  ApiException(this.statusCode, this.code, [this.message = '']);

  @override
  String toString() => 'ApiException($statusCode, $code, $message)';
}

class ApiClient {
  /// Максимальное время выполнения любого HTTP-запроса.
  /// Защищает UI от вечного спиннера при сетевых проблемах.
  static const Duration _requestTimeout = Duration(seconds: 10);

  String baseUrl;
  String? token;

  ApiClient({required this.baseUrl, this.token});

  Future<http.Response> _get(String url, {Map<String, String>? headers}) {
    return http.get(Uri.parse(url), headers: headers).timeout(_requestTimeout);
  }

  Future<http.Response> _post(String url, {Map<String, String>? headers, String? body}) {
    return http
        .post(Uri.parse(url), headers: headers, body: body)
        .timeout(_requestTimeout);
  }

  String _cleanUrl(String path) {
    var base = baseUrl.trim();
    if (base.endsWith('/')) {
      base = base.substring(0, base.length - 1);
    }
    if (!path.startsWith('/')) {
      path = '/$path';
    }
    return '$base$path';
  }

  Map<String, String> _headers() {
    final h = <String, String>{
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };
    if (token != null && token!.isNotEmpty) {
      h['Authorization'] = 'Bearer $token';
    }
    return h;
  }

  /// Получение базовой конфигурации сервера
  Future<Map<String, dynamic>> getConfig() async {
    final res = await _get(_cleanUrl('/api/v1/app/config'));
    if (res.statusCode == 200) {
      return jsonDecode(utf8.decode(res.bodyBytes)) as Map<String, dynamic>;
    }
    throw ApiException(res.statusCode, 'config_error');
  }

  /// Авторизация устройства в приложении
  Future<Map<String, dynamic>> login({
    required String username,
    required String password,
    String? code,
    required String deviceName,
    required String platform,
    String osVersion = '',
    String appVersion = '1.0.1',
    String pushToken = '',
    Map<String, dynamic>? securityPosture,
  }) async {
    final payload = {
      'username': username,
      'password': password,
      if (code != null && code.trim().isNotEmpty) 'code': code.trim(),
      'device_name': deviceName,
      'platform': platform,
      'os_version': osVersion,
      'app_version': appVersion,
      'push_token': pushToken,
      'security_posture': securityPosture ?? {},
    };

    final res = await _post(
      _cleanUrl('/api/v1/app/login'),
      headers: _headers(),
      body: jsonEncode(payload),
    );

    final data = jsonDecode(utf8.decode(res.bodyBytes)) as Map<String, dynamic>;
    if (res.statusCode == 200) {
      token = data['token'] as String?;
      return data;
    }
    throw ApiException(res.statusCode, data['error']?.toString() ?? 'login_failed');
  }

  /// Выход устройства (деактивация сессии)
  Future<void> logout() async {
    try {
      await _post(
        _cleanUrl('/api/v1/app/logout'),
        headers: _headers(),
      );
    } finally {
      token = null;
    }
  }

  /// Обновление APNs/FCM push-токена
  Future<void> updatePushToken(String pushToken) async {
    final res = await _post(
      _cleanUrl('/api/v1/app/device/push-token'),
      headers: _headers(),
      body: jsonEncode({'push_token': pushToken}),
    );
    if (res.statusCode != 200) {
      throw ApiException(res.statusCode, 'push_token_update_failed');
    }
  }

  /// Передача снимка безопасности (телеметрии) устройства
  Future<bool> sendTelemetry(Map<String, dynamic> posture) async {
    final res = await _post(
      _cleanUrl('/api/v1/app/telemetry'),
      headers: _headers(),
      body: jsonEncode({'security_posture': posture}),
    );
    if (res.statusCode == 200) {
      final data = jsonDecode(utf8.decode(res.bodyBytes)) as Map<String, dynamic>;
      return data['is_compliant'] == true;
    }
    throw ApiException(res.statusCode, 'telemetry_failed');
  }

  /// Получение активных запросов на подтверждение входа
  Future<List<Map<String, dynamic>>> getPendingChallenges() async {
    final res = await _get(
      _cleanUrl('/api/v1/app/challenges/pending'),
      headers: _headers(),
    );
    if (res.statusCode == 200) {
      final list = jsonDecode(utf8.decode(res.bodyBytes)) as List<dynamic>;
      return list.cast<Map<String, dynamic>>();
    }
    throw ApiException(res.statusCode, 'challenges_fetch_failed');
  }

  /// Принятие решения по запросу авторизации: approve или deny
  Future<void> challengeDecision({
    required String challengeId,
    required String decision,
    String? numberMatch,
  }) async {
    final payload = <String, dynamic>{
      'decision': decision,
    };
    if (numberMatch != null && numberMatch.isNotEmpty) {
      payload['number_match'] = numberMatch;
    }

    final res = await _post(
      _cleanUrl('/api/v1/app/challenges/$challengeId/decision'),
      headers: _headers(),
      body: jsonEncode(payload),
    );

    if (res.statusCode != 200) {
      String code = 'decision_failed';
      try {
        final errObj = jsonDecode(utf8.decode(res.bodyBytes));
        code = errObj['error']?.toString() ?? code;
      } catch (_) {}
      throw ApiException(res.statusCode, code);
    }
  }

  /// Профиль текущего пользователя
  Future<Map<String, dynamic>> getProfile() async {
    final res = await _get(
      _cleanUrl('/api/v1/app/me/profile'),
      headers: _headers(),
    );
    if (res.statusCode == 200) {
      return jsonDecode(utf8.decode(res.bodyBytes)) as Map<String, dynamic>;
    }
    throw ApiException(res.statusCode, 'profile_fetch_failed');
  }

  /// Список доступных корпоративных приложений (SSO Launchpad)
  Future<List<Map<String, dynamic>>> getAllowedApps() async {
    final res = await _get(
      _cleanUrl('/api/v1/app/me/apps'),
      headers: _headers(),
    );
    if (res.statusCode == 200) {
      final list = jsonDecode(utf8.decode(res.bodyBytes)) as List<dynamic>;
      return list.cast<Map<String, dynamic>>();
    }
    throw ApiException(res.statusCode, 'apps_fetch_failed');
  }

  /// История недавних входов пользователя (аудит-лог)
  Future<List<Map<String, dynamic>>> getHistory() async {
    final res = await _get(
      _cleanUrl('/api/v1/app/me/history'),
      headers: _headers(),
    );
    if (res.statusCode == 200) {
      final list = jsonDecode(utf8.decode(res.bodyBytes)) as List<dynamic>;
      return list.cast<Map<String, dynamic>>();
    }
    throw ApiException(res.statusCode, 'history_fetch_failed');
  }

  /// Запрос экстренной удаленной помощи (SOS)
  Future<Map<String, dynamic>> requestSupport({
    required String category,
    required String problemSummary,
    String accessMode = 'full_control',
  }) async {
    final payload = {
      'category': category,
      'problem_summary': problemSummary,
      'access_mode': accessMode,
    };

    final res = await _post(
      _cleanUrl('/api/v1/app/support/request'),
      headers: _headers(),
      body: jsonEncode(payload),
    );

    final data = jsonDecode(utf8.decode(res.bodyBytes)) as Map<String, dynamic>;
    if (res.statusCode == 200) {
      return data;
    }
    throw ApiException(res.statusCode, data['error']?.toString() ?? 'support_request_failed');
  }

  /// Получение текущей активной сессии поддержки
  Future<Map<String, dynamic>?> getCurrentSupportSession() async {
    final res = await _get(
      _cleanUrl('/api/v1/app/support/current'),
      headers: _headers(),
    );
    if (res.statusCode == 200) {
      final data = jsonDecode(utf8.decode(res.bodyBytes)) as Map<String, dynamic>;
      if (data['active'] == true) {
        return data['session'] as Map<String, dynamic>?;
      }
      return null;
    }
    throw ApiException(res.statusCode, 'support_current_fetch_failed');
  }

  /// Решение пользователя по запросу на подключение к экрану (approve / deny)
  Future<void> supportDecision({
    required String sessionId,
    required String decision,
    String? numberMatch,
  }) async {
    final payload = <String, dynamic>{
      'decision': decision,
    };
    if (numberMatch != null && numberMatch.isNotEmpty) {
      payload['number_match'] = numberMatch;
    }

    final res = await _post(
      _cleanUrl('/api/v1/app/support/$sessionId/decision'),
      headers: _headers(),
      body: jsonEncode(payload),
    );

    if (res.statusCode != 200) {
      String code = 'decision_failed';
      try {
        final errObj = jsonDecode(utf8.decode(res.bodyBytes));
        code = errObj['error']?.toString() ?? code;
      } catch (_) {}
      throw ApiException(res.statusCode, code);
    }
  }

  /// Отправка WebRTC сигнального пакета оператору поддержки
  Future<void> sendSupportSignal({
    required String sessionId,
    required Map<String, dynamic> signal,
  }) async {
    final res = await _post(
      _cleanUrl('/api/v1/app/support/$sessionId/signal'),
      headers: _headers(),
      body: jsonEncode(signal),
    );
    if (res.statusCode != 200) {
      throw ApiException(res.statusCode, 'signal_failed');
    }
  }

  /// Получение истории сообщений чата сессии поддержки
  Future<List<Map<String, dynamic>>> getSupportMessages(String sessionId) async {
    http.Response res;
    try {
      res = await _get(
        _cleanUrl('/api/v1/app/support/$sessionId/messages'),
        headers: _headers(),
      );
    } catch (_) {
      res = await _get(
        _cleanUrl('/api/v1/support/sessions/$sessionId/messages'),
        headers: _headers(),
      );
    }
    if (res.statusCode != 200) {
      res = await _get(
        _cleanUrl('/api/v1/support/sessions/$sessionId/messages'),
        headers: _headers(),
      );
    }
    if (res.statusCode != 200) {
      return [];
    }
    final data = jsonDecode(utf8.decode(res.bodyBytes));
    if (data is Map<String, dynamic> && data['messages'] is List) {
      return (data['messages'] as List)
          .whereType<Map<String, dynamic>>()
          .toList();
    }
    if (data is List) {
      return data.whereType<Map<String, dynamic>>().toList();
    }
    return [];
  }

  /// Отправка сообщения в чат поддержки
  Future<void> sendSupportChatMessage({
    required String sessionId,
    required String text,
    String? senderName,
  }) async {
    final body = jsonEncode({
      'text': text,
      if (senderName != null && senderName.isNotEmpty) 'sender_name': senderName,
    });
    http.Response res;
    try {
      res = await _post(
        _cleanUrl('/api/v1/app/support/$sessionId/messages'),
        headers: _headers(),
        body: body,
      );
      if (res.statusCode != 200) {
        res = await _post(
          _cleanUrl('/api/v1/support/sessions/$sessionId/messages'),
          headers: _headers(),
          body: body,
        );
      }
    } catch (_) {
      res = await _post(
        _cleanUrl('/api/v1/support/sessions/$sessionId/messages'),
        headers: _headers(),
        body: body,
      );
    }
    if (res.statusCode != 200) {
      // Fallback на /signal
      await sendSupportSignal(
        sessionId: sessionId,
        signal: {
          'type': 'chat_message',
          'text': text,
          'sender_name': senderName ?? 'Пользователь',
        },
      );
    }
  }

  /// Завершение сеанса удаленного доступа со стороны пользователя
  Future<void> endSupportSession({
    required String sessionId,
  }) async {
    final res = await _post(
      _cleanUrl('/api/v1/app/support/$sessionId/end'),
      headers: _headers(),
    ).timeout(const Duration(seconds: 4));
    if (res.statusCode != 200) {
      throw ApiException(res.statusCode, 'end_support_failed');
    }
  }

  /// Получение активных категорий поддержки (IT, 1C и др.)
  Future<List<Map<String, dynamic>>> getSupportCategories() async {
    final res = await _get(
      _cleanUrl('/api/v1/app/support/categories'),
      headers: _headers(),
    );
    if (res.statusCode == 200) {
      final data = jsonDecode(utf8.decode(res.bodyBytes)) as Map<String, dynamic>;
      final list = data['categories'] as List<dynamic>? ?? [];
      return list.cast<Map<String, dynamic>>();
    }
    return [];
  }

  /// Получение очереди входящих SOS-обращений для инженера
  Future<List<Map<String, dynamic>>> getSupportQueue() async {
    final res = await _get(
      _cleanUrl('/api/v1/app/support/queue'),
      headers: _headers(),
    );
    if (res.statusCode == 200) {
      final decoded = jsonDecode(utf8.decode(res.bodyBytes));
      if (decoded is List) {
        return decoded.map((e) => Map<String, dynamic>.from(e as Map)).toList();
      } else if (decoded is Map) {
        final list = (decoded['queue'] ?? decoded['sessions']) as List<dynamic>? ?? [];
        return list.map((e) => Map<String, dynamic>.from(e as Map)).toList();
      }
    }
    return [];
  }

  /// Инициация подключения инженера к удаленной сессии из приложения
  Future<Map<String, dynamic>> connectToSupport({
    required String sessionId,
    String? adminName,
  }) async {
    final payload = <String, dynamic>{};
    if (adminName != null && adminName.isNotEmpty) {
      payload['admin_name'] = adminName;
    }
    final res = await _post(
      _cleanUrl('/api/v1/app/support/$sessionId/connect'),
      headers: _headers(),
      body: jsonEncode(payload),
    );
    if (res.statusCode == 200) {
      return jsonDecode(utf8.decode(res.bodyBytes)) as Map<String, dynamic>;
    }
    throw ApiException(res.statusCode, 'connect_failed');
  }
}
