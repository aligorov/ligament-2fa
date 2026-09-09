import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

typedef PushPromptCallback = void Function(Map<String, dynamic> prompt);

/// Сервис постоянного WebSocket соединения для мгновенных push-уведомлений.
class WebSocketService {
  WebSocketChannel? _channel;
  Timer? _reconnectTimer;
  Timer? _pingTimer;
  bool _disposed = false;

  PushPromptCallback? onPrompt;
  VoidCallback? onConnected;
  VoidCallback? onDisconnected;

  bool get isConnected => _channel != null;

  void connect({required String baseUrl, required String token}) {
    _disposed = false;
    _reconnectTimer?.cancel();

    var wsUrl = baseUrl.trim();
    if (wsUrl.startsWith('https://')) {
      wsUrl = 'wss://${wsUrl.substring(8)}';
    } else if (wsUrl.startsWith('http://')) {
      wsUrl = 'ws://${wsUrl.substring(7)}';
    }
    if (wsUrl.endsWith('/')) {
      wsUrl = wsUrl.substring(0, wsUrl.length - 1);
    }
    wsUrl = '$wsUrl/api/v1/app/ws?token=$token';

    try {
      final uri = Uri.parse(wsUrl);
      _channel = WebSocketChannel.connect(uri);
      onConnected?.call();

      _channel!.stream.listen(
        (message) {
          _handleMessage(message);
        },
        onDone: () {
          _channel = null;
          onDisconnected?.call();
          _scheduleReconnect(baseUrl: baseUrl, token: token);
        },
        onError: (err) {
          debugPrint('ws_service: ошибка соединения: $err');
          _channel = null;
          onDisconnected?.call();
          _scheduleReconnect(baseUrl: baseUrl, token: token);
        },
        cancelOnError: true,
      );

      _startPing();
    } catch (e) {
      debugPrint('ws_service: исключение при подключении: $e');
      _scheduleReconnect(baseUrl: baseUrl, token: token);
    }
  }

  void _handleMessage(dynamic message) {
    try {
      final text = message is String ? message : utf8.decode(message as List<int>);
      final data = jsonDecode(text) as Map<String, dynamic>;

      if (data['type'] == 'challenge_prompt') {
        onPrompt?.call(data);
      }
    } catch (e) {
      debugPrint('ws_service: ошибка парсинга сообщения: $e');
    }
  }

  void _startPing() {
    _pingTimer?.cancel();
    _pingTimer = Timer.periodic(const Duration(seconds: 25), (_) {
      try {
        _channel?.sink.add(jsonEncode({'type': 'ping'}));
      } catch (_) {}
    });
  }

  void _scheduleReconnect({required String baseUrl, required String token}) {
    if (_disposed) return;
    _reconnectTimer?.cancel();
    _reconnectTimer = Timer(const Duration(seconds: 3), () {
      if (!_disposed) {
        connect(baseUrl: baseUrl, token: token);
      }
    });
  }

  void disconnect() {
    _disposed = true;
    _reconnectTimer?.cancel();
    _pingTimer?.cancel();
    _channel?.sink.close();
    _channel = null;
  }
}
