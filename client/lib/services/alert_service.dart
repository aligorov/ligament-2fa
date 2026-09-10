import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:audioplayers/audioplayers.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:window_manager/window_manager.dart';
import 'gpo_service.dart';

/// Сервис оповещений и форсированного вывода окна при входящих push-запросах.
class AlertService {
  final GPOService _gpo = GPOService();
  final AudioPlayer _audioPlayer = AudioPlayer();
  final FlutterLocalNotificationsPlugin _localNotifications =
      FlutterLocalNotificationsPlugin();

  bool _initialized = false;

  Future<void> init() async {
    if (_initialized) return;

    if (!kIsWeb && (Platform.isAndroid || Platform.isIOS)) {
      const androidInit = AndroidInitializationSettings('@mipmap/ic_launcher');
      const iosInit = DarwinInitializationSettings(
        requestAlertPermission: true,
        requestBadgePermission: true,
        requestSoundPermission: true,
      );
      await _localNotifications.initialize(
        const InitializationSettings(android: androidInit, iOS: iosInit),
      );
    }

    _initialized = true;
  }

  /// Сигнализация о входящем запросе авторизации:
  /// 1. Вывод окна на передний план (AlwaysOnTop + Focus).
  /// 2. Мигание на панели задач (FlashWindow).
  /// 3. Звуковой сигнал оповещения.
  /// 4. Мобильный Full-Screen Intent / High Priority Notification.
  Future<void> triggerAlert({
    required String title,
    required String body,
    String? challengeId,
  }) async {
    await init();

    if (!kIsWeb && (Platform.isWindows || Platform.isMacOS || Platform.isLinux)) {
      try {
        // Показываем окно и разворачиваем, если было скрыто/минимизировано в трей
        await windowManager.show();
        await windowManager.focus();

        if (_gpo.alwaysOnTop) {
          await windowManager.setAlwaysOnTop(true);
        }

        if (_gpo.flashTaskbar && Platform.isWindows) {
          // Выделяем окно на панели задач Windows (progress indicator)
          await windowManager.setProgressBar(1.0);
        }
      } catch (e) {
        debugPrint('alert_service: ошибка управления окном: $e');
      }

      if (_gpo.playSound) {
        try {
          await _audioPlayer.play(AssetSource('sounds/alert.mp3'));
        } catch (_) {
          // Если файл звука недоступен, продолжаем без краша
        }
      }
    } else if (!kIsWeb && (Platform.isAndroid || Platform.isIOS)) {
      const androidDetails = AndroidNotificationDetails(
        'push_challenges_channel',
        'Входящие подтверждения входа',
        channelDescription: 'Срочные push-запросы 2FA с подтверждением доступа',
        importance: Importance.max,
        priority: Priority.high,
        fullScreenIntent: true,
        category: AndroidNotificationCategory.alarm,
      );
      const iosDetails = DarwinNotificationDetails(
        presentAlert: true,
        presentBadge: true,
        presentSound: true,
        interruptionLevel: InterruptionLevel.timeSensitive,
      );
      await _localNotifications.show(
        0,
        title,
        body,
        const NotificationDetails(android: androidDetails, iOS: iosDetails),
        payload: challengeId,
      );
    }
  }

  /// Оповещение о новом сообщении в чате поддержки
  Future<void> triggerChatNotification({
    required String sender,
    required String message,
  }) async {
    await init();

    if (!kIsWeb && (Platform.isWindows || Platform.isMacOS || Platform.isLinux)) {
      try {
        if (Platform.isWindows) {
          await windowManager.setProgressBar(1.0);
        }
      } catch (_) {}

      try {
        await _audioPlayer.play(AssetSource('sounds/alert.mp3'));
      } catch (_) {}
    } else if (!kIsWeb && (Platform.isAndroid || Platform.isIOS)) {
      const androidDetails = AndroidNotificationDetails(
        'chat_messages_channel',
        'Чат технической поддержки',
        channelDescription: 'Сообщения от инженера поддержки',
        importance: Importance.high,
        priority: Priority.high,
      );
      const iosDetails = DarwinNotificationDetails(
        presentAlert: true,
        presentBadge: true,
        presentSound: true,
      );
      await _localNotifications.show(
        1001,
        sender.isNotEmpty ? 'Сообщение от: $sender' : 'Новое сообщение в чате',
        message,
        const NotificationDetails(android: androidDetails, iOS: iosDetails),
      );
    }
  }

  /// Сброс AlwaysOnTop и индикатора на таскбаре после завершения обработки запроса
  Future<void> resetWindowPriority() async {
    if (!kIsWeb && (Platform.isWindows || Platform.isMacOS)) {
      try {
        await windowManager.setAlwaysOnTop(false);
        if (Platform.isWindows) {
          await windowManager.setProgressBar(-1);
        }
      } catch (_) {}
    }
  }
}
