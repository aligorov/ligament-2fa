import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';

import '../api/client.dart';

enum SupportSessionState {
  idle,
  requested,
  authorizing,
  active,
  ended,
}

/// Сервис управления WebRTC экраном и вводом для удаленной поддержки (SOS).
class SupportService extends ChangeNotifier {
  SupportSessionState _state = SupportSessionState.idle;
  String? _activeSessionId;
  String? _category;
  String? _problemSummary;
  String _accessMode = 'full_control';

  RTCPeerConnection? _peerConnection;
  MediaStream? _localStream;
  RTCDataChannel? _dataChannel;
  ApiClient? _api;

  SupportSessionState get state => _state;
  String? get activeSessionId => _activeSessionId;
  String? get category => _category;
  String? get problemSummary => _problemSummary;
  String get accessMode => _accessMode;
  bool get isSharing => _state == SupportSessionState.active;

  /// Установка локального состояния запроса
  void setRequested({
    required String sessionId,
    required String category,
    required String problemSummary,
    String accessMode = 'full_control',
  }) {
    _activeSessionId = sessionId;
    _category = category;
    _problemSummary = problemSummary;
    _accessMode = accessMode;
    _state = SupportSessionState.requested;
    notifyListeners();
  }

  /// Установка состояния авторизации (когда оператор запросил подключение)
  void setAuthorizing({
    required String sessionId,
    String? category,
    String? problemSummary,
  }) {
    _activeSessionId = sessionId;
    if (category != null) _category = category;
    if (problemSummary != null) _problemSummary = problemSummary;
    _state = SupportSessionState.authorizing;
    notifyListeners();
  }

  /// Инициализация P2P WebRTC захвата экрана и отправка SDP Offer оператору
  Future<void> startScreenSharing({
    required String sessionId,
    required ApiClient api,
    String accessMode = 'full_control',
  }) async {
    _activeSessionId = sessionId;
    _api = api;
    _accessMode = accessMode;

    try {
      final rtcConfig = <String, dynamic>{
        'iceServers': [
          {'urls': 'stun:stun.l.google.com:19302'},
          {'urls': 'stun:stun1.l.google.com:19302'},
        ],
        'sdpSemantics': 'unified-plan',
      };

      _peerConnection = await createPeerConnection(rtcConfig);

      // ICE кандидаты отправляются через серверный сигнальный шлюз оператору
      _peerConnection!.onIceCandidate = (candidate) {
        if (candidate.candidate != null && candidate.candidate!.isNotEmpty) {
          _api?.sendSupportSignal(
            sessionId: _activeSessionId!,
            signal: {
              'candidate': {
                'candidate': candidate.candidate,
                'sdpMid': candidate.sdpMid,
                'sdpMLineIndex': candidate.sdpMLineIndex,
              },
            },
          ).catchError((err) {
            debugPrint('support_service: ошибка отправки ICE: $err');
          });
        }
      };

      _peerConnection!.onConnectionState = (state) {
        debugPrint('support_service: WebRTC connection state: $state');
        if (state == RTCPeerConnectionState.RTCPeerConnectionStateConnected) {
          _state = SupportSessionState.active;
          notifyListeners();
        } else if (state == RTCPeerConnectionState.RTCPeerConnectionStateDisconnected ||
            state == RTCPeerConnectionState.RTCPeerConnectionStateFailed ||
            state == RTCPeerConnectionState.RTCPeerConnectionStateClosed) {
          if (_state == SupportSessionState.active) {
            stopScreenSharing();
          }
        }
      };

      // Канал данных для удаленного управления мышью и клавиатурой
      final dcInit = RTCDataChannelInit()..ordered = true;
      _dataChannel = await _peerConnection!.createDataChannel('input', dcInit);
      _setupDataChannel(_dataChannel!);

      _peerConnection!.onDataChannel = (channel) {
        _setupDataChannel(channel);
      };

      // Захват экрана
      final mediaConstraints = <String, dynamic>{
        'audio': false,
        'video': {
          'mandatory': {
            'minWidth': '1280',
            'minHeight': '720',
            'minFrameRate': '30',
          },
          'optional': [],
        },
      };

      _localStream = await navigator.mediaDevices.getDisplayMedia(mediaConstraints);

      for (final track in _localStream!.getVideoTracks()) {
        await _peerConnection!.addTrack(track, _localStream!);
      }

      // Создаем SDP Offer
      final offer = await _peerConnection!.createOffer({
        'offerToReceiveVideo': 0,
        'offerToReceiveAudio': 0,
      });

      await _peerConnection!.setLocalDescription(offer);

      // Отправляем оффер оператору
      await _api?.sendSupportSignal(
        sessionId: _activeSessionId!,
        signal: {
          'sdp': offer.toMap(),
        },
      );

      _state = SupportSessionState.active;
      notifyListeners();
    } catch (e) {
      debugPrint('support_service: ошибка инициализации захвата экрана: $e');
      stopScreenSharing();
      rethrow;
    }
  }

  /// Обработка сигнальных WebRTC пакетов от браузера оператора (Answer, Candidates)
  Future<void> handleRemoteSignal(Map<String, dynamic> signal) async {
    if (_peerConnection == null) return;

    try {
      final payload = (signal['data'] is Map<String, dynamic>)
          ? signal['data'] as Map<String, dynamic>
          : signal;

      if (payload.containsKey('sdp')) {
        final sdpMap = payload['sdp'] as Map<String, dynamic>;
        final desc = RTCSessionDescription(
          sdpMap['sdp']?.toString(),
          sdpMap['type']?.toString(),
        );
        await _peerConnection!.setRemoteDescription(desc);
      } else if (payload.containsKey('candidate')) {
        final cMap = payload['candidate'] as Map<String, dynamic>;
        final candidate = RTCIceCandidate(
          cMap['candidate']?.toString(),
          cMap['sdpMid']?.toString(),
          cMap['sdpMLineIndex'] as int?,
        );
        await _peerConnection!.addCandidate(candidate);
      }
    } catch (e) {
      debugPrint('support_service: ошибка обработки входящего сигнала: $e');
    }
  }

  void _setupDataChannel(RTCDataChannel channel) {
    _dataChannel = channel;
    channel.onMessage = (RTCDataChannelMessage msg) {
      if (msg.isBinary) return;
      try {
        final data = jsonDecode(msg.text) as Map<String, dynamic>;
        _handleRemoteInput(data);
      } catch (e) {
        debugPrint('support_service: ошибка разбора команды ввода: $e');
      }
    };
  }

  /// Эмуляция пользовательского ввода от оператора (мышь/клавиатура)
  void _handleRemoteInput(Map<String, dynamic> input) {
    if (_accessMode != 'full_control') {
      // Режим «Только просмотр» игнорирует входящие команды управления
      return;
    }

    final type = (input['type'] ?? input['action'])?.toString();
    if (type == null) return;

    // Ввод обрабатывается в зависимости от платформы (Windows / macOS / Linux / Android)
    if (!kIsWeb && Platform.isWindows) {
      _handleWindowsInput(type, input);
    } else {
      debugPrint('support_service: input event ($type): $input');
    }
  }

  void _handleWindowsInput(String type, Map<String, dynamic> input) {
    // Безопасная диспетчеризация событий мыши и клавиатуры
    try {
      switch (type) {
        case 'mouse_move':
          final x = (input['x'] as num?)?.toDouble() ?? 0;
          final y = (input['y'] as num?)?.toDouble() ?? 0;
          debugPrint('support_service: mouse move -> ($x, $y)');
          break;
        case 'mouse_down':
        case 'mouse_up':
          final btn = input['button'] ?? 0;
          debugPrint('support_service: mouse button $btn -> $type');
          break;
        case 'wheel':
          final dy = input['deltaY'] ?? 0;
          debugPrint('support_service: wheel -> $dy');
          break;
        case 'key_down':
        case 'key_up':
          final key = input['key'] ?? '';
          debugPrint('support_service: key $key -> $type');
          break;
      }
    } catch (e) {
      debugPrint('support_service: ошибка эмуляции ввода Windows: $e');
    }
  }

  /// Остановка трансляции экрана и освобождение ресурсов
  void stopScreenSharing() {
    try {
      _dataChannel?.close();
      _dataChannel = null;
    } catch (_) {}

    try {
      _localStream?.getTracks().forEach((track) {
        track.stop();
      });
      _localStream?.dispose();
      _localStream = null;
    } catch (_) {}

    try {
      _peerConnection?.close();
      _peerConnection?.dispose();
      _peerConnection = null;
    } catch (_) {}

    _state = SupportSessionState.idle;
    _activeSessionId = null;
    _category = null;
    _problemSummary = null;
    _api = null;
    notifyListeners();
  }

  @override
  void dispose() {
    stopScreenSharing();
    super.dispose();
  }
}
