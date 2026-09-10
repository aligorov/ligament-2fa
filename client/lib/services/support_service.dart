import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';

import '../api/client.dart';
import 'input_injector.dart';
import 'telemetry_service.dart';

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

  List<Map<String, dynamic>> _screens = [];
  String? _currentScreenId;
  Timer? _telemetryTimer;
  final TelemetryService _telemetry = TelemetryService();

  SupportSessionState get state => _state;
  String? get activeSessionId => _activeSessionId;
  String? get category => _category;
  String? get problemSummary => _problemSummary;
  String get accessMode => _accessMode;
  bool get isSharing => _state == SupportSessionState.active;
  List<Map<String, dynamic>> get screens => _screens;
  String? get currentScreenId => _currentScreenId;

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
          {'urls': 'stun:stun.cloudflare.com:3478'},
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
          _startPeriodicTelemetry();
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

      // Захват экрана: получение списка всех мониторов на десктопе
      MediaStream screenStream;
      if (!kIsWeb && (Platform.isWindows || Platform.isLinux || Platform.isMacOS)) {
        final sources = await desktopCapturer.getSources(types: [SourceType.Screen]);
        if (sources.isEmpty) {
          throw Exception('Не найдены источники экрана для захвата');
        }
        _screens = sources.map((s) => {'id': s.id, 'name': s.name}).toList();
        final selectedSource = sources.first;
        _currentScreenId = selectedSource.id;

        debugPrint('support_service: найдено ${_screens.length} экранов, активен: ${selectedSource.name}');
        screenStream = await navigator.mediaDevices.getDisplayMedia(<String, dynamic>{
          'audio': false,
          'video': {
            'deviceId': {'exact': selectedSource.id},
            'mandatory': {'frameRate': 25.0},
          },
        });
      } else {
        // Мобильные платформы и Web
        screenStream = await navigator.mediaDevices.getDisplayMedia(<String, dynamic>{
          'audio': false,
          'video': true,
        });
      }
      _localStream = screenStream;

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

  final List<RTCIceCandidate> _pendingCandidates = [];

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
        while (_pendingCandidates.isNotEmpty) {
          final c = _pendingCandidates.removeAt(0);
          try {
            await _peerConnection!.addCandidate(c);
          } catch (e) {
            debugPrint('support_service: ошибка flush ICE: $e');
          }
        }
      } else if (payload.containsKey('candidate')) {
        final cMap = payload['candidate'] as Map<String, dynamic>;
        final candidate = RTCIceCandidate(
          cMap['candidate']?.toString(),
          cMap['sdpMid']?.toString(),
          cMap['sdpMLineIndex'] as int?,
        );
        final remoteDesc = await _peerConnection!.getRemoteDescription();
        if (remoteDesc == null || remoteDesc.type == null || remoteDesc.type!.isEmpty) {
          _pendingCandidates.add(candidate);
        } else {
          await _peerConnection!.addCandidate(candidate);
        }
      }
    } catch (e) {
      debugPrint('support_service: ошибка обработки входящего сигнала: $e');
    }
  }

  void _setupDataChannel(RTCDataChannel channel) {
    _dataChannel = channel;
    channel.onDataChannelState = (RTCDataChannelState st) {
      if (st == RTCDataChannelState.RTCDataChannelOpen) {
        _sendScreenList();
        _sendCurrentTelemetry();
      }
    };
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

  void _sendScreenList() {
    if (_dataChannel == null || _dataChannel!.state != RTCDataChannelState.RTCDataChannelOpen) return;
    try {
      _dataChannel!.send(RTCDataChannelMessage(jsonEncode({
        'type': 'screen_list',
        'screens': _screens,
        'selected_id': _currentScreenId,
      })));
    } catch (_) {}
  }

  /// Переключение транслируемого монитора на лету
  Future<void> switchScreen(String screenId) async {
    if (kIsWeb || _peerConnection == null) return;
    try {
      final newStream = await navigator.mediaDevices.getDisplayMedia(<String, dynamic>{
        'audio': false,
        'video': {
          'deviceId': {'exact': screenId},
          'mandatory': {'frameRate': 25.0},
        },
      });

      final newVideoTracks = newStream.getVideoTracks();
      if (newVideoTracks.isEmpty) return;
      final newTrack = newVideoTracks.first;

      final senders = await _peerConnection!.getSenders();
      for (final sender in senders) {
        if (sender.track?.kind == 'video') {
          await sender.replaceTrack(newTrack);
          break;
        }
      }

      _localStream?.getVideoTracks().forEach((t) => t.stop());
      _localStream?.dispose();
      _localStream = newStream;
      _currentScreenId = screenId;

      _sendScreenList();
      notifyListeners();
    } catch (e) {
      debugPrint('support_service: ошибка переключения экрана: $e');
    }
  }

  void _startPeriodicTelemetry() {
    _telemetryTimer?.cancel();
    _telemetryTimer = Timer.periodic(const Duration(seconds: 4), (_) {
      _sendCurrentTelemetry();
    });
  }

  Future<void> _sendCurrentTelemetry() async {
    if (_dataChannel == null || _dataChannel!.state != RTCDataChannelState.RTCDataChannelOpen) return;
    try {
      final cpu = await _telemetry.collectCpuMetrics();
      final disk = await _telemetry.collectDiskMetrics();
      final payload = {
        'type': 'telemetry',
        ...cpu,
        ...disk,
      };
      _dataChannel!.send(RTCDataChannelMessage(jsonEncode(payload)));
    } catch (_) {}
  }

  /// Эмуляция пользовательского ввода от оператора (мышь/клавиатура/хоткеи/буфер)
  void _handleRemoteInput(Map<String, dynamic> input) async {
    final type = (input['type'] ?? input['action'])?.toString();
    if (type == null) return;

    // Команды, разрешенные даже в режиме просмотра (например, запрос списка экранов или буфер обмена)
    if (type == 'screen_list') {
      _sendScreenList();
      return;
    } else if (type == 'switch_screen') {
      final sId = input['screen_id']?.toString();
      if (sId != null && sId.isNotEmpty) {
        await switchScreen(sId);
      }
      return;
    } else if (type == 'clipboard_set') {
      final text = input['text']?.toString() ?? '';
      await Clipboard.setData(ClipboardData(text: text));
      return;
    } else if (type == 'clipboard_get') {
      final clip = await Clipboard.getData(Clipboard.kTextPlain);
      if (_dataChannel != null && _dataChannel!.state == RTCDataChannelState.RTCDataChannelOpen) {
        _dataChannel!.send(RTCDataChannelMessage(jsonEncode({
          'type': 'clipboard_data',
          'text': clip?.text ?? '',
        })));
      }
      return;
    }

    if (_accessMode != 'full_control') {
      // Режим «Только просмотр» блокирует все команды управления
      return;
    }

    try {
      switch (type) {
        case 'mouse_move':
          final x = (input['x'] as num?)?.toDouble() ?? 0.0;
          final y = (input['y'] as num?)?.toDouble() ?? 0.0;
          InputInjector.instance.moveMouse(x, y);
          break;
        case 'mouse_down':
        case 'mouse_up':
        case 'mouse_click':
          final btn = (input['button'] as num?)?.toInt() ?? 0;
          final x = (input['x'] as num?)?.toDouble() ?? 0.0;
          final y = (input['y'] as num?)?.toDouble() ?? 0.0;
          final act = type == 'mouse_down' ? 'down' : (type == 'mouse_up' ? 'up' : 'click');
          InputInjector.instance.mouseAction(action: act, button: btn, normX: x, normY: y);
          break;
        case 'wheel':
          final dy = (input['deltaY'] as num?)?.toDouble() ?? 0.0;
          InputInjector.instance.mouseWheel(dy);
          break;
        case 'key_down':
        case 'key_up':
          final key = input['key']?.toString() ?? '';
          final code = (input['keyCode'] as num?)?.toInt();
          final act = type == 'key_down' ? 'down' : 'up';
          InputInjector.instance.keyAction(action: act, key: key, keyCode: code);
          break;
        case 'block_input':
          final blocked = input['blocked'] == true || input['enabled'] == true;
          InputInjector.instance.setInputBlocked(blocked);
          break;
        case 'hotkey':
          final hotkey = (input['action'] ?? input['hotkey'])?.toString() ?? '';
          if (hotkey.isNotEmpty) {
            await InputInjector.instance.triggerHotkey(hotkey);
          }
          break;
      }
    } catch (e) {
      debugPrint('support_service: ошибка выполнения ввода: $e');
    }
  }

  /// Остановка трансляции экрана и освобождение ресурсов
  void stopScreenSharing() {
    _telemetryTimer?.cancel();
    _telemetryTimer = null;
    InputInjector.instance.setInputBlocked(false);

    _pendingCandidates.clear();
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
    _screens.clear();
    _currentScreenId = null;
    _api = null;
    notifyListeners();
  }

  @override
  void dispose() {
    stopScreenSharing();
    super.dispose();
  }
}
