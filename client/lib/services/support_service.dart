import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';

import '../api/client.dart';
import 'input_injector.dart';
import 'telemetry_service.dart';

class SupportChatMessage {
  final String id;
  final String sender; // 'operator' | 'user'
  final String senderName;
  final String text;
  final DateTime timestamp;

  SupportChatMessage({
    required this.id,
    required this.sender,
    required this.senderName,
    required this.text,
    required this.timestamp,
  });

  Map<String, dynamic> toJson() => {
    'type': 'chat_message',
    'id': id,
    'sender': sender,
    'sender_name': senderName,
    'text': text,
    'timestamp': timestamp.millisecondsSinceEpoch,
  };

  factory SupportChatMessage.fromJson(Map<String, dynamic> json) {
    return SupportChatMessage(
      id: json['id']?.toString() ?? DateTime.now().millisecondsSinceEpoch.toString(),
      sender: json['sender']?.toString() ?? 'operator',
      senderName: json['sender_name']?.toString() ??
          (json['sender'] == 'operator' ? 'Инженер' : 'Пользователь'),
      text: json['text']?.toString() ?? '',
      timestamp: json['timestamp'] != null
          ? DateTime.fromMillisecondsSinceEpoch((json['timestamp'] as num).toInt())
          : DateTime.now(),
    );
  }
}

class ReceivedFileItem {
  final String id;
  final String filename;
  final String localPath;
  final int size;
  final DateTime receivedAt;

  ReceivedFileItem({
    required this.id,
    required this.filename,
    required this.localPath,
    required this.size,
    required this.receivedAt,
  });
}

class _ActiveFileDownload {
  final String id;
  final String filename;
  final int totalSize;
  final int totalChunks;
  final Map<int, List<int>> chunks = {};

  _ActiveFileDownload({
    required this.id,
    required this.filename,
    required this.totalSize,
    required this.totalChunks,
  });
}

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

  final List<SupportChatMessage> _chatMessages = [];
  int _unreadChatCount = 0;
  final List<ReceivedFileItem> _receivedFiles = [];
  final Map<String, _ActiveFileDownload> _activeDownloads = {};

  SupportSessionState get state => _state;
  String? get activeSessionId => _activeSessionId;
  String? get category => _category;
  String? get problemSummary => _problemSummary;
  String get accessMode => _accessMode;
  bool get isSharing => _state == SupportSessionState.active;
  List<Map<String, dynamic>> get screens => _screens;
  String? get currentScreenId => _currentScreenId;

  List<SupportChatMessage> get chatMessages => List.unmodifiable(_chatMessages);
  int get unreadChatCount => _unreadChatCount;
  List<ReceivedFileItem> get receivedFiles => List.unmodifiable(_receivedFiles);
  void Function(SupportChatMessage message)? onChatMessageReceived;

  void markChatAsRead() {
    _unreadChatCount = 0;
    notifyListeners();
  }

  void clearChat() {
    _chatMessages.clear();
    _unreadChatCount = 0;
    notifyListeners();
  }

  void sendChatMessage(String text, {String? senderName}) {
    if (text.trim().isEmpty) return;
    final msg = SupportChatMessage(
      id: 'msg_${DateTime.now().millisecondsSinceEpoch}',
      sender: 'user',
      senderName: senderName ?? 'Пользователь',
      text: text.trim(),
      timestamp: DateTime.now(),
    );
    _chatMessages.add(msg);
    notifyListeners();

    _sendSignalOrData(msg.toJson());
  }

  void _sendSignalOrData(Map<String, dynamic> data) {
    bool sent = false;
    if (_dataChannel != null && _dataChannel!.state == RTCDataChannelState.RTCDataChannelOpen) {
      try {
        _dataChannel!.send(RTCDataChannelMessage(jsonEncode(data)));
        sent = true;
      } catch (e) {
        debugPrint('support_service: ошибка отправки через DataChannel: $e');
      }
    }
    if (!sent && _api != null && _activeSessionId != null) {
      _api!.sendSupportSignal(sessionId: _activeSessionId!, signal: data);
    }
  }

  Future<void> sendFile(File file) async {
    if (!await file.exists()) return;
    final filename = file.uri.pathSegments.last;
    final bytes = await file.readAsBytes();
    final totalSize = bytes.length;
    const chunkSize = 32768; // 32 KB
    final totalChunks = (totalSize / chunkSize).ceil();
    final transferId = 'file_${DateTime.now().millisecondsSinceEpoch}';

    _sendSignalOrData({
      'type': 'file_start',
      'transfer_id': transferId,
      'filename': filename,
      'size': totalSize,
      'total_chunks': totalChunks,
      'sender': 'user',
    });

    for (int i = 0; i < totalChunks; i++) {
      final start = i * chunkSize;
      final end = (start + chunkSize > totalSize) ? totalSize : start + chunkSize;
      final chunkBytes = bytes.sublist(start, end);
      final b64 = base64Encode(chunkBytes);

      _sendSignalOrData({
        'type': 'file_chunk',
        'transfer_id': transferId,
        'chunk_index': i,
        'data': b64,
      });
      if (i % 10 == 0) {
        await Future.delayed(const Duration(milliseconds: 15));
      }
    }

    _sendSignalOrData({
      'type': 'file_end',
      'transfer_id': transferId,
    });

    _chatMessages.add(SupportChatMessage(
      id: 'sys_${DateTime.now().millisecondsSinceEpoch}',
      sender: 'user',
      senderName: 'Пользователь',
      text: '📎 Отправлен файл: $filename (${(totalSize / 1024).toStringAsFixed(1)} КБ)',
      timestamp: DateTime.now(),
    ));
    notifyListeners();
  }

  Future<void> _saveReceivedFile(_ActiveFileDownload dl) async {
    try {
      String downloadsPath = '';
      if (Platform.isWindows) {
        final profile = Platform.environment['USERPROFILE'] ?? 'C:\\Users\\Default';
        downloadsPath = '$profile\\Downloads\\LigamentSupport';
      } else if (Platform.isMacOS || Platform.isLinux) {
        final home = Platform.environment['HOME'] ?? '/tmp';
        downloadsPath = '$home/Downloads/LigamentSupport';
      } else {
        downloadsPath = '/sdcard/Download/LigamentSupport';
      }

      final dir = Directory(downloadsPath);
      if (!await dir.exists()) {
        await dir.create(recursive: true);
      }

      final safeName = dl.filename.replaceAll(RegExp(r'[\\/:*?"<>|]'), '_');
      final targetPath = '${dir.path}${Platform.pathSeparator}$safeName';
      final file = File(targetPath);

      final builder = BytesBuilder(copy: false);
      for (int i = 0; i < dl.totalChunks; i++) {
        if (dl.chunks.containsKey(i)) {
          builder.add(dl.chunks[i]!);
        }
      }
      await file.writeAsBytes(builder.takeBytes(), flush: true);

      final item = ReceivedFileItem(
        id: dl.id,
        filename: safeName,
        localPath: targetPath,
        size: dl.totalSize,
        receivedAt: DateTime.now(),
      );
      _receivedFiles.insert(0, item);

      final sysMsg = SupportChatMessage(
        id: 'sys_${DateTime.now().millisecondsSinceEpoch}',
        sender: 'operator',
        senderName: 'Система',
        text: '📁 Получен файл: $safeName (${(dl.totalSize / 1024).toStringAsFixed(1)} КБ)',
        timestamp: DateTime.now(),
      );
      _chatMessages.add(sysMsg);
      _unreadChatCount++;
      notifyListeners();
    } catch (e) {
      debugPrint('support_service: ошибка сохранения переданного файла: $e');
    }
  }

  /// Установка локального состояния запроса
  void setRequested({
    required String sessionId,
    required String category,
    required String problemSummary,
    String accessMode = 'full_control',
    ApiClient? api,
  }) {
    _activeSessionId = sessionId;
    if (api != null) _api = api;
    _category = category;
    _problemSummary = problemSummary;
    _accessMode = accessMode;
    _state = SupportSessionState.requested;
    _unreadChatCount = 0;
    _activeDownloads.clear();
    notifyListeners();
  }

  /// Установка состояния авторизации (когда оператор запросил подключение)
  void setAuthorizing({
    required String sessionId,
    String? category,
    String? problemSummary,
    String? accessMode,
    ApiClient? api,
  }) {
    _activeSessionId = sessionId;
    if (api != null) _api = api;
    if (category != null) _category = category;
    if (problemSummary != null) _problemSummary = problemSummary;
    if (accessMode != null && accessMode.isNotEmpty) _accessMode = accessMode;
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
    try {
      final payload = (signal['data'] is Map<String, dynamic>)
          ? signal['data'] as Map<String, dynamic>
          : signal;

      if (payload['type'] == 'chat_message' ||
          (payload['type'] == 'input_control' && (payload['data'] as Map?)?['type'] == 'chat_message')) {
        final chatData = payload['type'] == 'chat_message'
            ? payload
            : (payload['data'] as Map<String, dynamic>);
        _handleRemoteInput(chatData);
        return;
      }

      if (_peerConnection == null) return;

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
      } else if (payload['type'] == 'input_control' && payload['data'] is Map<String, dynamic>) {
        _handleRemoteInput(payload['data'] as Map<String, dynamic>);
      } else if (payload.containsKey('type') &&
          (payload['type'].toString().startsWith('mouse_') ||
              payload['type'].toString().startsWith('key_') ||
              payload['type'].toString().startsWith('file_') ||
              payload['type'] == 'wheel' ||
              payload['type'] == 'hotkey' ||
              payload['type'] == 'switch_screen' ||
              payload['type'] == 'clipboard_get' ||
              payload['type'] == 'clipboard_set' ||
              payload['type'] == 'chat_message')) {
        _handleRemoteInput(payload);
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
    } else if (type == 'chat_message') {
      try {
        final chatMsg = SupportChatMessage.fromJson(input);
        _chatMessages.add(chatMsg);
        _unreadChatCount++;
        notifyListeners();
        onChatMessageReceived?.call(chatMsg);
      } catch (e) {
        debugPrint('support_service: ошибка разбора чат-сообщения: $e');
      }
      return;
    } else if (type == 'file_start') {
      final transferId = input['transfer_id']?.toString() ?? input['id']?.toString() ?? '';
      final filename = input['filename']?.toString() ?? 'file_${DateTime.now().millisecondsSinceEpoch}';
      final size = (input['size'] as num?)?.toInt() ?? 0;
      final totalChunks = (input['total_chunks'] as num?)?.toInt() ?? 1;
      _activeDownloads[transferId] = _ActiveFileDownload(
        id: transferId,
        filename: filename,
        totalSize: size,
        totalChunks: totalChunks,
      );
      return;
    } else if (type == 'file_chunk') {
      final transferId = input['transfer_id']?.toString() ?? input['id']?.toString() ?? '';
      final chunkIndex = (input['chunk_index'] as num?)?.toInt() ?? 0;
      final base64Data = input['data']?.toString() ?? '';
      final dl = _activeDownloads[transferId];
      if (dl != null && base64Data.isNotEmpty) {
        try {
          dl.chunks[chunkIndex] = base64Decode(base64Data);
        } catch (_) {}
      }
      return;
    } else if (type == 'file_end') {
      final transferId = input['transfer_id']?.toString() ?? input['id']?.toString() ?? '';
      final dl = _activeDownloads.remove(transferId);
      if (dl != null) {
        _saveReceivedFile(dl);
      }
      return;
    }

    if (_accessMode == 'view_only') {
      // Режим «Только просмотр» блокирует команды управления
      return;
    }

    try {
      debugPrint('support_service: remote input command: $type');
      switch (type) {
        case 'mouse_move':
          final x = (input['x'] as num?)?.toDouble() ?? 0.0;
          final y = (input['y'] as num?)?.toDouble() ?? 0.0;
          InputInjector.instance.moveMouse(x, y);
          break;
        case 'mouse_down':
        case 'mouse_up':
        case 'mouse_click':
        case 'click':
          final btn = (input['button'] as num?)?.toInt() ?? 0;
          final x = (input['x'] as num?)?.toDouble() ?? 0.0;
          final y = (input['y'] as num?)?.toDouble() ?? 0.0;
          final act = type == 'mouse_down' ? 'down' : (type == 'mouse_up' ? 'up' : 'click');
          InputInjector.instance.mouseAction(action: act, button: btn, normX: x, normY: y);
          break;
        case 'wheel':
        case 'mouse_wheel':
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
          final hotkey = (input['action'] ?? input['hotkey'] ?? input['key'])?.toString() ?? '';
          if (hotkey.isNotEmpty) {
            await InputInjector.instance.triggerHotkey(hotkey);
          }
          break;
      }
    } catch (e) {
      debugPrint('support_service: ошибка выполнения ввода: $e');
    }
  }

  bool _isStopping = false;

  /// Остановка трансляции экрана и освобождение ресурсов (асинхронно, с защитой от рекурсии)
  Future<void> stopScreenSharing() async {
    if (_isStopping) return;
    _isStopping = true;

    try {
      // 1. Немедленно освобождаем мышь и ввод пользователя
      InputInjector.instance.setInputBlocked(false);

      _telemetryTimer?.cancel();
      _telemetryTimer = null;

      _pendingCandidates.clear();

      // Немедленно переводим статус в idle, чтобы UI обновился мгновенно
      _state = SupportSessionState.idle;
      _activeSessionId = null;
      _category = null;
      _problemSummary = null;
      _screens.clear();
      _currentScreenId = null;
      _activeDownloads.clear();
      _api = null;
      notifyListeners();

      // 2. Закрываем DataChannel и снимаем его обработчики
      final dc = _dataChannel;
      _dataChannel = null;
      if (dc != null) {
        try {
          dc.onMessage = null;
          dc.onDataChannelState = null;
          await dc.close().timeout(const Duration(milliseconds: 300), onTimeout: () => null);
        } catch (_) {}
      }

      // 3. Закрываем PeerConnection ПЕРЕД остановкой треков, чтобы остановить RTP sender threads в libwebrtc
      final pc = _peerConnection;
      _peerConnection = null;
      if (pc != null) {
        try {
          pc.onIceCandidate = null;
          pc.onConnectionState = null;
          pc.onTrack = null;
          pc.onDataChannel = null;
          pc.onIceConnectionState = null;
          pc.onRenegotiationNeeded = null;
          await pc.close().timeout(const Duration(milliseconds: 300), onTimeout: () => null);
        } catch (_) {}
      }

      // 4. Останавливаем все медиатреки захвата экрана
      final stream = _localStream;
      _localStream = null;
      if (stream != null) {
        try {
          for (final track in stream.getTracks()) {
            try {
              await track.stop().timeout(const Duration(milliseconds: 300), onTimeout: () => null);
            } catch (_) {}
          }
        } catch (_) {}
      }

      // 5. Окончательное освобождение нативных дескрипторов производим в фоне (не блокируя UI)
      Future.microtask(() async {
        try {
          await stream?.dispose();
        } catch (_) {}
        try {
          await pc?.dispose();
        } catch (_) {}
      });
    } catch (e) {
      debugPrint('support_service: ошибка при stopScreenSharing: $e');
    } finally {
      _isStopping = false;
      InputInjector.instance.setInputBlocked(false);
    }
  }

  @override
  void dispose() {
    stopScreenSharing();
    super.dispose();
  }
}
