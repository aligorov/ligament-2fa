import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import 'package:web_socket_channel/web_socket_channel.dart';
import 'package:window_manager/window_manager.dart';

import '../services/auth_state.dart';
import '../services/support_service.dart';

enum OperatorZoomMode {
  fit,
  original,
  zoomIn,
}

enum MouseClickMode {
  left,
  right,
}

class SupportOperatorScreen extends StatefulWidget {
  final String sessionId;
  final String? numberMatch;
  final Map<String, dynamic> sessionData;
  final bool isChatOnly;

  const SupportOperatorScreen({
    super.key,
    required this.sessionId,
    this.numberMatch,
    required this.sessionData,
    this.isChatOnly = false,
  });

  @override
  State<SupportOperatorScreen> createState() => _SupportOperatorScreenState();
}

class _SupportOperatorScreenState extends State<SupportOperatorScreen> {
  final RTCVideoRenderer _remoteRenderer = RTCVideoRenderer();
  RTCPeerConnection? _peerConnection;
  RTCDataChannel? _dataChannel;
  WebSocketChannel? _wsChannel;
  final List<RTCIceCandidate> _pendingCandidates = [];

  late bool _isChatOnly;
  String? _currentNumberMatch;
  String _connectionStatus = 'Инициализация...';
  bool _isConnected = false;
  bool _isInputBlocked = false;
  bool _isControlEnabled = true;
  MouseClickMode _mouseClickMode = MouseClickMode.left;

  List<Map<String, dynamic>> _screens = [];
  String? _selectedScreenId;

  int _cpuPercent = 0;
  bool _cpuWarning = false;
  int _diskPercent = 0;
  int _diskFreeGb = 0;
  bool _diskWarning = false;

  OperatorZoomMode _zoomMode = OperatorZoomMode.fit;
  double _zoomScale = 1.0;
  final FocusNode _keyboardFocus = FocusNode();
  final GlobalKey _videoKey = GlobalKey();

  final List<SupportChatMessage> _chatMessages = [];
  late final ValueNotifier<List<SupportChatMessage>> _chatMessagesNotifier;
  int _unreadChatCount = 0;

  Size? _previousWindowSize;

  Future<void> _expandWindowForOperator() async {
    if (!kIsWeb && (Platform.isWindows || Platform.isMacOS || Platform.isLinux)) {
      try {
        _previousWindowSize = await windowManager.getSize();
        await windowManager.setMinimumSize(const Size(800, 600));
        await windowManager.setSize(const Size(1280, 820));
        await windowManager.setResizable(true);
      } catch (_) {}
    }
  }

  Future<void> _restoreWindowSize() async {
    if (!kIsWeb && (Platform.isWindows || Platform.isMacOS || Platform.isLinux)) {
      try {
        if (_previousWindowSize != null) {
          await windowManager.setMinimumSize(const Size(380, 600));
          await windowManager.setSize(_previousWindowSize!);
        }
      } catch (_) {}
    }
  }

  Future<void> _loadChatHistory() async {
    final auth = context.read<AuthState>();
    if (auth.api == null || widget.sessionId.isEmpty) return;
    try {
      final list = await auth.api!.getSupportMessages(widget.sessionId);
      bool changed = false;
      for (final item in list) {
        final chatMsg = SupportChatMessage.fromJson(item);
        final idx = _chatMessages.indexWhere((m) =>
            m.id == chatMsg.id ||
            (m.sender == chatMsg.sender &&
                m.text == chatMsg.text &&
                m.timestamp.difference(chatMsg.timestamp).abs().inSeconds < 5));
        if (idx == -1) {
          _chatMessages.add(chatMsg);
          changed = true;
        } else if (_chatMessages[idx].id != chatMsg.id) {
          _chatMessages[idx] = chatMsg;
          changed = true;
        }
      }
      if (changed) {
        _chatMessages.sort((a, b) => a.timestamp.compareTo(b.timestamp));
        _chatMessagesNotifier.value = List.of(_chatMessages);
        if (mounted) setState(() {});
      }
    } catch (e) {
      debugPrint('support_operator: _loadChatHistory error: $e');
    }
  }

  @override
  void initState() {
    super.initState();
    _chatMessagesNotifier = ValueNotifier<List<SupportChatMessage>>(_chatMessages);
    _expandWindowForOperator();
    _isChatOnly = widget.isChatOnly;
    _currentNumberMatch = widget.numberMatch;
    final accessMode = widget.sessionData['access_mode']?.toString();
    _isControlEnabled = accessMode != 'view_only';
    _loadChatHistory();
    if (_isChatOnly) {
      _connectionStatus = 'Режим чата';
      _connectWebSocket();
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) _showOperatorChatModal();
      });
    } else {
      _initRendererAndWebRTC();
    }
  }

  Future<void> _initRendererAndWebRTC() async {
    setState(() {
      _connectionStatus = 'Ожидание согласия пользователя (${_currentNumberMatch ?? '2FA'})...';
    });
    await _remoteRenderer.initialize();
    _connectWebSocket();
    await _setupPeerConnection();
  }

  void _connectWebSocket() {
    if (_wsChannel != null) return;
    final auth = context.read<AuthState>();
    var serverUrl = auth.serverUrl ?? '';
    if (serverUrl.startsWith('https://')) {
      serverUrl = 'wss://${serverUrl.substring(8)}';
    } else if (serverUrl.startsWith('http://')) {
      serverUrl = 'ws://${serverUrl.substring(7)}';
    }
    if (serverUrl.endsWith('/')) {
      serverUrl = serverUrl.substring(0, serverUrl.length - 1);
    }
    final wsUrl = '$serverUrl/api/v1/support/ws/${widget.sessionId}?token=${auth.token}';

    try {
      final uri = Uri.parse(wsUrl);
      _wsChannel = WebSocketChannel.connect(uri);

      _wsChannel!.stream.listen(
        (message) {
          _handleWsMessage(message);
        },
        onDone: () {
          if (mounted) {
            setState(() {
              _connectionStatus = 'Сеанс завершен сервером';
              _isConnected = false;
              _currentNumberMatch = null;
            });
          }
        },
        onError: (err) {
          if (mounted) {
            setState(() {
              _connectionStatus = 'Ошибка соединения: $err';
              _isConnected = false;
              _currentNumberMatch = null;
            });
          }
        },
      );
    } catch (e) {
      if (mounted) {
        setState(() {
          _connectionStatus = 'Исключение подключения: $e';
        });
      }
    }
  }

  Future<void> _requestScreenAccess() async {
    setState(() {
      _connectionStatus = 'Запрос доступа к экрану у пользователя...';
    });
    final auth = context.read<AuthState>();
    try {
      final res = await auth.connectToSupportSession(widget.sessionId);
      if (mounted) {
        setState(() {
          _isChatOnly = false;
          _currentNumberMatch = res['number_match']?.toString();
        });
        await _initRendererAndWebRTC();
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _connectionStatus = 'Ошибка запроса: $e';
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFFEF4444),
            content: Text('Ошибка запроса экрана: $e'),
          ),
        );
      }
    }
  }

  Future<void> _setupPeerConnection() async {
    final config = <String, dynamic>{
      'iceServers': [
        {'urls': 'stun:stun.l.google.com:19302'},
        {'urls': 'stun:stun1.l.google.com:19302'},
        {'urls': 'stun:stun.cloudflare.com:3478'},
      ],
      'sdpSemantics': 'unified-plan',
    };

    _peerConnection = await createPeerConnection(config);

    _peerConnection!.onIceCandidate = (candidate) {
      if (candidate.candidate != null && candidate.candidate!.isNotEmpty) {
        _sendWsSignal({
          'candidate': {
            'candidate': candidate.candidate,
            'sdpMid': candidate.sdpMid,
            'sdpMLineIndex': candidate.sdpMLineIndex,
          },
        });
      }
    };

    _peerConnection!.onConnectionState = (state) {
      debugPrint('support_operator: connection state: $state');
      if (mounted) {
        setState(() {
          if (state == RTCPeerConnectionState.RTCPeerConnectionStateConnected) {
            _isConnected = true;
            _currentNumberMatch = null;
            _connectionStatus = 'Подключено (P2P)';
          } else if (state == RTCPeerConnectionState.RTCPeerConnectionStateFailed ||
              state == RTCPeerConnectionState.RTCPeerConnectionStateClosed ||
              state == RTCPeerConnectionState.RTCPeerConnectionStateDisconnected) {
            _isConnected = false;
            _currentNumberMatch = null;
            _connectionStatus = 'Отключено ($state)';
          }
        });
      }
    };

    _peerConnection!.onTrack = (RTCTrackEvent event) {
      debugPrint('support_operator: remote track received: ${event.track.kind}');
      if (event.streams.isNotEmpty && mounted) {
        setState(() {
          _remoteRenderer.srcObject = event.streams[0];
          _isConnected = true;
          _currentNumberMatch = null;
          _connectionStatus = 'Трансляция активна';
        });
      }
    };

    _peerConnection!.onDataChannel = (channel) {
      _setupDataChannel(channel);
    };

    // Создаем свой data channel, если еще не открыт
    final dcInit = RTCDataChannelInit()..ordered = true;
    final dc = await _peerConnection!.createDataChannel('input', dcInit);
    _setupDataChannel(dc);
  }

  void _setupDataChannel(RTCDataChannel channel) {
    _dataChannel = channel;
    channel.onDataChannelState = (state) {
      if (state == RTCDataChannelState.RTCDataChannelOpen) {
        if (mounted) {
          setState(() {
            _currentNumberMatch = null;
          });
        }
        _sendDataMessage({'type': 'screen_list'});
      }
    };

    channel.onMessage = (RTCDataChannelMessage msg) {
      if (msg.isBinary) return;
      try {
        final data = jsonDecode(msg.text) as Map<String, dynamic>;
        _handleDataChannelMessage(data);
      } catch (_) {}
    };
  }

  void _handleDataChannelMessage(Map<String, dynamic> data) {
    final type = data['type']?.toString();
    if (type == 'screen_list') {
      final list = data['screens'] as List<dynamic>? ?? [];
      final sel = data['selected_id']?.toString();
      if (mounted) {
        setState(() {
          _screens = list.cast<Map<String, dynamic>>();
          _selectedScreenId = sel ?? (_screens.isNotEmpty ? _screens.first['id']?.toString() : null);
        });
      }
    } else if (type == 'telemetry') {
      if (mounted) {
        setState(() {
          _cpuPercent = (data['cpu_percent'] as num?)?.toInt() ?? _cpuPercent;
          _cpuWarning = data['cpu_warning'] == true || _cpuPercent >= 90;
          _diskPercent = (data['disk_percent'] as num?)?.toInt() ?? _diskPercent;
          _diskFreeGb = (data['disk_free_gb'] as num?)?.toInt() ?? _diskFreeGb;
          _diskWarning = data['disk_warning'] == true;
        });
      }
    } else if (type == 'clipboard_data') {
      final text = data['text']?.toString() ?? '';
      _showRemoteClipboardDialog(text);
    } else if (type == 'chat_message') {
      try {
        final msg = SupportChatMessage.fromJson(data);
        final isDuplicate = _chatMessages.any((m) =>
            m.id == msg.id ||
            (m.sender == msg.sender &&
                m.text == msg.text &&
                m.timestamp.difference(msg.timestamp).abs().inSeconds < 5));
        if (!isDuplicate) {
          _chatMessages.add(msg);
          _chatMessages.sort((a, b) => a.timestamp.compareTo(b.timestamp));
          _chatMessagesNotifier.value = List.of(_chatMessages);
          if (mounted) {
            setState(() {
              if (msg.sender != 'operator') {
                _unreadChatCount++;
              }
            });
            if (msg.sender != 'operator') {
              context.read<AuthState>().alert.triggerChatNotification(
                sender: msg.senderName,
                message: msg.text,
              );
            }
          }
        }
      } catch (_) {}
    }
  }

  void _handleWsMessage(dynamic message) async {
    try {
      final text = message is String ? message : utf8.decode(message as List<int>);
      final data = jsonDecode(text) as Map<String, dynamic>;

      final payload = (data['data'] is Map<String, dynamic>)
          ? data['data'] as Map<String, dynamic>
          : data;

      if (payload.containsKey('sdp')) {
        final sdpMap = payload['sdp'] as Map<String, dynamic>;
        final type = sdpMap['type']?.toString();
        final desc = RTCSessionDescription(sdpMap['sdp']?.toString(), type);

        if (_peerConnection != null) {
          await _peerConnection!.setRemoteDescription(desc);
          while (_pendingCandidates.isNotEmpty) {
            final c = _pendingCandidates.removeAt(0);
            try {
              await _peerConnection!.addCandidate(c);
            } catch (_) {}
          }

          if (type == 'offer') {
            final answer = await _peerConnection!.createAnswer({
              'offerToReceiveVideo': 1,
              'offerToReceiveAudio': 0,
            });
            await _peerConnection!.setLocalDescription(answer);
            _sendWsSignal({'sdp': answer.toMap()});
          }
        }
      } else if (payload.containsKey('candidate')) {
        final cMap = payload['candidate'] as Map<String, dynamic>;
        final candidate = RTCIceCandidate(
          cMap['candidate']?.toString(),
          cMap['sdpMid']?.toString(),
          cMap['sdpMLineIndex'] as int?,
        );
        final remoteDesc = await _peerConnection?.getRemoteDescription();
        if (remoteDesc == null || remoteDesc.type == null || remoteDesc.type!.isEmpty) {
          _pendingCandidates.add(candidate);
        } else {
          await _peerConnection?.addCandidate(candidate);
        }
      } else if (data['type'] == 'session_ended' || data['type'] == 'support_ended') {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Сеанс поддержки был завершен пользователем')),
          );
          Navigator.of(context).pop();
        }
      } else if (data['type'] == 'chat_message' || payload['type'] == 'chat_message') {
        _handleDataChannelMessage(payload['type'] == 'chat_message' ? payload : data);
      }
    } catch (e) {
      debugPrint('support_operator: ошибка обработки WS: $e');
    }
  }

  void _sendChatMessage(String text) {
    if (text.trim().isEmpty) return;
    final auth = context.read<AuthState>();
    final operatorName = auth.displayName.isNotEmpty ? auth.displayName : 'Инженер';
    final msg = SupportChatMessage(
      id: 'msg_${DateTime.now().millisecondsSinceEpoch}',
      sender: 'operator',
      senderName: operatorName,
      text: text.trim(),
      timestamp: DateTime.now(),
    );

    if (!_chatMessages.any((m) => m.id == msg.id)) {
      _chatMessages.add(msg);
      _chatMessages.sort((a, b) => a.timestamp.compareTo(b.timestamp));
      _chatMessagesNotifier.value = List.of(_chatMessages);
      if (mounted) setState(() {});
    }

    _sendDataMessage(msg.toJson());
    _sendWsSignal(msg.toJson());

    auth.api?.sendSupportChatMessage(
      sessionId: widget.sessionId,
      text: msg.text,
      senderName: operatorName,
    ).catchError((e) {
      debugPrint('support_operator: ошибка отправки сообщения через API: $e');
    });
  }

  void _showOperatorChatModal() {
    setState(() {
      _unreadChatCount = 0;
    });
    _loadChatHistory();

    final textController = TextEditingController();
    final scrollController = ScrollController();

    Timer? historyPoller;
    historyPoller = Timer.periodic(const Duration(seconds: 2), (_) {
      _loadChatHistory();
    });

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) {
        return ValueListenableBuilder<List<SupportChatMessage>>(
          valueListenable: _chatMessagesNotifier,
          builder: (context, messages, _) {
            WidgetsBinding.instance.addPostFrameCallback((_) {
              if (scrollController.hasClients) {
                scrollController.animateTo(
                  scrollController.position.maxScrollExtent,
                  duration: const Duration(milliseconds: 200),
                  curve: Curves.easeOut,
                );
              }
            });

            return Container(
              height: MediaQuery.of(context).size.height * 0.75,
              decoration: const BoxDecoration(
                color: Color(0xFF0F172A),
                borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
                border: Border(
                  top: BorderSide(color: Color(0xFF334155), width: 1.5),
                  left: BorderSide(color: Color(0xFF334155), width: 1),
                  right: BorderSide(color: Color(0xFF334155), width: 1),
                ),
              ),
              child: Column(
                children: [
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                    child: Row(
                      children: [
                        const Icon(Icons.chat, color: Color(0xFF38BDF8), size: 22),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            'Чат с пользователем • ${widget.sessionData['employee_name'] ?? widget.sessionData['username'] ?? 'Клиент'}',
                            style: const TextStyle(color: Colors.white, fontSize: 15, fontWeight: FontWeight.bold),
                          ),
                        ),
                        IconButton(
                          icon: const Icon(Icons.close, color: Color(0xFF94A3B8), size: 20),
                          onPressed: () => Navigator.of(ctx).pop(),
                          padding: EdgeInsets.zero,
                          constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
                        ),
                      ],
                    ),
                  ),
                  const Divider(color: Color(0xFF1E293B), height: 1),

                  SingleChildScrollView(
                    scrollDirection: Axis.horizontal,
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                    child: Row(
                      children: [
                        _buildOperatorChatChip('👋 Здравствуйте! Подключился к экрану.'),
                        _buildOperatorChatChip('📁 Пожалуйста, сохраните открытые файлы.'),
                        _buildOperatorChatChip('🔄 Сейчас потребуется перезагрузить систему.'),
                        _buildOperatorChatChip('✅ Проблема устранена, проверяйте!'),
                      ],
                    ),
                  ),

                  Expanded(
                    child: messages.isEmpty
                        ? const Center(
                            child: Text(
                              'Сообщений пока нет.\nНапишите пользователю приветствие или инструкцию.',
                              textAlign: TextAlign.center,
                              style: TextStyle(color: Color(0xFF64748B), fontSize: 13),
                            ),
                          )
                        : ListView.builder(
                            controller: scrollController,
                            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                            itemCount: messages.length,
                            itemBuilder: (c, i) {
                              final msg = messages[i];
                              final isOperator = msg.sender == 'operator';
                              final timeStr = DateFormat('HH:mm').format(msg.timestamp);

                              return Align(
                                alignment: isOperator ? Alignment.centerRight : Alignment.centerLeft,
                                child: Container(
                                  margin: const EdgeInsets.only(bottom: 8),
                                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                                  constraints: BoxConstraints(
                                    maxWidth: MediaQuery.of(context).size.width * 0.75,
                                  ),
                                  decoration: BoxDecoration(
                                    color: isOperator ? const Color(0xFF2563EB) : const Color(0xFF1E293B),
                                    borderRadius: BorderRadius.circular(12),
                                    border: Border.all(
                                      color: isOperator ? const Color(0xFF3B82F6) : const Color(0xFF334155),
                                    ),
                                  ),
                                  child: Column(
                                    crossAxisAlignment: isOperator ? CrossAxisAlignment.end : CrossAxisAlignment.start,
                                    children: [
                                      if (!isOperator)
                                        Padding(
                                          padding: const EdgeInsets.only(bottom: 2),
                                          child: Text(
                                            msg.senderName,
                                            style: const TextStyle(color: Color(0xFF38BDF8), fontSize: 10, fontWeight: FontWeight.bold),
                                          ),
                                        ),
                                      Text(msg.text, style: const TextStyle(color: Colors.white, fontSize: 13)),
                                      const SizedBox(height: 2),
                                      Text(
                                        timeStr,
                                        style: TextStyle(color: isOperator ? Colors.white70 : const Color(0xFF64748B), fontSize: 9),
                                      ),
                                    ],
                                  ),
                                ),
                              );
                            },
                          ),
                  ),

                  Container(
                    padding: EdgeInsets.only(
                      left: 12,
                      right: 12,
                      top: 8,
                      bottom: MediaQuery.of(context).viewInsets.bottom + 8,
                    ),
                    decoration: const BoxDecoration(
                      color: Color(0xFF0B0F19),
                      border: Border(top: BorderSide(color: Color(0xFF1E293B))),
                    ),
                    child: Row(
                      children: [
                        Expanded(
                          child: TextField(
                            controller: textController,
                            style: const TextStyle(color: Colors.white, fontSize: 13),
                            decoration: InputDecoration(
                              hintText: 'Написать сообщение пользователю...',
                              hintStyle: const TextStyle(color: Color(0xFF64748B), fontSize: 13),
                              filled: true,
                              fillColor: const Color(0xFF1E293B),
                              contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                              border: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(20),
                                borderSide: BorderSide.none,
                              ),
                            ),
                            onSubmitted: (val) {
                              if (val.trim().isNotEmpty) {
                                _sendChatMessage(val.trim());
                                textController.clear();
                              }
                            },
                          ),
                        ),
                        const SizedBox(width: 8),
                        IconButton(
                          icon: const Icon(Icons.send, color: Color(0xFF38BDF8)),
                          onPressed: () {
                            final val = textController.text.trim();
                            if (val.isNotEmpty) {
                              _sendChatMessage(val);
                              textController.clear();
                            }
                          },
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            );
          },
        );
      },
    ).whenComplete(() {
      historyPoller?.cancel();
      textController.dispose();
      scrollController.dispose();
    });
  }

  Widget _buildOperatorChatChip(String text) {
    return Container(
      margin: const EdgeInsets.only(right: 6),
      child: InkWell(
        borderRadius: BorderRadius.circular(16),
        onTap: () {
          _sendChatMessage(text);
        },
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
          decoration: BoxDecoration(
            color: const Color(0xFF1E293B),
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: const Color(0xFF334155)),
          ),
          child: Text(text, style: const TextStyle(color: Color(0xFFCBD5E1), fontSize: 11)),
        ),
      ),
    );
  }

  void _sendWsSignal(Map<String, dynamic> signal) {
    try {
      _wsChannel?.sink.add(jsonEncode(signal));
    } catch (_) {}
  }

  void _sendDataMessage(Map<String, dynamic> msg) {
    bool sent = false;
    if (_dataChannel != null && _dataChannel!.state == RTCDataChannelState.RTCDataChannelOpen) {
      try {
        _dataChannel!.send(RTCDataChannelMessage(jsonEncode(msg)));
        sent = true;
      } catch (_) {}
    }
    if (!sent) {
      if (msg['type'] == 'chat_message') {
        _sendWsSignal(msg);
      } else {
        _sendWsSignal({'type': 'input_control', 'data': msg});
      }
    }
  }

  void _sendPointerEvent(String action, PointerEvent event, int button) {
    if (!_isControlEnabled) return;
    final renderBox = _videoKey.currentContext?.findRenderObject() as RenderBox?;
    if (renderBox == null) return;

    final localPos = renderBox.globalToLocal(event.position);
    final size = renderBox.size;
    if (size.width <= 0 || size.height <= 0) return;

    double videoW = _remoteRenderer.videoWidth.toDouble();
    double videoH = _remoteRenderer.videoHeight.toDouble();
    if (videoW <= 0) videoW = 1920;
    if (videoH <= 0) videoH = 1080;

    final containerW = size.width;
    final containerH = size.height;
    final videoAspect = videoW / videoH;
    final containerAspect = containerW / containerH;

    double renderW = containerW;
    double renderH = containerH;
    double offsetX = 0.0;
    double offsetY = 0.0;

    if (_zoomMode == OperatorZoomMode.fit) {
      if (containerAspect > videoAspect) {
        // Черные полосы по бокам (left / right)
        renderW = containerH * videoAspect;
        offsetX = (containerW - renderW) / 2.0;
      } else {
        // Черные полосы сверху / снизу (top / bottom)
        renderH = containerW / videoAspect;
        offsetY = (containerH - renderH) / 2.0;
      }
    }

    final normX = ((localPos.dx - offsetX) / renderW).clamp(0.0, 1.0);
    final normY = ((localPos.dy - offsetY) / renderH).clamp(0.0, 1.0);

    if (action == 'move') {
      _sendDataMessage({'type': 'mouse_move', 'x': normX, 'y': normY});
    } else {
      _sendDataMessage({
        'type': action,
        'button': button,
        'x': normX,
        'y': normY,
      });
    }
  }

  void _showTextInputDialog() {
    final controller = TextEditingController();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E293B),
        title: const Row(
          children: [
            Icon(Icons.keyboard_alt_outlined, color: Color(0xFF38BDF8), size: 20),
            SizedBox(width: 8),
            Text('Ввод текста на ПК клиента', style: TextStyle(color: Colors.white, fontSize: 16)),
          ],
        ),
        content: SizedBox(
          width: 420,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Введите текст или команду для отправки на компьютер клиента:',
                style: TextStyle(color: Color(0xFF94A3B8), fontSize: 12),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: controller,
                autofocus: true,
                style: const TextStyle(color: Colors.white),
                decoration: InputDecoration(
                  hintText: 'Текст, пароль или команда...',
                  hintStyle: const TextStyle(color: Color(0xFF64748B)),
                  filled: true,
                  fillColor: const Color(0xFF0F172A),
                  border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
                ),
                onSubmitted: (val) {
                  Navigator.of(ctx).pop();
                  _sendTextToRemote(val);
                },
              ),
              const SizedBox(height: 14),
              const Text('Быстрые клавиши:', style: TextStyle(color: Color(0xFF94A3B8), fontSize: 11)),
              const SizedBox(height: 6),
              Wrap(
                spacing: 6,
                runSpacing: 6,
                children: [
                  _buildQuickKeyButton('Enter ↵', () => _sendSpecialKey('Enter')),
                  _buildQuickKeyButton('Tab ⇥', () => _sendSpecialKey('Tab')),
                  _buildQuickKeyButton('Esc ⎋', () => _sendSpecialKey('Escape')),
                  _buildQuickKeyButton('Backspace ⌫', () => _sendSpecialKey('Backspace')),
                  _buildQuickKeyButton('Win+R ⊞', () => _sendHotkey('win_r')),
                  _buildQuickKeyButton('Ctrl+Alt+Del 🔒', () => _sendHotkey('ctrl_alt_del')),
                  _buildQuickKeyButton('Диспетчер ⚡', () => _sendHotkey('task_mgr')),
                ],
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Отмена'),
          ),
          ElevatedButton.icon(
            onPressed: () {
              final text = controller.text;
              Navigator.of(ctx).pop();
              _sendTextToRemote(text);
            },
            icon: const Icon(Icons.send, size: 14),
            label: const Text('Отправить'),
            style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF0284C7)),
          ),
        ],
      ),
    );
  }

  Widget _buildQuickKeyButton(String label, VoidCallback onPressed) {
    return InkWell(
      onTap: onPressed,
      borderRadius: BorderRadius.circular(6),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 5),
        decoration: BoxDecoration(
          color: const Color(0xFF0F172A),
          borderRadius: BorderRadius.circular(6),
          border: Border.all(color: const Color(0xFF475569)),
        ),
        child: Text(
          label,
          style: const TextStyle(color: Color(0xFF38BDF8), fontSize: 11, fontWeight: FontWeight.bold),
        ),
      ),
    );
  }

  void _sendSpecialKey(String key) {
    _sendDataMessage({'type': 'key_down', 'key': key});
    _sendDataMessage({'type': 'key_up', 'key': key});
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Отправлена клавиша $key'),
        duration: const Duration(milliseconds: 600),
      ),
    );
  }

  void _sendTextToRemote(String text) {
    if (text.isEmpty) return;
    _sendDataMessage({'type': 'clipboard_set', 'text': text});
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Текст отправлен в буфер ПК клиента: "$text"'),
        duration: const Duration(seconds: 2),
      ),
    );
  }

  void _toggleBlockInput() {
    setState(() {
      _isInputBlocked = !_isInputBlocked;
    });
    _sendDataMessage({'type': 'block_input', 'blocked': _isInputBlocked});
  }

  void _sendHotkey(String action) {
    _sendDataMessage({'type': 'hotkey', 'action': action});
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Отправлена комбинация: $action'),
        duration: const Duration(milliseconds: 900),
      ),
    );
  }

  void _switchScreen(String screenId) {
    setState(() => _selectedScreenId = screenId);
    _sendDataMessage({'type': 'switch_screen', 'screen_id': screenId});
  }

  void _sendLocalClipboardToRemote() async {
    final clip = await Clipboard.getData(Clipboard.kTextPlain);
    final text = clip?.text ?? '';
    if (text.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Локальный буфер обмена пуст')),
        );
      }
      return;
    }
    _sendDataMessage({'type': 'clipboard_set', 'text': text});
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Буфер отправлен на ПК клиента (${text.length} симв.)')),
      );
    }
  }

  void _requestRemoteClipboard() {
    _sendDataMessage({'type': 'clipboard_get'});
  }

  void _showRemoteClipboardDialog(String text) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E293B),
        title: const Text('Буфер обмена клиента', style: TextStyle(color: Colors.white)),
        content: SelectableText(
          text.isNotEmpty ? text : '(Буфер обмена пуст)',
          style: const TextStyle(color: Color(0xFF94A3B8)),
        ),
        actions: [
          if (text.isNotEmpty)
            TextButton.icon(
              onPressed: () {
                Clipboard.setData(ClipboardData(text: text));
                Navigator.of(ctx).pop();
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Скопировано в ваш локальный буфер')),
                );
              },
              icon: const Icon(Icons.copy, size: 16),
              label: const Text('Скопировать себе'),
            ),
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Закрыть'),
          ),
        ],
      ),
    );
  }

  bool _isCleanedUp = false;

  void _cleanupResources() {
    if (_isCleanedUp) return;
    _isCleanedUp = true;

    try {
      _remoteRenderer.srcObject = null;
    } catch (_) {}

    final dc = _dataChannel;
    _dataChannel = null;
    if (dc != null) {
      try {
        dc.onMessage = null;
        dc.onDataChannelState = null;
        dc.close();
      } catch (_) {}
    }

    final pc = _peerConnection;
    _peerConnection = null;
    if (pc != null) {
      try {
        pc.onConnectionState = null;
        pc.onIceCandidate = null;
        pc.onTrack = null;
        pc.onDataChannel = null;
        pc.close();
      } catch (_) {}
    }

    try {
      _wsChannel?.sink.close();
      _wsChannel = null;
    } catch (_) {}

    // Отложенное освобождение нативных DirectX текстур рендерера и WebRTC соединения,
    // чтобы анимация закрытия окна (route pop) завершилась абсолютно гладко без зависаний
    Future.delayed(const Duration(milliseconds: 350), () {
      try {
        _remoteRenderer.dispose();
      } catch (_) {}
      try {
        pc?.dispose();
      } catch (_) {}
    });
  }

  void _endSession() async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E293B),
        title: const Text('Завершить сеанс?', style: TextStyle(color: Colors.white)),
        content: const Text(
          'Вы уверены, что хотите завершить сеанс удаленного управления?',
          style: TextStyle(color: Color(0xFF94A3B8)),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Отмена'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFEF4444)),
            child: const Text('Завершить'),
          ),
        ],
      ),
    );

    if (confirm == true && mounted) {
      final auth = context.read<AuthState>();
      final sessId = widget.sessionId;
      Navigator.of(context).pop();
      try {
        auth.api?.endSupportSession(sessionId: sessId).timeout(
          const Duration(seconds: 2),
          onTimeout: () => null,
        );
      } catch (_) {}
    }
  }

  @override
  void dispose() {
    _chatMessagesNotifier.dispose();
    _keyboardFocus.dispose();
    _restoreWindowSize();
    _cleanupResources();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final clientName = widget.sessionData['display_name'] ??
        widget.sessionData['employee_name'] ??
        widget.sessionData['username'] ??
        'Клиент';
    final pcName = widget.sessionData['device_name'] ?? widget.sessionData['pc_name'] ?? 'PC';
    final is1C = widget.sessionData['category'] == '1c';

    return Scaffold(
      backgroundColor: const Color(0xFF0B0F19),
      body: Column(
        children: [
          // Верхняя панель управления (Toolbar)
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            decoration: const BoxDecoration(
              color: Color(0xFF1E293B),
              border: Border(bottom: BorderSide(color: Color(0xFF334155))),
            ),
            child: SafeArea(
              bottom: false,
              child: Wrap(
                spacing: 8,
                runSpacing: 6,
                crossAxisAlignment: WrapCrossAlignment.center,
                alignment: WrapAlignment.spaceBetween,
                children: [
                  // Информация о клиенте и статус
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      IconButton(
                        icon: const Icon(Icons.arrow_back, color: Colors.white, size: 20),
                        tooltip: 'Назад',
                        onPressed: () => Navigator.of(context).pop(),
                      ),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                        decoration: BoxDecoration(
                          color: is1C ? const Color(0xFFF59E0B) : const Color(0xFF0284C7),
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: Text(
                          is1C ? '1С' : 'IT',
                          style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 11),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            '$clientName ($pcName)',
                            style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 13),
                          ),
                          Text(
                            _connectionStatus,
                            style: TextStyle(
                              color: _isConnected ? const Color(0xFF10B981) : const Color(0xFFF59E0B),
                              fontSize: 10,
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),

                  // Выбор монитора
                  if (_screens.isNotEmpty)
                    Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        DropdownButton<String>(
                          value: _selectedScreenId,
                          dropdownColor: const Color(0xFF1E293B),
                          underline: const SizedBox(),
                          style: const TextStyle(color: Colors.white, fontSize: 12),
                          items: _screens.map((s) {
                            return DropdownMenuItem<String>(
                              value: s['id']?.toString(),
                              child: Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  const Icon(Icons.desktop_windows, size: 14, color: Color(0xFF38BDF8)),
                                  const SizedBox(width: 4),
                                  Text(s['name']?.toString() ?? 'Монитор', overflow: TextOverflow.ellipsis),
                                ],
                              ),
                            );
                          }).toList(),
                          onChanged: (val) {
                            if (val != null) _switchScreen(val);
                          },
                        ),
                        IconButton(
                          icon: const Icon(Icons.refresh, size: 16, color: Color(0xFF94A3B8)),
                          tooltip: 'Обновить список экранов (Win+P "Расширить" на клиенте)',
                          onPressed: () {
                            _sendDataMessage({'type': 'screen_list'});
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(
                                duration: Duration(seconds: 2),
                                content: Text('Запрос обновления списка экранов отправлен...'),
                              ),
                            );
                          },
                        ),
                      ],
                    ),

                  // Масштабирование
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      IconButton(
                        icon: Icon(
                          _zoomMode == OperatorZoomMode.fit ? Icons.fit_screen : Icons.aspect_ratio,
                          color: const Color(0xFF38BDF8),
                          size: 18,
                        ),
                        tooltip: _zoomMode == OperatorZoomMode.fit ? 'Масштаб: Вписать' : 'Масштаб: 1:1',
                        onPressed: () {
                          setState(() {
                            if (_zoomMode == OperatorZoomMode.fit) {
                              _zoomMode = OperatorZoomMode.original;
                              _zoomScale = 1.0;
                            } else {
                              _zoomMode = OperatorZoomMode.fit;
                            }
                          });
                        },
                      ),
                      IconButton(
                        icon: const Icon(Icons.zoom_in, color: Colors.white, size: 18),
                        tooltip: 'Приблизить',
                        onPressed: () {
                          setState(() {
                            _zoomMode = OperatorZoomMode.zoomIn;
                            _zoomScale = (_zoomScale + 0.25).clamp(1.0, 3.0);
                          });
                        },
                      ),
                      IconButton(
                        icon: const Icon(Icons.zoom_out, color: Colors.white, size: 18),
                        tooltip: 'Отдалить',
                        onPressed: () {
                          setState(() {
                            _zoomScale = (_zoomScale - 0.25).clamp(0.5, 3.0);
                            if (_zoomScale <= 1.0) _zoomMode = OperatorZoomMode.fit;
                          });
                        },
                      ),
                    ],
                  ),

                  // Блокировка ввода
                  IconButton(
                    icon: Icon(
                      _isInputBlocked ? Icons.lock : Icons.lock_open,
                      color: _isInputBlocked ? const Color(0xFFEF4444) : const Color(0xFF94A3B8),
                      size: 18,
                    ),
                    tooltip: _isInputBlocked ? 'Разблокировать мышь клиента' : 'Заблокировать мышь/клавиатуру клиента',
                    onPressed: _toggleBlockInput,
                  ),

                  // Горячие клавиши
                  PopupMenuButton<String>(
                    icon: const Icon(Icons.keyboard, color: Color(0xFF38BDF8), size: 20),
                    tooltip: 'Горячие клавиши',
                    color: const Color(0xFF1E293B),
                    itemBuilder: (ctx) => [
                      const PopupMenuItem(value: 'win_key', child: Text('⊞ Пуск (Win)', style: TextStyle(color: Colors.white))),
                      const PopupMenuItem(value: 'win_r', child: Text('⊞ Win + R (Выполнить)', style: TextStyle(color: Colors.white))),
                      const PopupMenuItem(value: 'win_e', child: Text('⊞ Win + E (Проводник)', style: TextStyle(color: Colors.white))),
                      const PopupMenuItem(value: 'win_x', child: Text('⊞ Win + X (Админ-меню)', style: TextStyle(color: Colors.white))),
                      const PopupMenuItem(value: 'win_d', child: Text('⊞ Win + D (Рабочий стол)', style: TextStyle(color: Colors.white))),
                      const PopupMenuItem(value: 'win_l', child: Text('⊞ Win + L (Блокировка)', style: TextStyle(color: Colors.white))),
                      const PopupMenuItem(value: 'task_mgr', child: Text('⚡ Диспетчер задач', style: TextStyle(color: Colors.white))),
                      const PopupMenuItem(value: 'ctrl_alt_del', child: Text('🔒 Ctrl+Alt+Del', style: TextStyle(color: Colors.white))),
                      const PopupMenuItem(value: 'alt_tab', child: Text('🔄 Alt + Tab', style: TextStyle(color: Colors.white))),
                      const PopupMenuItem(value: 'alt_f4', child: Text('❌ Alt + F4', style: TextStyle(color: Colors.white))),
                      const PopupMenuItem(value: 'esc', child: Text('⎋ Escape', style: TextStyle(color: Colors.white))),
                    ],
                    onSelected: _sendHotkey,
                  ),

                  // Буфер обмена
                  PopupMenuButton<String>(
                    icon: const Icon(Icons.content_paste, color: Color(0xFF38BDF8), size: 20),
                    tooltip: 'Буфер обмена',
                    color: const Color(0xFF1E293B),
                    itemBuilder: (ctx) => [
                      const PopupMenuItem(value: 'send', child: Text('⬆ Отправить мой буфер клиенту', style: TextStyle(color: Colors.white))),
                      const PopupMenuItem(value: 'get', child: Text('⬇ Прочитать буфер с ПК клиента', style: TextStyle(color: Colors.white))),
                    ],
                    onSelected: (val) {
                      if (val == 'send') _sendLocalClipboardToRemote();
                      if (val == 'get') _requestRemoteClipboard();
                    },
                  ),

                  // Чат с пользователем
                  IconButton(
                    icon: Badge(
                      isLabelVisible: _unreadChatCount > 0,
                      label: Text('$_unreadChatCount'),
                      child: const Icon(Icons.chat_bubble_outline, color: Color(0xFF38BDF8), size: 20),
                    ),
                    tooltip: 'Чат с пользователем',
                    onPressed: _showOperatorChatModal,
                  ),

                  // Бейджи телеметрии (CPU, Диск)
                  if (_cpuPercent > 0 || _diskPercent > 0)
                    Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
                          decoration: BoxDecoration(
                            color: _cpuWarning ? const Color(0xFFEF4444).withValues(alpha: 0.2) : const Color(0xFF334155),
                            borderRadius: BorderRadius.circular(4),
                            border: Border.all(color: _cpuWarning ? const Color(0xFFEF4444) : const Color(0xFF475569)),
                          ),
                          child: Text(
                            '⚡ CPU: $_cpuPercent%',
                            style: TextStyle(
                              color: _cpuWarning ? const Color(0xFFEF4444) : Colors.white,
                              fontSize: 10,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                        const SizedBox(width: 4),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
                          decoration: BoxDecoration(
                            color: _diskWarning ? const Color(0xFFEF4444).withValues(alpha: 0.2) : const Color(0xFF334155),
                            borderRadius: BorderRadius.circular(4),
                            border: Border.all(color: _diskWarning ? const Color(0xFFEF4444) : const Color(0xFF475569)),
                          ),
                          child: Text(
                            '💾 $_diskFreeGb ГБ ($_diskPercent%)',
                            style: TextStyle(
                              color: _diskWarning ? const Color(0xFFEF4444) : Colors.white,
                              fontSize: 10,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                      ],
                    ),

                  // Переключатель управления / просмотра
                  IconButton(
                    icon: Icon(
                      _isControlEnabled ? Icons.sports_esports : Icons.visibility,
                      color: _isControlEnabled ? const Color(0xFF10B981) : const Color(0xFF94A3B8),
                      size: 20,
                    ),
                    tooltip: _isControlEnabled ? 'Управление активно (кликните для паузы)' : 'Только просмотр (кликните для включения)',
                    onPressed: () {
                      setState(() => _isControlEnabled = !_isControlEnabled);
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(
                          content: Text(_isControlEnabled ? '🎮 Управление включено' : '👁 Режим только просмотра'),
                          duration: const Duration(milliseconds: 800),
                        ),
                      );
                    },
                  ),

                  // Ввод текста на удаленный ПК
                  IconButton(
                    icon: const Icon(Icons.keyboard_alt_outlined, color: Color(0xFF38BDF8), size: 20),
                    tooltip: 'Ввести текст/команду на ПК клиента',
                    onPressed: _showTextInputDialog,
                  ),

                  // Режим клика мыши (ЛКМ / ПКМ)
                  IconButton(
                    icon: Icon(
                      _mouseClickMode == MouseClickMode.right ? Icons.mouse : Icons.touch_app,
                      color: _mouseClickMode == MouseClickMode.right ? const Color(0xFFF59E0B) : const Color(0xFF94A3B8),
                      size: 18,
                    ),
                    tooltip: _mouseClickMode == MouseClickMode.right ? 'Режим: Правый клик (ПКМ)' : 'Режим: Левый клик (ЛКМ)',
                    onPressed: () {
                      setState(() {
                        _mouseClickMode = _mouseClickMode == MouseClickMode.left ? MouseClickMode.right : MouseClickMode.left;
                      });
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(
                          content: Text(_mouseClickMode == MouseClickMode.right ? '🖱 Следующий клик: Правая кнопка (ПКМ)' : '🖱 Режим: Левая кнопка (ЛКМ)'),
                          duration: const Duration(milliseconds: 800),
                        ),
                      );
                    },
                  ),

                  // Кнопка запроса экрана в режиме чата
                  if (_isChatOnly)
                    ElevatedButton.icon(
                      onPressed: _requestScreenAccess,
                      icon: const Icon(Icons.desktop_windows, size: 14),
                      label: const Text('Запросить экран (2FA)', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold)),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFF0284C7),
                        foregroundColor: Colors.white,
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                        minimumSize: Size.zero,
                        tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                      ),
                    ),

                  // Кнопка завершения сеанса
                  ElevatedButton.icon(
                    onPressed: _endSession,
                    icon: const Icon(Icons.call_end, size: 14),
                    label: const Text('Завершить', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold)),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: const Color(0xFFEF4444),
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                      minimumSize: Size.zero,
                      tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                    ),
                  ),
                ],
              ),
            ),
          ),

          // Карточка с контрольным числом (если сеанс еще авторизуется клиентом)
          if (!_isConnected && !_isChatOnly && _currentNumberMatch != null && _connectionStatus.startsWith('Ожидание согласия'))
            Container(
              margin: const EdgeInsets.all(16),
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: const Color(0xFF1E293B),
                borderRadius: BorderRadius.circular(16),
                border: Border.all(color: const Color(0xFF38BDF8), width: 2),
              ),
              child: Column(
                children: [
                  const Text(
                    'Контрольное число для клиента (2FA):',
                    style: TextStyle(color: Color(0xFF94A3B8), fontSize: 13),
                  ),
                  const SizedBox(height: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0F172A),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Text(
                      _currentNumberMatch!,
                      style: const TextStyle(
                        color: Color(0xFF38BDF8),
                        fontSize: 32,
                        fontWeight: FontWeight.bold,
                        letterSpacing: 4,
                      ),
                    ),
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'Пользователь должен выбрать или подтвердить это число на своем экране',
                    style: TextStyle(color: Color(0xFF64748B), fontSize: 11),
                  ),
                ],
              ),
            ),

          // Область удаленного экрана
          Expanded(
            child: Focus(
              focusNode: _keyboardFocus,
              autofocus: true,
              onKeyEvent: (node, event) {
                if (!_isConnected || !_isControlEnabled) return KeyEventResult.ignored;
                final isDown = event is KeyDownEvent || event is KeyRepeatEvent;
                final keyLabel = event.logicalKey.keyLabel;
                _sendDataMessage({
                  'type': isDown ? 'key_down' : 'key_up',
                  'key': keyLabel,
                });
                return KeyEventResult.handled;
              },
              child: Listener(
                onPointerHover: (ev) => _sendPointerEvent('move', ev, 0),
                onPointerMove: (ev) => _sendPointerEvent('move', ev, 0),
                onPointerDown: (ev) {
                  if (!_isControlEnabled) return;
                  _keyboardFocus.requestFocus();
                  int btn = 0;
                  if (ev.buttons == 2 || _mouseClickMode == MouseClickMode.right) {
                    btn = 2; // Right
                  } else if (ev.buttons == 4) {
                    btn = 1; // Middle
                  }
                  _sendPointerEvent('mouse_down', ev, btn);
                },
                onPointerUp: (ev) {
                  if (!_isControlEnabled) return;
                  int btn = 0;
                  if (ev.buttons == 2 || _mouseClickMode == MouseClickMode.right) {
                    btn = 2;
                  } else if (ev.buttons == 4) {
                    btn = 1;
                  }
                  _sendPointerEvent('mouse_up', ev, btn);
                  if (_mouseClickMode == MouseClickMode.right) {
                    setState(() => _mouseClickMode = MouseClickMode.left);
                  }
                },
                onPointerSignal: (signal) {
                  if (!_isControlEnabled) return;
                  if (signal is PointerScrollEvent) {
                    _sendDataMessage({'type': 'wheel', 'deltaY': signal.scrollDelta.dy});
                  }
                },
                child: Center(
                  child: _isChatOnly
                      ? Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Container(
                              padding: const EdgeInsets.all(20),
                              decoration: BoxDecoration(
                                color: const Color(0xFF0284C7).withValues(alpha: 0.15),
                                shape: BoxShape.circle,
                              ),
                              child: const Icon(Icons.chat_outlined, size: 48, color: Color(0xFF38BDF8)),
                            ),
                            const SizedBox(height: 16),
                            const Text(
                              'Текстовый чат с пользователем',
                              style: TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold),
                            ),
                            const SizedBox(height: 8),
                            const Padding(
                              padding: EdgeInsets.symmetric(horizontal: 32),
                              child: Text(
                                'Вы находитесь в режиме прямого чата.\nТрансляция экрана начнется после запроса доступа и 2FA подтверждения.',
                                style: TextStyle(color: Color(0xFF94A3B8), fontSize: 13),
                                textAlign: TextAlign.center,
                              ),
                            ),
                            const SizedBox(height: 24),
                            ElevatedButton.icon(
                              onPressed: _requestScreenAccess,
                              icon: const Icon(Icons.desktop_windows, size: 18),
                              label: const Text('🎮 Запросить доступ к экрану (2FA)', style: TextStyle(fontWeight: FontWeight.bold)),
                              style: ElevatedButton.styleFrom(
                                backgroundColor: const Color(0xFF0284C7),
                                foregroundColor: Colors.white,
                                padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
                                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                              ),
                            ),
                            const SizedBox(height: 12),
                            OutlinedButton.icon(
                              onPressed: _showOperatorChatModal,
                              icon: const Icon(Icons.chat_bubble_outline, size: 16),
                              label: Text(_chatMessages.isEmpty ? '💬 Открыть окно чата' : '💬 Чат (${_chatMessages.length})'),
                              style: OutlinedButton.styleFrom(
                                foregroundColor: const Color(0xFF38BDF8),
                                side: const BorderSide(color: Color(0xFF0284C7)),
                                padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
                                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                              ),
                            ),
                          ],
                        )
                      : _remoteRenderer.srcObject == null
                          ? Column(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                const CircularProgressIndicator(color: Color(0xFF38BDF8)),
                                const SizedBox(height: 16),
                                Text(
                                  _connectionStatus,
                                  style: const TextStyle(color: Color(0xFF94A3B8), fontSize: 14),
                                ),
                              ],
                            )
                          : InteractiveViewer(
                          scaleEnabled: _zoomMode == OperatorZoomMode.zoomIn,
                          minScale: 1.0,
                          maxScale: 3.0,
                          child: Container(
                            key: _videoKey,
                            child: RTCVideoView(
                              _remoteRenderer,
                              objectFit: _zoomMode == OperatorZoomMode.fit
                                  ? RTCVideoViewObjectFit.RTCVideoViewObjectFitContain
                                  : RTCVideoViewObjectFit.RTCVideoViewObjectFitCover,
                            ),
                          ),
                        ),
                ),
              ),
            ),
          ),

          // Быстрая панель действий для оператора (скролл, режим клика, ввод текста)
          if (_isConnected)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: const BoxDecoration(
                color: Color(0xFF1E293B),
                border: Border(top: BorderSide(color: Color(0xFF334155))),
              ),
              child: SafeArea(
                top: false,
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceAround,
                  children: [
                    TextButton.icon(
                      onPressed: () {
                        setState(() {
                          _mouseClickMode = _mouseClickMode == MouseClickMode.left ? MouseClickMode.right : MouseClickMode.left;
                        });
                        ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(
                            content: Text(_mouseClickMode == MouseClickMode.right ? '🖱 Следующий клик: Правая кнопка (ПКМ)' : '🖱 Режим: Обычный клик (ЛКМ)'),
                            duration: const Duration(milliseconds: 700),
                          ),
                        );
                      },
                      icon: Icon(
                        _mouseClickMode == MouseClickMode.right ? Icons.mouse : Icons.touch_app,
                        size: 16,
                        color: _mouseClickMode == MouseClickMode.right ? const Color(0xFFF59E0B) : const Color(0xFF38BDF8),
                      ),
                      label: Text(
                        _mouseClickMode == MouseClickMode.right ? 'Режим: ПКМ' : 'Режим: ЛКМ',
                        style: TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.bold,
                          color: _mouseClickMode == MouseClickMode.right ? const Color(0xFFF59E0B) : Colors.white,
                        ),
                      ),
                    ),
                    TextButton.icon(
                      onPressed: () => _sendDataMessage({'type': 'wheel', 'deltaY': -180}),
                      icon: const Icon(Icons.arrow_upward, size: 14, color: Color(0xFF38BDF8)),
                      label: const Text('Скролл ▲', style: TextStyle(fontSize: 12, color: Colors.white)),
                    ),
                    TextButton.icon(
                      onPressed: () => _sendDataMessage({'type': 'wheel', 'deltaY': 180}),
                      icon: const Icon(Icons.arrow_downward, size: 14, color: Color(0xFF38BDF8)),
                      label: const Text('Скролл ▼', style: TextStyle(fontSize: 12, color: Colors.white)),
                    ),
                    TextButton.icon(
                      onPressed: _showTextInputDialog,
                      icon: const Icon(Icons.keyboard_alt_outlined, size: 16, color: Color(0xFF38BDF8)),
                      label: const Text('Ввод текста', style: TextStyle(fontSize: 12, color: Colors.white)),
                    ),
                    TextButton.icon(
                      onPressed: _showOperatorChatModal,
                      icon: Badge(
                        isLabelVisible: _unreadChatCount > 0,
                        label: Text('$_unreadChatCount'),
                        child: const Icon(Icons.chat_bubble_outline, size: 16, color: Color(0xFF38BDF8)),
                      ),
                      label: Text(
                        _unreadChatCount > 0 ? 'Чат ($_unreadChatCount)' : 'Чат',
                        style: const TextStyle(fontSize: 12, color: Colors.white),
                      ),
                    ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }
}
