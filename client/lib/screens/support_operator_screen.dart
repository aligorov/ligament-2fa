import 'dart:async';
import 'dart:convert';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:provider/provider.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

import '../services/auth_state.dart';

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

  const SupportOperatorScreen({
    super.key,
    required this.sessionId,
    this.numberMatch,
    required this.sessionData,
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

  @override
  void initState() {
    super.initState();
    final accessMode = widget.sessionData['access_mode']?.toString();
    _isControlEnabled = accessMode != 'view_only';
    _initRendererAndWebRTC();
  }

  Future<void> _initRendererAndWebRTC() async {
    await _remoteRenderer.initialize();
    _connectWebSocketAndWebRTC();
  }

  void _connectWebSocketAndWebRTC() async {
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

    setState(() {
      _connectionStatus = 'Ожидание согласия пользователя (${widget.numberMatch ?? '2FA'})...';
    });

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
            });
          }
        },
        onError: (err) {
          if (mounted) {
            setState(() {
              _connectionStatus = 'Ошибка соединения: $err';
              _isConnected = false;
            });
          }
        },
      );

      _setupPeerConnection();
    } catch (e) {
      if (mounted) {
        setState(() {
          _connectionStatus = 'Исключение подключения: $e';
        });
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
            _connectionStatus = 'Подключено (P2P)';
          } else if (state == RTCPeerConnectionState.RTCPeerConnectionStateFailed ||
              state == RTCPeerConnectionState.RTCPeerConnectionStateClosed ||
              state == RTCPeerConnectionState.RTCPeerConnectionStateDisconnected) {
            _isConnected = false;
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
      }
    } catch (e) {
      debugPrint('support_operator: ошибка обработки WS: $e');
    }
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
      _sendWsSignal({'type': 'input_control', 'data': msg});
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
      _remoteRenderer.dispose();
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
        pc.dispose();
      } catch (_) {}
    }

    try {
      _wsChannel?.sink.close();
      _wsChannel = null;
    } catch (_) {}
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
      _cleanupResources();
      try {
        await auth.api?.endSupportSession(sessionId: widget.sessionId).timeout(
          const Duration(seconds: 3),
          onTimeout: () => null,
        );
      } catch (_) {}
      if (!mounted) return;
      Navigator.of(context).pop();
    }
  }

  @override
  void dispose() {
    _keyboardFocus.dispose();
    _cleanupResources();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final clientName = widget.sessionData['employee_name'] ??
        widget.sessionData['username'] ??
        'Клиент';
    final pcName = widget.sessionData['pc_name'] ?? 'PC';
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

                  // Выбор монитора (если больше одного)
                  if (_screens.isNotEmpty)
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
                      const PopupMenuItem(value: 'win_d', child: Text('⊞ Win + D (Рабочий стол)', style: TextStyle(color: Colors.white))),
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
          if (!_isConnected && widget.numberMatch != null)
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
                      widget.numberMatch!,
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
                  child: _remoteRenderer.srcObject == null
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
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }
}
