import 'dart:async';
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/auth_state.dart';

class ApprovalModal extends StatefulWidget {
  final Map<String, dynamic> prompt;
  const ApprovalModal({super.key, required this.prompt});

  @override
  State<ApprovalModal> createState() => _ApprovalModalState();
}

class _ApprovalModalState extends State<ApprovalModal> {
  /// Актуальный prompt: инициализируется виджетом, затем отслеживает
  /// AuthState.activePrompt — челлендж могут доставить/обновить и WS, и
  /// polling-фолбэк. Новый челлендж при открытом окне заменяет содержимое
  /// ЭТОГО же диалога (без второго окна); исчезнувший — закрывает окно
  /// (например, подтверждено в Telegram или истёк TTL).
  late Map<String, dynamic> _prompt;
  AuthState? _auth;
  late int _secondsLeft;
  Timer? _timer;
  String? _selectedMatch;
  bool _isProcessing = false;
  bool _closing = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _prompt = widget.prompt;
    _secondsLeft = _prompt['expires_in_seconds'] as int? ?? 60;
    _restartTimer();
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_auth == null) {
      _auth = context.read<AuthState>();
      _auth!.addListener(_onAuthStateChanged);
    }
  }

  @override
  void dispose() {
    _auth?.removeListener(_onAuthStateChanged);
    _timer?.cancel();
    super.dispose();
  }

  void _onAuthStateChanged() {
    if (!mounted || _closing) return;
    final live = _auth?.activePrompt;
    if (live == null) {
      // Челлендж закрыт в другом канале (Telegram / истёк / подтверждён) —
      // закрываем окно.
      _close();
      return;
    }
    final liveId = live['challenge_id']?.toString();
    final curId = _prompt['challenge_id']?.toString();
    if (liveId != null && liveId != curId) {
      // Новый челлендж пришёл, пока окно открыто: обновляем содержимое
      // этого же окна вместо второго диалога.
      setState(() {
        _prompt = Map<String, dynamic>.from(live);
        _selectedMatch = null;
        _error = null;
        _isProcessing = false;
        _secondsLeft = live['expires_in_seconds'] as int? ?? 60;
      });
      _restartTimer();
    } else if (liveId != null && liveId == curId) {
      // Тот же челлендж: подтягиваем актуальный остаток TTL из polling
      // (локальный отсчёт может отставать/спешить).
      final ttl = live['expires_in_seconds'] as int?;
      if (ttl != null && ttl > _secondsLeft && !_isProcessing) {
        setState(() => _secondsLeft = ttl);
      }
    }
  }

  void _restartTimer() {
    _timer?.cancel();
    _timer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (_secondsLeft <= 1) {
        timer.cancel();
        _close();
      } else {
        setState(() => _secondsLeft--);
      }
    });
  }

  /// Закрытие окна строго один раз: таймер, исчезновение prompt и завершение
  /// решения могут сработать вместе — повторный pop снял бы чужой маршрут.
  void _close() {
    if (_closing || !mounted) return;
    _closing = true;
    Navigator.of(context, rootNavigator: true).maybePop();
  }

  String _translateError(dynamic e) {
    final msg = e.toString();
    if (msg.contains('device_non_compliant')) {
      return 'Вход заблокирован: устройство не соответствует требованиям безопасности (отключен BitLocker или обнаружен root)';
    }
    if (msg.contains('number_match_mismatch')) {
      return 'Выбрано неверное число подтверждения';
    }
    if (msg.contains('challenge_expired')) {
      return 'Время действия запроса истекло';
    }
    if (msg.contains('Windows Hello')) {
      return 'Подтверждение Windows Hello отклонено';
    }
    return 'Ошибка: $e';
  }

  Future<void> _handleDecision(bool approve) async {
    final expectedMatch = _prompt['number_match']?.toString();
    if (approve && expectedMatch != null && expectedMatch.isNotEmpty) {
      if (_selectedMatch == null || _selectedMatch != expectedMatch) {
        setState(() => _error = 'Выберите верный номер, показанный на экране входа');
        return;
      }
    }

    setState(() {
      _isProcessing = true;
      _error = null;
    });

    final auth = context.read<AuthState>();
    final challengeId = _prompt['challenge_id']?.toString() ?? '';

    try {
      await auth.submitDecision(
        challengeId: challengeId,
        approve: approve,
        selectedNumberMatch: _selectedMatch,
      );
      _close();
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = _translateError(e);
          _isProcessing = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final expectedMatch = _prompt['number_match']?.toString();
    final who = _prompt['who']?.toString() ?? 'Сотрудник';
    final clientIp = _prompt['client_ip']?.toString() ?? _prompt['ip']?.toString() ?? '—';
    final hostIp = _prompt['host_ip']?.toString();
    final host = _prompt['host']?.toString();
    final service = _prompt['service']?.toString() ?? 'Корпоративный доступ';
    final device = _prompt['device']?.toString() ?? _formatDeviceUA(_prompt['ua']?.toString() ?? '');

    // Для Number Matching генерируем 3 уникальных варианта: верный + 2 правдоподобных ложных
    final options = <String>[];
    if (expectedMatch != null && expectedMatch.isNotEmpty) {
      final set = <String>{expectedMatch};
      final rnd = Random(expectedMatch.hashCode);
      while (set.length < 3) {
        final cand = (rnd.nextInt(90) + 10).toString();
        set.add(cand);
      }
      options.addAll(set);
      options.sort();
    }

    return Dialog(
      backgroundColor: const Color(0xFF1E293B),
      elevation: 24,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
          side: BorderSide(color: const Color(0xFF38BDF8).withValues(alpha: 0.4), width: 2),
      ),
      insetPadding: const EdgeInsets.all(16),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 440),
        child: Container(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Заголовок, таймер и кнопка закрытия
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Expanded(
                    child: Row(
                      children: [
                        Container(
                          padding: const EdgeInsets.all(8),
                          decoration: BoxDecoration(
                            color: const Color(0xFF38BDF8).withValues(alpha: 0.15),
                            shape: BoxShape.circle,
                          ),
                          child: const Icon(Icons.security, color: Color(0xFF38BDF8), size: 24),
                        ),
                        const SizedBox(width: 10),
                        const Flexible(
                          child: Text(
                            'Запрос на вход',
                            style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: Colors.white),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                      ],
                    ),
                  ),
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                        decoration: BoxDecoration(
                          color: const Color(0xFF0F172A),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(color: const Color(0xFF475569)),
                        ),
                        child: Text(
                          '$_secondsLeft с',
                          style: TextStyle(
                            fontWeight: FontWeight.bold,
                            color: _secondsLeft < 15 ? Colors.redAccent : const Color(0xFF38BDF8),
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      IconButton(
                        icon: const Icon(Icons.close, color: Color(0xFF94A3B8), size: 20),
                        tooltip: 'Закрыть',
                        padding: EdgeInsets.zero,
                        constraints: const BoxConstraints(),
                        onPressed: () {
                          Navigator.of(context, rootNavigator: true).maybePop();
                        },
                      ),
                    ],
                  ),
                ],
              ),
              const Divider(color: Color(0xFF334155), height: 28),

              // Карточка метаданных
              Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: const Color(0xFF0F172A),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: const Color(0xFF334155)),
                ),
                child: Column(
                  children: [
                    _metaRow(Icons.apps, 'Куда (сервис):', service),
                    const SizedBox(height: 8),
                    _metaRow(Icons.person, 'Пользователь:', who),
                    const SizedBox(height: 8),
                    _metaRow(Icons.wifi, 'IP клиента:', _formatIPBadge(clientIp)),
                    if (hostIp != null && hostIp.isNotEmpty && hostIp != clientIp) ...[
                      const SizedBox(height: 8),
                      _metaRow(Icons.dns, 'Сервер (IP):', _formatIPBadge(hostIp)),
                    ],
                    if (host != null && host.isNotEmpty) ...[
                      const SizedBox(height: 8),
                      _metaRow(Icons.computer, 'Имя сервера:', host),
                    ],
                    const SizedBox(height: 8),
                    _metaRow(Icons.devices, 'Устройство:', device),
                  ],
                ),
              ),

              // Number Matching (Защита от push-fatigue)
              if (expectedMatch != null && expectedMatch.isNotEmpty) ...[
                const SizedBox(height: 20),
                const Text(
                  'Защита от случайных нажатий (Number Match):',
                  style: TextStyle(fontSize: 13, color: Color(0xFF94A3B8)),
                ),
                const SizedBox(height: 6),
                const Text(
                  'Выберите число, отображаемое на экране компьютера:',
                  style: TextStyle(fontSize: 12, color: Colors.white70),
                ),
                const SizedBox(height: 12),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: options.map((opt) {
                    final isSelected = _selectedMatch == opt;
                    return InkWell(
                      onTap: () => setState(() => _selectedMatch = opt),
                      borderRadius: BorderRadius.circular(10),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
                        decoration: BoxDecoration(
                          color: isSelected ? const Color(0xFF0284C7) : const Color(0xFF0F172A),
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(
                            color: isSelected ? const Color(0xFF38BDF8) : const Color(0xFF475569),
                            width: 2,
                          ),
                        ),
                        child: Text(
                          opt,
                          style: TextStyle(
                            fontSize: 20,
                            fontWeight: FontWeight.bold,
                            color: isSelected ? Colors.white : const Color(0xFFE2E8F0),
                          ),
                        ),
                      ),
                    );
                  }).toList(),
                ),
              ],

              if (_error != null) ...[
                const SizedBox(height: 16),
                Text(_error!, style: const TextStyle(color: Colors.redAccent, fontSize: 13)),
              ],

              const SizedBox(height: 24),

              // Кнопки решений
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton(
                      onPressed: _isProcessing ? null : () => _handleDecision(false),
                      style: OutlinedButton.styleFrom(
                        foregroundColor: Colors.redAccent,
                        side: const BorderSide(color: Colors.redAccent),
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                      ),
                      child: const Text('Отклонить', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 15)),
                    ),
                  ),
                  const SizedBox(width: 14),
                  Expanded(
                    child: ElevatedButton(
                      onPressed: _isProcessing ? null : () => _handleDecision(true),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFF10B981),
                        foregroundColor: Colors.white,
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                      ),
                      child: _isProcessing
                          ? const SizedBox(height: 18, width: 18, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                          : const Text('Принять', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 15)),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _metaRow(IconData icon, String label, String value) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(icon, size: 16, color: const Color(0xFF94A3B8)),
        const SizedBox(width: 8),
        Text(label, style: const TextStyle(fontSize: 12, color: Color(0xFF94A3B8))),
        const SizedBox(width: 8),
        Expanded(
          child: Text(
            value,
            textAlign: TextAlign.end,
            style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: Colors.white),
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );
  }

  static bool _isPrivateIP(String ip) {
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip == '127.0.0.1' || ip == '::1') {
      return true;
    }
    if (ip.startsWith('172.')) {
      final parts = ip.split('.');
      if (parts.length >= 2) {
        final second = int.tryParse(parts[1]) ?? 0;
        if (second >= 16 && second <= 31) return true;
      }
    }
    return false;
  }

  static String _formatIPBadge(String ip) {
    if (ip == '—' || ip.isEmpty) return '—';
    if (_isPrivateIP(ip)) {
      return '$ip (внутренний IP)';
    }
    return ip;
  }

  static String _formatDeviceUA(String raw) {
    if (raw.isEmpty || raw == '—') return 'Рабочая станция';
    if (raw.contains('CredentialProvider')) return 'Windows (Credential Provider)';
    if (raw.contains('Windows NT 10.0')) return 'Windows 10 / 11';
    if (raw.contains('Macintosh') || raw.contains('Mac OS')) return 'macOS';
    if (raw.contains('Android')) return 'Android Устройство';
    if (raw.contains('iPhone') || raw.contains('iPad')) return 'iOS Устройство';
    if (raw.contains('Linux')) return 'Linux';
    return raw;
  }
}
