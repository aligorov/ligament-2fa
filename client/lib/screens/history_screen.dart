import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import '../services/auth_state.dart';

class HistoryScreen extends StatelessWidget {
  const HistoryScreen({super.key});

  void _handleEmergencyRevoke(BuildContext context) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E293B),
        title: const Row(
          children: [
            Icon(Icons.warning_amber_rounded, color: Colors.redAccent),
            SizedBox(width: 8),
            Text('Это были не вы?', style: TextStyle(color: Colors.white, fontSize: 18)),
          ],
        ),
        content: const Text(
          'Если вы заметили подозрительную активность входа, немедленно выйдите из приложения. Все активные сессии на данном устройстве будут заблокированы.',
          style: TextStyle(color: Color(0xFFCBD5E1), fontSize: 14),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Отмена', style: TextStyle(color: Color(0xFF94A3B8))),
          ),
          ElevatedButton(
            onPressed: () async {
              Navigator.of(ctx).pop();
              final auth = context.read<AuthState>();
              await auth.logout();
            },
            style: ElevatedButton.styleFrom(backgroundColor: Colors.redAccent),
            child: const Text('Экстренный выход', style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );
  }

  void _showDetailsDialog(BuildContext context, Map<String, dynamic> item) {
    final eventTitle = item['event_title']?.toString() ?? _formatEventName(item['event']?.toString() ?? '');
    final resultTitle = item['result_title']?.toString() ?? (item['result'] == 'ok' ? 'Успешно' : 'Ошибка');
    final isSuccess = item['result'] == 'ok';
    final service = item['service']?.toString() ?? 'Корпоративный доступ';
    final clientIp = item['client_ip']?.toString() ?? item['ip']?.toString() ?? '—';
    final hostIp = item['host_ip']?.toString() ?? '';
    final location = item['location']?.toString() ?? clientIp;
    final device = item['device']?.toString() ?? 'Устройство пользователя';
    final browser = item['browser']?.toString() ?? '';
    final method = item['method']?.toString() ?? 'Пароль / 2FA';
    final tsStr = item['timestamp']?.toString();
    DateTime? ts;
    if (tsStr != null) {
      ts = DateTime.tryParse(tsStr)?.toLocal();
    }
    final df = DateFormat('dd.MM.yyyy HH:mm:ss');

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E293B),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: BorderSide(color: const Color(0xFF38BDF8).withValues(alpha: 0.3)),
        ),
        title: Row(
          children: [
            Icon(
              isSuccess ? Icons.check_circle_outline : Icons.error_outline,
              color: isSuccess ? const Color(0xFF10B981) : Colors.redAccent,
              size: 24,
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                eventTitle,
                style: const TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
        ),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              _detailRow(Icons.check, 'Статус:', resultTitle, isSuccess ? const Color(0xFF10B981) : Colors.redAccent),
              const Divider(color: Color(0xFF334155), height: 16),
              _detailRow(Icons.apps, 'Куда (сервис):', service, const Color(0xFF38BDF8)),
              const Divider(color: Color(0xFF334155), height: 16),
              _detailRow(Icons.wifi, 'IP клиента:', _formatIPWithPrivate(clientIp), Colors.white),
              if (hostIp.isNotEmpty && hostIp != clientIp) ...[
                const Divider(color: Color(0xFF334155), height: 16),
                _detailRow(Icons.dns, 'IP сервера:', _formatIPWithPrivate(hostIp), Colors.white),
              ],
              if (location.isNotEmpty && location != clientIp) ...[
                const Divider(color: Color(0xFF334155), height: 16),
                _detailRow(Icons.map, 'Сеть / Маршрут:', location, const Color(0xFF94A3B8)),
              ],
              const Divider(color: Color(0xFF334155), height: 16),
              _detailRow(Icons.devices, 'Устройство:', device, Colors.white),
              if (browser.isNotEmpty) ...[
                const Divider(color: Color(0xFF334155), height: 16),
                _detailRow(Icons.language, 'Клиент / Браузер:', browser, Colors.white),
              ],
              const Divider(color: Color(0xFF334155), height: 16),
              _detailRow(Icons.security, 'Способ 2FA:', method, const Color(0xFFF59E0B)),
              if (ts != null) ...[
                const Divider(color: Color(0xFF334155), height: 16),
                _detailRow(Icons.access_time, 'Время входа:', df.format(ts), const Color(0xFF94A3B8)),
              ],
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () {
              Navigator.of(ctx).pop();
              _handleEmergencyRevoke(context);
            },
            child: const Text('Это не я!', style: TextStyle(color: Colors.redAccent, fontWeight: FontWeight.bold)),
          ),
          ElevatedButton(
            onPressed: () => Navigator.of(ctx).pop(),
            style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF0284C7)),
            child: const Text('Закрыть', style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );
  }

  Widget _detailRow(IconData icon, String label, String value, Color valColor) {
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
            style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: valColor),
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

  static String _formatIPWithPrivate(String ip) {
    if (ip.isEmpty || ip == '—') return '—';
    if (_isPrivateIP(ip)) {
      return '$ip (внутренний IP)';
    }
    return ip;
  }

  Widget _badge({
    required String text,
    required Color color,
    IconData? icon,
  }) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: color.withValues(alpha: 0.25)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (icon != null) ...[
            Icon(icon, size: 11, color: color),
            const SizedBox(width: 4),
          ],
          Flexible(
            child: Text(
              text,
              style: TextStyle(fontSize: 11, color: color, fontWeight: FontWeight.w600),
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final auth = context.watch<AuthState>();
    final history = auth.history;
    final df = DateFormat('dd.MM.yyyy HH:mm:ss');

    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      appBar: AppBar(
        backgroundColor: const Color(0xFF1E293B),
        title: const Text('Журнал входов', style: TextStyle(color: Colors.white, fontSize: 18)),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh, color: Color(0xFF38BDF8)),
            onPressed: () => auth.loadHistory(),
            tooltip: 'Обновить',
          ),
        ],
      ),
      body: Column(
        children: [
          Container(
            margin: const EdgeInsets.all(16),
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: const Color(0xFFEF4444).withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: Colors.redAccent.withValues(alpha: 0.4)),
            ),
            child: Row(
              children: [
                const Icon(Icons.shield_outlined, color: Colors.redAccent, size: 28),
                const SizedBox(width: 12),
                const Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('Заметили чужой вход?', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 13)),
                      Text('Нажмите кнопку для экстренного отзыва сессии', style: TextStyle(color: Color(0xFFFCA5A5), fontSize: 11)),
                    ],
                  ),
                ),
                OutlinedButton(
                  onPressed: () => _handleEmergencyRevoke(context),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: Colors.redAccent,
                    side: const BorderSide(color: Colors.redAccent),
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                  ),
                  child: const Text('Это не я', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
                ),
              ],
            ),
          ),
          Expanded(
            child: history.isEmpty
                ? const Center(
                    child: Text('История событий пуста', style: TextStyle(color: Color(0xFF64748B))),
                  )
                : ListView.separated(
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                    itemCount: history.length,
                    separatorBuilder: (_, __) => const SizedBox(height: 10),
                    itemBuilder: (context, index) {
                      final item = history[index];
                      final isSuccess = item['result'] == 'ok';
                      final event = item['event']?.toString() ?? 'auth';
                      final eventTitle = item['event_title']?.toString() ?? _formatEventName(event);
                      final resultTitle = item['result_title']?.toString() ?? (isSuccess ? 'Успешно' : 'Ошибка');
                      final service = item['service']?.toString() ?? 'Корпоративный доступ';
                      final method = item['method']?.toString() ?? 'Пароль / 2FA';
                      final clientIp = item['client_ip']?.toString() ?? item['ip']?.toString() ?? '—';
                      final hostIp = item['host_ip']?.toString() ?? '';
                      final device = item['device']?.toString() ?? '';
                      final tsStr = item['timestamp']?.toString();
                      DateTime? ts;
                      if (tsStr != null) {
                        ts = DateTime.tryParse(tsStr)?.toLocal();
                      }

                      Color statusColor = const Color(0xFF10B981);
                      if (!isSuccess || resultTitle.contains('Отклонено') || resultTitle.contains('Ошибка')) {
                        statusColor = Colors.redAccent;
                      }

                      return InkWell(
                        onTap: () => _showDetailsDialog(context, item),
                        borderRadius: BorderRadius.circular(12),
                        child: Container(
                          padding: const EdgeInsets.all(14),
                          decoration: BoxDecoration(
                            color: const Color(0xFF1E293B),
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(
                              color: isSuccess
                                  ? const Color(0xFF334155)
                                  : Colors.redAccent.withValues(alpha: 0.3),
                            ),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              // 1. Верхняя строка: иконка статуса + заголовок + дата
                              Row(
                                children: [
                                  Container(
                                    padding: const EdgeInsets.all(6),
                                    decoration: BoxDecoration(
                                      color: statusColor.withValues(alpha: 0.15),
                                      shape: BoxShape.circle,
                                    ),
                                    child: Icon(
                                      isSuccess ? Icons.check_circle_outline : Icons.highlight_off,
                                      color: statusColor,
                                      size: 18,
                                    ),
                                  ),
                                  const SizedBox(width: 10),
                                  Expanded(
                                    child: Text(
                                      eventTitle,
                                      style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13, color: Colors.white),
                                      overflow: TextOverflow.ellipsis,
                                    ),
                                  ),
                                  if (ts != null)
                                    Text(
                                      df.format(ts),
                                      style: const TextStyle(fontSize: 11, color: Color(0xFF64748B)),
                                    ),
                                ],
                              ),
                              const SizedBox(height: 10),

                              // 2. Бейджи: Сервис («Куда») + Способ («Чем») + Статус
                              Wrap(
                                spacing: 6,
                                runSpacing: 6,
                                children: [
                                  _badge(
                                    text: service,
                                    color: const Color(0xFF38BDF8),
                                    icon: Icons.apps,
                                  ),
                                  _badge(
                                    text: method,
                                    color: const Color(0xFFF59E0B),
                                    icon: Icons.security,
                                  ),
                                  _badge(
                                    text: resultTitle,
                                    color: statusColor,
                                    icon: isSuccess ? Icons.check : Icons.close,
                                  ),
                                ],
                              ),
                              const SizedBox(height: 8),

                              // 3. Строка с IP и устройством («Где / Откуда»)
                              Row(
                                children: [
                                  const Icon(Icons.wifi, size: 13, color: Color(0xFF94A3B8)),
                                  const SizedBox(width: 4),
                                  Expanded(
                                    child: Text(
                                      hostIp.isNotEmpty && hostIp != clientIp
                                          ? 'Клиент: ${_formatIPWithPrivate(clientIp)} • Сервер: ${_formatIPWithPrivate(hostIp)}'
                                          : 'Клиент: ${_formatIPWithPrivate(clientIp)}',
                                      style: const TextStyle(fontSize: 11, color: Color(0xFF94A3B8)),
                                      overflow: TextOverflow.ellipsis,
                                    ),
                                  ),
                                ],
                              ),
                              if (device.isNotEmpty) ...[
                                const SizedBox(height: 4),
                                Row(
                                  children: [
                                    const Icon(Icons.devices, size: 13, color: Color(0xFF64748B)),
                                    const SizedBox(width: 4),
                                    Expanded(
                                      child: Text(
                                        device,
                                        style: const TextStyle(fontSize: 11, color: Color(0xFF64748B)),
                                        overflow: TextOverflow.ellipsis,
                                      ),
                                    ),
                                    const Icon(Icons.chevron_right, size: 16, color: Color(0xFF64748B)),
                                  ],
                                ),
                              ],
                            ],
                          ),
                        ),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }

  String _formatEventName(String raw) {
    switch (raw) {
      case 'app_login':
        return 'Вход в приложение';
      case 'app_push_decision':
        return 'Подтверждение 2FA входа';
      case 'tg_push':
        return 'Вход через Telegram';
      case 'login_ok':
        return 'Успешный вход в систему';
      case 'login_fail':
        return 'Неудачная попытка входа';
      case 'code_sent':
        return 'Отправлен одноразовый код';
      case 'code_fail':
        return 'Неверный 2FA код';
      case 'radius_auth':
        return 'Авторизация в сети Wi-Fi/VPN';
      case 'oidc_token':
        return 'Вход через SSO (OpenID)';
      case 'oidc_consent':
        return 'Предоставление доступа SSO';
      case 'api_start':
        return 'Запрос 2FA входа';
      case 'api_verify_ok':
        return 'Успешная 2FA авторизация';
      default:
        return raw;
    }
  }
}
