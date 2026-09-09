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
              color: const Color(0xFFEF4444).withOpacity(0.12),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: Colors.redAccent.withOpacity(0.4)),
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
                    separatorBuilder: (_, __) => const Divider(color: Color(0xFF1E293B), height: 1),
                    itemBuilder: (context, index) {
                      final item = history[index];
                      final isSuccess = item['result'] == 'ok';
                      final event = item['event']?.toString() ?? 'auth';
                      final ip = item['ip']?.toString() ?? '—';
                      final tsStr = item['timestamp']?.toString();
                      DateTime? ts;
                      if (tsStr != null) {
                        ts = DateTime.tryParse(tsStr)?.toLocal();
                      }

                      return Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: const Color(0xFF1E293B),
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: Row(
                          children: [
                            Container(
                              padding: const EdgeInsets.all(8),
                              decoration: BoxDecoration(
                                color: isSuccess
                                    ? const Color(0xFF10B981).withOpacity(0.15)
                                    : Colors.redAccent.withOpacity(0.15),
                                shape: BoxShape.circle,
                              ),
                              child: Icon(
                                isSuccess ? Icons.check_circle_outline : Icons.highlight_off,
                                color: isSuccess ? const Color(0xFF10B981) : Colors.redAccent,
                                size: 22,
                              ),
                            ),
                            const SizedBox(width: 12),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    _formatEventName(event),
                                    style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13, color: Colors.white),
                                  ),
                                  const SizedBox(height: 2),
                                  Text(
                                    'IP: $ip',
                                    style: const TextStyle(fontSize: 12, color: Color(0xFF94A3B8)),
                                  ),
                                ],
                              ),
                            ),
                            if (ts != null)
                              Text(
                                df.format(ts),
                                style: const TextStyle(fontSize: 11, color: Color(0xFF64748B)),
                              ),
                          ],
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
      case 'login_ok':
        return 'Успешный вход в систему';
      case 'login_fail':
        return 'Неудачная попытка входа';
      case 'code_sent':
        return 'Отправлен одноразовый код';
      case 'code_fail':
        return 'Неверный 2FA код';
      default:
        return raw;
    }
  }
}
