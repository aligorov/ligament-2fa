import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/auth_state.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final auth = context.watch<AuthState>();
    final user = auth.currentUser ?? {};
    final posture = auth.currentPosture ?? {};
    final isGpoLocked = auth.gpo.enforcedServerUrl != null;
    final allowExit = auth.gpo.allowExit;

    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      appBar: AppBar(
        backgroundColor: const Color(0xFF1E293B),
        title: const Text('Безопасность и профиль', style: TextStyle(color: Colors.white, fontSize: 18)),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Карточка пользователя
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: const Color(0xFF1E293B),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: const Color(0xFF334155)),
            ),
            child: Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: const Color(0xFF38BDF8).withOpacity(0.15),
                    shape: BoxShape.circle,
                  ),
                  child: const Icon(Icons.person, color: Color(0xFF38BDF8), size: 32),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        user['display_name'] ?? user['username'] ?? 'Пользователь',
                        style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16, color: Colors.white),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        'Роль: ${user['role'] ?? 'user'}',
                        style: const TextStyle(fontSize: 12, color: Color(0xFF94A3B8)),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        'Сервер: ${auth.serverUrl ?? '—'}',
                        style: const TextStyle(fontSize: 11, color: Color(0xFF64748B)),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // Карточка GPO статуса
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: const Color(0xFF1E293B),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: const Color(0xFF334155)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Row(
                  children: [
                    Icon(Icons.policy_outlined, color: Color(0xFF38BDF8), size: 20),
                    SizedBox(width: 8),
                    Text('Групповые политики Windows (GPO)', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 14)),
                  ],
                ),
                const SizedBox(height: 12),
                _statusTile(
                  'Централизованное управление',
                  isGpoLocked ? 'Активно (ADMX/GPO)' : 'Не назначено',
                  isGpoLocked ? Colors.greenAccent : Colors.grey,
                ),
                _statusTile(
                  'Требование Windows Hello',
                  auth.gpo.requireWindowsHello ? 'Включено' : 'Выключено',
                  auth.gpo.requireWindowsHello ? Colors.greenAccent : Colors.grey,
                ),
                _statusTile(
                  'Требование BitLocker',
                  auth.gpo.requireBitLocker ? 'Включено' : 'Выключено',
                  auth.gpo.requireBitLocker ? Colors.greenAccent : Colors.grey,
                ),
                _statusTile(
                  'Выход из приложения',
                  allowExit ? 'Разрешен' : 'Запрещен политикой GPO',
                  allowExit ? Colors.grey : Colors.amber,
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // Карточка телеметрии устройства
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: const Color(0xFF1E293B),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: const Color(0xFF334155)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    const Row(
                      children: [
                        Icon(Icons.health_and_safety_outlined, color: Color(0xFF10B981), size: 20),
                        SizedBox(width: 8),
                        Text('Телеметрия безопасности', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 14)),
                      ],
                    ),
                    IconButton(
                      icon: const Icon(Icons.refresh, size: 18, color: Color(0xFF38BDF8)),
                      onPressed: () => auth.checkPosture(),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                _statusTile(
                  'Статус соответствия',
                  auth.isCompliant ? 'Соответствует корпоративным политикам' : 'Нарушение комплаенса',
                  auth.isCompliant ? Colors.greenAccent : Colors.redAccent,
                ),
                if (posture['bitlocker'] != null)
                  _statusTile(
                    'Шифрование BitLocker',
                    posture['bitlocker'] == 'encrypted' ? 'Защищен (100%)' : 'Отключен',
                    posture['bitlocker'] == 'encrypted' ? Colors.greenAccent : Colors.redAccent,
                  ),
                if (posture['defender'] != null)
                  _statusTile(
                    'Windows Defender',
                    posture['defender'] == 'active' ? 'Активен' : 'Отключен',
                    posture['defender'] == 'active' ? Colors.greenAccent : Colors.redAccent,
                  ),
                if (posture['firewall'] != null)
                  _statusTile(
                    'Брандмауэр Windows',
                    posture['firewall'] == 'active' ? 'Включен' : 'Отключен',
                    posture['firewall'] == 'active' ? Colors.greenAccent : Colors.redAccent,
                  ),
                if (posture['rooted'] != null)
                  _statusTile(
                    'Root / Jailbreak',
                    posture['rooted'] == true ? 'ОБНАРУЖЕН!' : 'Целостность чиста',
                    posture['rooted'] == true ? Colors.redAccent : Colors.greenAccent,
                  ),
              ],
            ),
          ),
          const SizedBox(height: 24),

          // Кнопка выхода
          ElevatedButton.icon(
            onPressed: allowExit ? () => auth.logout() : null,
            icon: const Icon(Icons.logout),
            label: Text(allowExit ? 'Выйти из учетной записи' : 'Выход заблокирован системным администратором'),
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.redAccent.withOpacity(0.8),
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(vertical: 14),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
            ),
          ),
        ],
      ),
    );
  }

  Widget _statusTile(String title, String value, Color color) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(title, style: const TextStyle(fontSize: 13, color: Color(0xFF94A3B8))),
          Text(value, style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold, color: color)),
        ],
      ),
    );
  }
}
