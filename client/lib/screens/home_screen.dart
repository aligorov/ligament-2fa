import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/auth_state.dart';
import '../services/support_service.dart';
import 'approval_modal.dart';
import 'apps_screen.dart';
import 'history_screen.dart';
import 'settings_screen.dart';
import 'support_approval_modal.dart';
import 'support_dialog.dart';
import 'support_operator_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  int _currentIndex = 0;
  bool _modalShown = false;
  bool _supportModalShown = false;
  bool _connectingToSession = false;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final auth = context.watch<AuthState>();
    if (auth.activePrompt != null && !_modalShown) {
      _modalShown = true;
      final prompt = auth.activePrompt!;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!mounted) {
          _modalShown = false;
          return;
        }
        showDialog(
          context: context,
          barrierDismissible: true,
          builder: (_) => ApprovalModal(prompt: prompt),
        ).then((_) {
          _modalShown = false;
          if (mounted) {
            context.read<AuthState>().dismissPrompt(prompt['challenge_id']?.toString());
          }
        });
      });
    }

    if (auth.activeSupportPrompt != null && !_supportModalShown) {
      _supportModalShown = true;
      final prompt = auth.activeSupportPrompt!;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!mounted) {
          _supportModalShown = false;
          return;
        }
        showDialog(
          context: context,
          barrierDismissible: false,
          builder: (_) => SupportApprovalModal(prompt: prompt),
        ).then((_) {
          _supportModalShown = false;
        });
      });
    }
  }

  Future<void> _connectAsOperator(AuthState auth, Map<String, dynamic> sess) async {
    final sessId = sess['id']?.toString();
    if (sessId == null || _connectingToSession) return;

    setState(() => _connectingToSession = true);
    try {
      final res = await auth.connectToSupportSession(sessId);
      final numberMatch = res['number_match']?.toString();

      if (mounted) {
        Navigator.of(context).push(
          MaterialPageRoute(
            builder: (_) => SupportOperatorScreen(
              sessionId: sessId,
              numberMatch: numberMatch,
              sessionData: sess,
            ),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFFEF4444),
            content: Text('Ошибка подключения: $e'),
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _connectingToSession = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final auth = context.watch<AuthState>();

    final pages = [
      _buildRequestsTab(auth),
      const AppsScreen(),
      const HistoryScreen(),
      const SettingsScreen(),
    ];

    final badgeCount = auth.pendingChallenges.length + (auth.isEngineer ? auth.supportQueue.length : 0);

    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      body: pages[_currentIndex],
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: _currentIndex,
        onTap: (idx) => setState(() => _currentIndex = idx),
        backgroundColor: const Color(0xFF1E293B),
        selectedItemColor: const Color(0xFF38BDF8),
        unselectedItemColor: const Color(0xFF64748B),
        type: BottomNavigationBarType.fixed,
        items: [
          BottomNavigationBarItem(
            icon: Badge(
              isLabelVisible: badgeCount > 0,
              label: Text('$badgeCount'),
              child: const Icon(Icons.shield_outlined),
            ),
            label: 'Запросы',
          ),
          const BottomNavigationBarItem(
            icon: Icon(Icons.apps_outlined),
            label: 'SSO Сервисы',
          ),
          const BottomNavigationBarItem(
            icon: Icon(Icons.history_outlined),
            label: 'Журнал',
          ),
          const BottomNavigationBarItem(
            icon: Icon(Icons.tune_outlined),
            label: 'Настройки',
          ),
        ],
      ),
    );
  }

  Widget _buildRequestsTab(AuthState auth) {
    final challenges = auth.pendingChallenges;
    final supportQueue = auth.supportQueue;
    final support = auth.support;
    final isEngineer = auth.isEngineer;
    final badge = auth.engineerBadge;

    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      appBar: AppBar(
        backgroundColor: const Color(0xFF1E293B),
        title: Row(
          children: [
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                const Text('Ligament 2FA', style: TextStyle(color: Colors.white, fontSize: 17, fontWeight: FontWeight.bold)),
                if (badge != null)
                  Container(
                    margin: const EdgeInsets.only(top: 2),
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: auth.isAdmin
                          ? const Color(0xFF8B5CF6).withValues(alpha: 0.25)
                          : (auth.is1CEngineer ? const Color(0xFFF59E0B).withValues(alpha: 0.25) : const Color(0xFF0284C7).withValues(alpha: 0.25)),
                      borderRadius: BorderRadius.circular(4),
                      border: Border.all(
                        color: auth.isAdmin
                            ? const Color(0xFF8B5CF6)
                            : (auth.is1CEngineer ? const Color(0xFFF59E0B) : const Color(0xFF38BDF8)),
                        width: 1,
                      ),
                    ),
                    child: Text(
                      badge,
                      style: TextStyle(
                        fontSize: 10,
                        fontWeight: FontWeight.bold,
                        color: auth.isAdmin
                            ? const Color(0xFFA78BFA)
                            : (auth.is1CEngineer ? const Color(0xFFFBBF24) : const Color(0xFF38BDF8)),
                      ),
                    ),
                  ),
              ],
            ),
            const Spacer(),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(
                color: auth.isOnline
                    ? const Color(0xFF10B981).withValues(alpha: 0.15)
                    : const Color(0xFFEF4444).withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Row(
                children: [
                  Container(
                    width: 8,
                    height: 8,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: auth.isOnline ? const Color(0xFF10B981) : const Color(0xFFEF4444),
                    ),
                  ),
                  const SizedBox(width: 6),
                  Text(
                    auth.isOnline ? 'Online' : 'Offline',
                    style: TextStyle(
                      fontSize: 11,
                      fontWeight: FontWeight.bold,
                      color: auth.isOnline ? const Color(0xFF10B981) : const Color(0xFFEF4444),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 8),
            ElevatedButton.icon(
              onPressed: () {
                showDialog(
                  context: context,
                  builder: (_) => const SupportDialog(),
                );
              },
              icon: const Icon(Icons.support_agent, size: 16),
              label: const Text('SOS', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFFEF4444),
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                minimumSize: Size.zero,
                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
              ),
            ),
          ],
        ),
      ),
      body: RefreshIndicator(
        onRefresh: () => auth.refreshAll(),
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            if (support.state != SupportSessionState.idle)
              _buildSupportSessionBanner(auth),

            // РАЗДЕЛ ДЛЯ ИНЖЕНЕРОВ: Входящие заявки на удаленную помощь
            if (isEngineer) ...[
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.headset_mic_outlined, color: Color(0xFF38BDF8), size: 20),
                      const SizedBox(width: 8),
                      const Text(
                        'Входящие SOS-обращения',
                        style: TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                      ),
                      if (supportQueue.isNotEmpty) ...[
                        const SizedBox(width: 8),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                          decoration: BoxDecoration(
                            color: const Color(0xFFEF4444),
                            borderRadius: BorderRadius.circular(10),
                          ),
                          child: Text(
                            '${supportQueue.length}',
                            style: const TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold),
                          ),
                        ),
                      ],
                    ],
                  ),
                  IconButton(
                    icon: const Icon(Icons.refresh, size: 18, color: Color(0xFF94A3B8)),
                    tooltip: 'Обновить очередь',
                    onPressed: () => auth.loadSupportQueue(),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              if (supportQueue.isEmpty)
                Container(
                  padding: const EdgeInsets.all(16),
                  margin: const EdgeInsets.only(bottom: 20),
                  decoration: BoxDecoration(
                    color: const Color(0xFF1E293B),
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(color: const Color(0xFF334155)),
                  ),
                  child: const Row(
                    children: [
                      Icon(Icons.check_circle_outline, color: Color(0xFF10B981), size: 24),
                      SizedBox(width: 12),
                      Expanded(
                        child: Text(
                          'Очередь обращений пуста. Новые запросы сотрудников появятся здесь.',
                          style: TextStyle(color: Color(0xFF94A3B8), fontSize: 12),
                        ),
                      ),
                    ],
                  ),
                )
              else
                ...supportQueue.map((sess) => _buildQueueItem(auth, sess)),
              const SizedBox(height: 16),
            ],

            // РАЗДЕЛ 2FA ЗАПРОСОВ
            const Row(
              children: [
                Icon(Icons.lock_outline, color: Color(0xFF38BDF8), size: 20),
                SizedBox(width: 8),
                Text(
                  'Запросы подтверждения входа (2FA)',
                  style: TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                ),
              ],
            ),
            const SizedBox(height: 12),

            if (challenges.isEmpty)
              Container(
                padding: const EdgeInsets.symmetric(vertical: 36, horizontal: 16),
                decoration: BoxDecoration(
                  color: const Color(0xFF1E293B),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: const Color(0xFF334155)),
                ),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Container(
                      padding: const EdgeInsets.all(18),
                      decoration: const BoxDecoration(
                        color: Color(0xFF0F172A),
                        shape: BoxShape.circle,
                      ),
                      child: const Icon(Icons.verified_user_outlined, size: 48, color: Color(0xFF10B981)),
                    ),
                    const SizedBox(height: 14),
                    const Text(
                      'Нет активных 2FA запросов',
                      style: TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 4),
                    const Text(
                      'При входе в корпоративную систему окно подтверждения появится автоматически',
                      style: TextStyle(color: Color(0xFF94A3B8), fontSize: 12),
                      textAlign: TextAlign.center,
                    ),
                  ],
                ),
              )
            else
              ...challenges.map((ch) => _buildChallengeItem(auth, ch)),
          ],
        ),
      ),
    );
  }

  Widget _buildQueueItem(AuthState auth, Map<String, dynamic> sess) {
    final is1C = sess['category'] == '1c';
    final clientName = sess['employee_name'] ?? sess['username'] ?? 'Сотрудник';
    final pcName = sess['pc_name'] ?? '—';
    final osName = sess['os_name'] ?? '—';
    final ip = sess['ip'] ?? '—';
    final summary = sess['problem_summary'] ?? 'Запрос помощи';
    final fullControl = sess['access_mode'] == 'full_control';

    return Card(
      color: const Color(0xFF1E293B),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: BorderSide(
          color: is1C ? const Color(0xFFF59E0B) : const Color(0xFF0284C7),
          width: 1.5,
        ),
      ),
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: is1C
                        ? const Color(0xFFF59E0B).withValues(alpha: 0.2)
                        : const Color(0xFF0284C7).withValues(alpha: 0.2),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                      color: is1C ? const Color(0xFFF59E0B) : const Color(0xFF38BDF8),
                    ),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        is1C ? Icons.analytics_outlined : Icons.computer,
                        size: 14,
                        color: is1C ? const Color(0xFFF59E0B) : const Color(0xFF38BDF8),
                      ),
                      const SizedBox(width: 4),
                      Text(
                        is1C ? 'Поддержка 1С' : 'IT-служба',
                        style: TextStyle(
                          color: is1C ? const Color(0xFFF59E0B) : const Color(0xFF38BDF8),
                          fontSize: 11,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 8),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
                  decoration: BoxDecoration(
                    color: fullControl
                        ? const Color(0xFF10B981).withValues(alpha: 0.15)
                        : const Color(0xFF64748B).withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: Text(
                    fullControl ? '🎮 Полный доступ' : '👀 Просмотр',
                    style: TextStyle(
                      color: fullControl ? const Color(0xFF10B981) : const Color(0xFF94A3B8),
                      fontSize: 10,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                const Spacer(),
                Text(
                  sess['status'] == 'connecting' ? '⚡ Подключение...' : '⏳ Ожидает',
                  style: TextStyle(
                    color: sess['status'] == 'connecting' ? const Color(0xFF38BDF8) : const Color(0xFFF59E0B),
                    fontSize: 11,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 10),
            Text(
              clientName,
              style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 15),
            ),
            const SizedBox(height: 2),
            Text(
              'ПК: $pcName • ОС: $osName • IP: $ip',
              style: const TextStyle(color: Color(0xFF94A3B8), fontSize: 11),
            ),
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: const Color(0xFF0F172A),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Icon(Icons.chat_bubble_outline, size: 14, color: Color(0xFF64748B)),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      summary,
                      style: const TextStyle(color: Color(0xFFCBD5E1), fontSize: 12),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: _connectingToSession ? null : () => _connectAsOperator(auth, sess),
                icon: const Icon(Icons.desktop_windows, size: 16),
                label: const Text('Подключиться к экрану', style: TextStyle(fontWeight: FontWeight.bold)),
                style: ElevatedButton.styleFrom(
                  backgroundColor: is1C ? const Color(0xFFF59E0B) : const Color(0xFF0284C7),
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(vertical: 12),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildChallengeItem(AuthState auth, Map<String, dynamic> ch) {
    final meta = ch['metadata'] as Map<String, dynamic>? ?? {};

    return Card(
      color: const Color(0xFF1E293B),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      margin: const EdgeInsets.only(bottom: 12),
      child: ListTile(
        contentPadding: const EdgeInsets.all(16),
        leading: const CircleAvatar(
          backgroundColor: Color(0xFF0284C7),
          child: Icon(Icons.security, color: Colors.white),
        ),
        title: Text(
          ch['purpose']?.toString() ?? 'Запрос входа',
          style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.white),
        ),
        subtitle: Text(
          'IP: ${meta['ip'] ?? '—'} • ${ch['expires_in_seconds']} сек',
          style: const TextStyle(color: Color(0xFF94A3B8)),
        ),
        trailing: ElevatedButton(
          onPressed: () {
            if (_modalShown) return;
            _modalShown = true;
            final promptData = {
              'challenge_id': ch['id'],
              'who': meta['username'] ?? auth.currentUser?['username'],
              'ip': meta['ip'] ?? '—',
              'ua': meta['ua'] ?? '—',
              'service': ch['purpose'] ?? '2FA Login',
              'number_match': meta['number_match'],
              'expires_in_seconds': ch['expires_in_seconds'],
            };
            final currentAuth = context.read<AuthState>();
            showDialog(
              context: context,
              barrierDismissible: true,
              builder: (_) => ApprovalModal(prompt: promptData),
            ).then((_) {
              _modalShown = false;
              if (mounted) {
                currentAuth.dismissPrompt(ch['id']?.toString());
              }
            });
          },
          style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF0284C7)),
          child: const Text('Открыть'),
        ),
      ),
    );
  }

  Widget _buildSupportSessionBanner(AuthState auth) {
    final support = auth.support;
    final is1C = support.category == '1c';
    final isActive = support.state == SupportSessionState.active;

    return Container(
      margin: const EdgeInsets.only(bottom: 16),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: isActive
            ? const Color(0xFFEF4444).withValues(alpha: 0.15)
            : (is1C ? const Color(0xFFF59E0B).withValues(alpha: 0.12) : const Color(0xFF0284C7).withValues(alpha: 0.12)),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: isActive
              ? const Color(0xFFEF4444)
              : (is1C ? const Color(0xFFF59E0B) : const Color(0xFF38BDF8)),
          width: 1.5,
        ),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: isActive
                  ? const Color(0xFFEF4444)
                  : (is1C ? const Color(0xFFF59E0B) : const Color(0xFF0284C7)),
              shape: BoxShape.circle,
            ),
            child: Icon(
              isActive ? Icons.screen_share : Icons.hourglass_top,
              color: Colors.white,
              size: 20,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  isActive
                      ? '🔴 Идет удаленный сеанс (${is1C ? '1С' : 'IT'})'
                      : '⏳ Заявка на помощь (${is1C ? '1С-поддержка' : 'IT-служба'})',
                  style: const TextStyle(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 13,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  isActive
                      ? 'Экран транслируется инженеру поддержки'
                      : (support.problemSummary?.isNotEmpty == true
                          ? '"${support.problemSummary}"'
                          : 'Ожидание подключения инженера...'),
                  style: const TextStyle(color: Color(0xFFCBD5E1), fontSize: 11),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          const SizedBox(width: 8),
          OutlinedButton(
            onPressed: () => auth.endSupport(),
            style: OutlinedButton.styleFrom(
              foregroundColor: isActive ? const Color(0xFFEF4444) : const Color(0xFF94A3B8),
              side: BorderSide(
                color: isActive ? const Color(0xFFEF4444) : const Color(0xFF64748B),
              ),
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              minimumSize: Size.zero,
              tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
            ),
            child: Text(
              isActive ? 'Завершить' : 'Отменить',
              style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
            ),
          ),
        ],
      ),
    );
  }
}
