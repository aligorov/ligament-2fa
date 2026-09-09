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

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  int _currentIndex = 0;
  bool _modalShown = false;
  bool _supportModalShown = false;

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

  @override
  Widget build(BuildContext context) {
    final auth = context.watch<AuthState>();

    final pages = [
      _buildRequestsTab(auth),
      const AppsScreen(),
      const HistoryScreen(),
      const SettingsScreen(),
    ];

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
              isLabelVisible: auth.pendingChallenges.isNotEmpty,
              label: Text('${auth.pendingChallenges.length}'),
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
    final support = auth.support;

    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      appBar: AppBar(
        backgroundColor: const Color(0xFF1E293B),
        title: Row(
          children: [
            const Text('Ligament 2FA', style: TextStyle(color: Colors.white, fontSize: 18)),
            const Spacer(),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(
                color: auth.isOnline
                    ? const Color(0xFF10B981).withOpacity(0.15)
                    : const Color(0xFFEF4444).withOpacity(0.15),
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
      body: Column(
        children: [
          if (support.state != SupportSessionState.idle)
            _buildSupportSessionBanner(auth),
          Expanded(
            child: challenges.isEmpty
                ? Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Container(
                          padding: const EdgeInsets.all(24),
                          decoration: const BoxDecoration(
                            color: Color(0xFF1E293B),
                            shape: BoxShape.circle,
                          ),
                          child: const Icon(Icons.check_circle_outline, size: 64, color: Color(0xFF10B981)),
                        ),
                        const SizedBox(height: 20),
                        const Text(
                          'Нет активных запросов',
                          style: TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold),
                        ),
                        const SizedBox(height: 6),
                        const Text(
                          'При входе в корпоративную сеть окно появится автоматически',
                          style: TextStyle(color: Color(0xFF94A3B8), fontSize: 13),
                          textAlign: TextAlign.center,
                        ),
                      ],
                    ),
                  )
                : ListView.builder(
                    padding: const EdgeInsets.all(16),
                    itemCount: challenges.length,
                    itemBuilder: (context, index) {
                      final ch = challenges[index];
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
                    },
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildSupportSessionBanner(AuthState auth) {
    final support = auth.support;
    final is1C = support.category == '1c';
    final isActive = support.state == SupportSessionState.active;

    return Container(
      margin: const EdgeInsets.fromLTRB(16, 16, 16, 0),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: isActive
            ? const Color(0xFFEF4444).withOpacity(0.15)
            : (is1C ? const Color(0xFFF59E0B).withOpacity(0.12) : const Color(0xFF0284C7).withOpacity(0.12)),
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
