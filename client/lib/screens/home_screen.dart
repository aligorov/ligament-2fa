import 'dart:io';
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
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
                icon: Icon(fullControl ? Icons.sports_esports : Icons.desktop_windows, size: 18),
                label: Text(
                  fullControl ? '🎮 Подключиться и управлять' : '👁 Подключиться (просмотр)',
                  style: const TextStyle(fontWeight: FontWeight.bold),
                ),
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
          if (isActive) ...[
            ElevatedButton.icon(
              onPressed: () => _showInSessionChatModal(context, auth),
              icon: const Icon(Icons.chat_bubble_outline, size: 13),
              label: Text(
                support.unreadChatCount > 0
                    ? 'Чат (${support.unreadChatCount})'
                    : 'Чат',
                style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
              ),
              style: ElevatedButton.styleFrom(
                backgroundColor: support.unreadChatCount > 0
                    ? const Color(0xFF3B82F6)
                    : const Color(0xFF334155),
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
                minimumSize: Size.zero,
                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
              ),
            ),
            const SizedBox(width: 4),
            IconButton(
              onPressed: () => _showReceivedFilesModal(context, auth),
              icon: const Icon(Icons.folder_open, size: 18, color: Color(0xFF94A3B8)),
              tooltip: 'Файлы от инженера',
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
            ),
            const SizedBox(width: 4),
          ],
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

  void _showInSessionChatModal(BuildContext context, AuthState auth) {
    auth.support.markChatAsRead();
    final textController = TextEditingController();
    final scrollController = ScrollController();

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) {
        return Consumer<AuthState>(
          builder: (context, currentAuth, _) {
            final messages = currentAuth.support.chatMessages;

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
                        const Icon(Icons.support_agent, color: Color(0xFF38BDF8), size: 22),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            'Чат с инженером (${currentAuth.support.category == '1c' ? '1С' : 'IT'})',
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 15,
                              fontWeight: FontWeight.bold,
                            ),
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
                        _buildQuickReplyChip(currentAuth, '👋 Здравствуйте!'),
                        _buildQuickReplyChip(currentAuth, '👍 Хорошо, ожидаю'),
                        _buildQuickReplyChip(currentAuth, '🔄 Перезагружаю ПК'),
                        _buildQuickReplyChip(currentAuth, '✅ Всё заработало!'),
                      ],
                    ),
                  ),

                  Expanded(
                    child: messages.isEmpty
                        ? const Center(
                            child: Text(
                              'Сообщений пока нет.\nВы можете написать инженеру здесь.',
                              textAlign: TextAlign.center,
                              style: TextStyle(color: Color(0xFF64748B), fontSize: 13),
                            ),
                          )
                        : ListView.builder(
                            controller: scrollController,
                            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                            itemCount: messages.length,
                            itemBuilder: (ctx, i) {
                              final msg = messages[i];
                              final isMe = msg.sender == 'user';
                              final timeStr = DateFormat('HH:mm').format(msg.timestamp);

                              return Align(
                                alignment: isMe ? Alignment.centerRight : Alignment.centerLeft,
                                child: Container(
                                  margin: const EdgeInsets.only(bottom: 8),
                                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                                  constraints: BoxConstraints(
                                    maxWidth: MediaQuery.of(context).size.width * 0.75,
                                  ),
                                  decoration: BoxDecoration(
                                    color: isMe
                                        ? const Color(0xFF2563EB)
                                        : const Color(0xFF1E293B),
                                    borderRadius: BorderRadius.circular(12),
                                    border: Border.all(
                                      color: isMe
                                          ? const Color(0xFF3B82F6)
                                          : const Color(0xFF334155),
                                    ),
                                  ),
                                  child: Column(
                                    crossAxisAlignment:
                                        isMe ? CrossAxisAlignment.end : CrossAxisAlignment.start,
                                    children: [
                                      if (!isMe)
                                        Padding(
                                          padding: const EdgeInsets.only(bottom: 2),
                                          child: Text(
                                            msg.senderName,
                                            style: const TextStyle(
                                              color: Color(0xFF38BDF8),
                                              fontSize: 10,
                                              fontWeight: FontWeight.bold,
                                            ),
                                          ),
                                        ),
                                      Text(
                                        msg.text,
                                        style: const TextStyle(color: Colors.white, fontSize: 13),
                                      ),
                                      const SizedBox(height: 2),
                                      Text(
                                        timeStr,
                                        style: TextStyle(
                                          color: isMe ? Colors.white70 : const Color(0xFF64748B),
                                          fontSize: 9,
                                        ),
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
                              hintText: 'Написать инженеру...',
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
                                currentAuth.support.sendChatMessage(
                                  val.trim(),
                                  senderName: currentAuth.displayName,
                                );
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
                              currentAuth.support.sendChatMessage(
                                val,
                                senderName: currentAuth.displayName,
                              );
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
    );
  }

  Widget _buildQuickReplyChip(AuthState auth, String text) {
    return Container(
      margin: const EdgeInsets.only(right: 6),
      child: InkWell(
        borderRadius: BorderRadius.circular(16),
        onTap: () {
          auth.support.sendChatMessage(
            text,
            senderName: auth.displayName,
          );
        },
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
          decoration: BoxDecoration(
            color: const Color(0xFF1E293B),
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: const Color(0xFF334155)),
          ),
          child: Text(
            text,
            style: const TextStyle(color: Color(0xFFCBD5E1), fontSize: 11),
          ),
        ),
      ),
    );
  }

  void _showReceivedFilesModal(BuildContext context, AuthState auth) {
    final support = auth.support;

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

    showDialog(
      context: context,
      builder: (ctx) {
        return AlertDialog(
          backgroundColor: const Color(0xFF0F172A),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: const BorderSide(color: Color(0xFF334155)),
          ),
          title: Row(
            children: [
              const Icon(Icons.folder_shared, color: Color(0xFF38BDF8), size: 22),
              const SizedBox(width: 8),
              const Expanded(
                child: Text(
                  'Файлы удаленной поддержки',
                  style: TextStyle(color: Colors.white, fontSize: 16),
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
          content: SizedBox(
            width: 480,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (support.receivedFiles.isEmpty)
                  const Padding(
                    padding: EdgeInsets.symmetric(vertical: 16),
                    child: Text(
                      'Инженер пока не передавал файлов.\nВсе полученные файлы автоматически сохраняются в вашу папку Загрузки/LigamentSupport.',
                      style: TextStyle(color: Color(0xFF94A3B8), fontSize: 13, height: 1.4),
                    ),
                  )
                else ...[
                  const Text(
                    'Полученные файлы в этой сессии:',
                    style: TextStyle(color: Color(0xFFCBD5E1), fontSize: 12, fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 8),
                  Container(
                    constraints: const BoxConstraints(maxHeight: 220),
                    child: ListView.separated(
                      shrinkWrap: true,
                      itemCount: support.receivedFiles.length,
                      separatorBuilder: (_, __) => const Divider(color: Color(0xFF1E293B), height: 1),
                      itemBuilder: (c, idx) {
                        final f = support.receivedFiles[idx];
                        return ListTile(
                          dense: true,
                          contentPadding: EdgeInsets.zero,
                          leading: const Icon(Icons.insert_drive_file, color: Color(0xFF38BDF8)),
                          title: Text(
                            f.filename,
                            style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w600),
                          ),
                          subtitle: Text(
                            '${(f.size / 1024).toStringAsFixed(1)} КБ • ${DateFormat('HH:mm').format(f.receivedAt)}',
                            style: const TextStyle(color: Color(0xFF64748B), fontSize: 11),
                          ),
                          trailing: IconButton(
                            icon: const Icon(Icons.folder_open, color: Color(0xFF94A3B8), size: 18),
                            tooltip: 'Показать в папке',
                            onPressed: () => _openFolder(downloadsPath),
                          ),
                        );
                      },
                    ),
                  ),
                ],
                const SizedBox(height: 12),
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: const Color(0xFF1E293B),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: const Color(0xFF334155)),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.folder, color: Color(0xFFF59E0B), size: 18),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          downloadsPath,
                          style: const TextStyle(color: Color(0xFFCBD5E1), fontSize: 11, fontFamily: 'monospace'),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          actions: [
            TextButton.icon(
              onPressed: () => _openFolder(downloadsPath),
              icon: const Icon(Icons.folder_open, size: 16),
              label: const Text('Открыть папку'),
              style: TextButton.styleFrom(foregroundColor: const Color(0xFF38BDF8)),
            ),
            ElevatedButton(
              onPressed: () => Navigator.of(ctx).pop(),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF2563EB),
                foregroundColor: Colors.white,
              ),
              child: const Text('Закрыть'),
            ),
          ],
        );
      },
    );
  }

  void _openFolder(String path) {
    try {
      if (Platform.isWindows) {
        Process.run('explorer.exe', [path]);
      } else if (Platform.isMacOS) {
        Process.run('open', [path]);
      } else if (Platform.isLinux) {
        Process.run('xdg-open', [path]);
      }
    } catch (_) {}
  }
}
