import 'dart:math';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/auth_state.dart';

/// Модальное окно Zero-Trust подтверждения удаленного доступа с Number Matching.
class SupportApprovalModal extends StatefulWidget {
  final Map<String, dynamic> prompt;

  const SupportApprovalModal({super.key, required this.prompt});

  @override
  State<SupportApprovalModal> createState() => _SupportApprovalModalState();
}

class _SupportApprovalModalState extends State<SupportApprovalModal> {
  late List<int> _numberChoices;
  int? _selectedNumber;
  bool _processing = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _initNumberChoices();
  }

  void _initNumberChoices() {
    final rawMatch = widget.prompt['number_match']?.toString();
    final target = int.tryParse(rawMatch ?? '');

    if (target != null) {
      final rng = Random();
      final set = <int>{target};
      while (set.length < 3) {
        set.add(10 + rng.nextInt(90));
      }
      _numberChoices = set.toList()..shuffle();
    } else {
      _numberChoices = [];
    }
  }

  Future<void> _approve() async {
    final rawMatch = widget.prompt['number_match']?.toString();
    if (rawMatch != null && rawMatch.isNotEmpty) {
      if (_selectedNumber == null) {
        setState(() => _error = 'Выберите контрольное число, названное инженером');
        return;
      }
      if (_selectedNumber.toString() != rawMatch) {
        setState(() => _error = 'Неверное число! Сверьтесь со специалистом поддержки');
        return;
      }
    }

    setState(() {
      _processing = true;
      _error = null;
    });

    try {
      final auth = context.read<AuthState>();
      final sessId = widget.prompt['session_id']?.toString() ?? '';
      await auth.confirmSupport(
        sessionId: sessId,
        numberMatch: _selectedNumber?.toString(),
      );

      if (mounted) {
        Navigator.of(context).pop(true);
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _processing = false;
          _error = 'Ошибка подтверждения: $e';
        });
      }
    }
  }

  Future<void> _deny() async {
    setState(() => _processing = true);
    try {
      final auth = context.read<AuthState>();
      final sessId = widget.prompt['session_id']?.toString() ?? '';
      await auth.rejectSupport(sessionId: sessId);
    } catch (_) {}
    if (mounted) {
      Navigator.of(context).pop(false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final category = widget.prompt['category']?.toString() ?? 'it';
    final summary = widget.prompt['problem_summary']?.toString() ?? 'Удаленная помощь';
    final operatorName = widget.prompt['operator']?.toString() ?? 'Инженер техподдержки';
    final accessMode = widget.prompt['access_mode']?.toString() ?? 'full_control';

    return Dialog(
      backgroundColor: const Color(0xFF1E293B),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
      child: Container(
        padding: const EdgeInsets.all(24),
        constraints: const BoxConstraints(maxWidth: 440),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            // Иконка замка и безопасность
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: const Color(0xFF38BDF8).withValues(alpha: 0.12),
                shape: BoxShape.circle,
              ),
              child: const Icon(Icons.screen_share, size: 48, color: Color(0xFF38BDF8)),
            ),
            const SizedBox(height: 16),

            const Text(
              'Запрос на подключение к ПК',
              style: TextStyle(color: Colors.white, fontSize: 20, fontWeight: FontWeight.bold),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 6),
            Text(
              category == '1c' ? 'Консультант 1С готов помочь вам' : 'Дежурный инженер IT на связи',
              style: const TextStyle(color: Color(0xFF94A3B8), fontSize: 13),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),

            // Карточка деталей
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: const Color(0xFF0F172A),
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: const Color(0xFF334155)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.person_outline, size: 16, color: Color(0xFF94A3B8)),
                      const SizedBox(width: 6),
                      Text(
                        operatorName,
                        style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600, fontSize: 13),
                      ),
                      const Spacer(),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                        decoration: BoxDecoration(
                          color: category == '1c'
                              ? const Color(0xFFF59E0B).withValues(alpha: 0.2)
                              : const Color(0xFF0284C7).withValues(alpha: 0.2),
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: Text(
                          category == '1c' ? '1С-поддержка' : 'IT-служба',
                          style: TextStyle(
                            color: category == '1c' ? const Color(0xFFF59E0B) : const Color(0xFF38BDF8),
                            fontSize: 11,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                    ],
                  ),
                  const Divider(color: Color(0xFF334155), height: 16),
                  Text(
                    'Суть проблемы: "$summary"',
                    style: const TextStyle(color: Color(0xFFCBD5E1), fontSize: 12),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    accessMode == 'full_control'
                        ? 'Режим: Полный доступ (управление курсором и клавиатурой)'
                        : 'Режим: Только просмотр экрана',
                    style: const TextStyle(color: Color(0xFF94A3B8), fontSize: 11),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 20),

            // Number Matching
            if (_numberChoices.isNotEmpty) ...[
              const Text(
                'Контрольное число Number Matching:',
                style: TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w600),
              ),
              const SizedBox(height: 4),
              const Text(
                'Специалист поддержки продиктовал вам число. Нажмите на него:',
                style: TextStyle(color: Color(0xFF94A3B8), fontSize: 12),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 12),
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  for (final choice in _numberChoices)
                    Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 8),
                      child: InkWell(
                        onTap: _processing ? null : () => setState(() => _selectedNumber = choice),
                        borderRadius: BorderRadius.circular(16),
                        child: AnimatedContainer(
                          duration: const Duration(milliseconds: 150),
                          width: 68,
                          height: 68,
                          decoration: BoxDecoration(
                            color: _selectedNumber == choice ? const Color(0xFF0284C7) : const Color(0xFF0F172A),
                            borderRadius: BorderRadius.circular(16),
                            border: Border.all(
                              color: _selectedNumber == choice ? const Color(0xFF38BDF8) : const Color(0xFF334155),
                              width: 2,
                            ),
                          ),
                          alignment: Alignment.center,
                          child: Text(
                            '$choice',
                            style: TextStyle(
                              color: _selectedNumber == choice ? Colors.white : const Color(0xFFE2E8F0),
                              fontSize: 26,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                      ),
                    ),
                ],
              ),
            ],

            if (_error != null) ...[
              const SizedBox(height: 14),
              Text(
                _error!,
                style: const TextStyle(color: Color(0xFFEF4444), fontSize: 12, fontWeight: FontWeight.bold),
                textAlign: TextAlign.center,
              ),
            ],

            const SizedBox(height: 24),

            // Кнопки
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: _processing ? null : _deny,
                    style: OutlinedButton.styleFrom(
                      foregroundColor: const Color(0xFFEF4444),
                      side: const BorderSide(color: Color(0xFFEF4444)),
                      padding: const EdgeInsets.symmetric(vertical: 14),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                    ),
                    child: const Text('Отклонить'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  flex: 2,
                  child: ElevatedButton(
                    onPressed: _processing ? null : _approve,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: const Color(0xFF10B981),
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.symmetric(vertical: 14),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                    ),
                    child: _processing
                        ? const SizedBox(
                            width: 20,
                            height: 20,
                            child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2),
                          )
                        : const Text(
                            'Разрешить доступ',
                            style: TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
                          ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
