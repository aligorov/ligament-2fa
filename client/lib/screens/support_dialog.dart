import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/auth_state.dart';

/// Диалоговое окно отправки экстренной заявки на удаленную помощь (SOS).
class SupportDialog extends StatefulWidget {
  const SupportDialog({super.key});

  @override
  State<SupportDialog> createState() => _SupportDialogState();
}

class _SupportDialogState extends State<SupportDialog> {
  final _formKey = GlobalKey<FormState>();
  final _summaryController = TextEditingController();
  String _category = 'it';
  String _accessMode = 'full_control'; // 'full_control' | 'view_only'
  bool _submitting = false;
  String? _errorMessage;

  List<Map<String, dynamic>> _categories = [
    {'id': 'it', 'name': 'IT-служба', 'icon': '🖥'},
    {'id': '1c', 'name': 'Поддержка 1С', 'icon': '📊'},
  ];

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      final auth = context.read<AuthState>();
      try {
        final cats = await auth.api?.getSupportCategories();
        if (cats != null && cats.isNotEmpty && mounted) {
          setState(() {
            _categories = cats;
            if (!_categories.any((c) => c['id'] == _category)) {
              _category = _categories.first['id']?.toString() ?? 'it';
            }
          });
        }
      } catch (_) {}
    });
  }

  @override
  void dispose() {
    _summaryController.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() {
      _submitting = true;
      _errorMessage = null;
    });

    try {
      final auth = context.read<AuthState>();
      await auth.requestSupport(
        category: _category,
        problemSummary: _summaryController.text.trim(),
        accessMode: _accessMode,
      );

      if (mounted) {
        Navigator.of(context).pop(true);
        final catName = _categories.firstWhere(
          (c) => c['id'] == _category,
          orElse: () => {'name': _category},
        )['name'];
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFF0284C7),
            content: Text('Запрос передан в службу: $catName. Ожидайте подключения инженера.'),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _errorMessage = 'Не удалось отправить запрос: $e';
          _submitting = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: const Color(0xFF1E293B),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
      child: Container(
        padding: const EdgeInsets.all(24),
        constraints: const BoxConstraints(maxWidth: 520),
        child: Form(
          key: _formKey,
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: const Color(0xFFEF4444).withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: const Icon(Icons.support_agent, color: Color(0xFFEF4444), size: 28),
                    ),
                    const SizedBox(width: 14),
                    const Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'Экстренная помощь (SOS)',
                            style: TextStyle(
                              color: Colors.white,
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          Text(
                            'Удаленный доступ к вашему рабочему месту',
                            style: TextStyle(color: Color(0xFF94A3B8), fontSize: 12),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 20),

                if (_errorMessage != null)
                  Container(
                    margin: const EdgeInsets.only(bottom: 16),
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: const Color(0xFFEF4444).withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: const Color(0xFFEF4444).withValues(alpha: 0.4)),
                    ),
                    child: Text(
                      _errorMessage!,
                      style: const TextStyle(color: Color(0xFFFCA5A5), fontSize: 13),
                    ),
                  ),

                // Выбор категории поддержки (динамический)
                const Text(
                  'Выберите службу поддержки:',
                  style: TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 8),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: _categories.map((cat) {
                    final id = cat['id']?.toString() ?? '';
                    final name = cat['name']?.toString() ?? id;
                    final icon = cat['icon']?.toString() ?? '🛠';
                    final isSelected = _category == id;
                    final is1C = id == '1c';

                    return InkWell(
                      onTap: () => setState(() => _category = id),
                      borderRadius: BorderRadius.circular(12),
                      child: Container(
                        padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 14),
                        decoration: BoxDecoration(
                          color: isSelected
                              ? (is1C
                                  ? const Color(0xFFF59E0B).withValues(alpha: 0.2)
                                  : const Color(0xFF0284C7).withValues(alpha: 0.2))
                              : const Color(0xFF0F172A),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(
                            color: isSelected
                                ? (is1C ? const Color(0xFFF59E0B) : const Color(0xFF38BDF8))
                                : const Color(0xFF334155),
                            width: 1.5,
                          ),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Text(icon, style: const TextStyle(fontSize: 16)),
                            const SizedBox(width: 8),
                            Text(
                              name,
                              style: TextStyle(
                                color: isSelected ? Colors.white : const Color(0xFF94A3B8),
                                fontSize: 13,
                                fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                              ),
                            ),
                          ],
                        ),
                      ),
                    );
                  }).toList(),
                ),
                const SizedBox(height: 18),

                // Обязательное описание сути проблемы
                const Text(
                  'Кратко опишите проблему:*',
                  style: TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 6),
                TextFormField(
                  controller: _summaryController,
                  maxLines: 3,
                  style: const TextStyle(color: Colors.white, fontSize: 14),
                  decoration: InputDecoration(
                    hintText: _category == '1c'
                        ? 'Например: Зависает проведение документа в 1С:Бухгалтерия...'
                        : 'Например: Не открывается сетевая папка, ошибка сетевого принтера...',
                    hintStyle: const TextStyle(color: Color(0xFF64748B), fontSize: 13),
                    filled: true,
                    fillColor: const Color(0xFF0F172A),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: const BorderSide(color: Color(0xFF334155)),
                    ),
                    enabledBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: const BorderSide(color: Color(0xFF334155)),
                    ),
                    focusedBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: const BorderSide(color: Color(0xFF38BDF8)),
                    ),
                  ),
                  validator: (val) {
                    if (val == null || val.trim().isEmpty) {
                      return 'Пожалуйста, опишите суть возникшей проблемы';
                    }
                    if (val.trim().length < 5) {
                      return 'Описание должно быть не менее 5 символов';
                    }
                    return null;
                  },
                ),
                const SizedBox(height: 18),

                // Режим доступа
                const Text(
                  'Режим удаленного доступа:',
                  style: TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 6),
                DropdownButtonFormField<String>(
                  initialValue: _accessMode,
                  dropdownColor: const Color(0xFF1E293B),
                  style: const TextStyle(color: Colors.white, fontSize: 13),
                  decoration: InputDecoration(
                    filled: true,
                    fillColor: const Color(0xFF0F172A),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: const BorderSide(color: Color(0xFF334155)),
                    ),
                  ),
                  items: const [
                    DropdownMenuItem(
                      value: 'full_control',
                      child: Text('🎮 Полный доступ (управление мышью и клавиатурой)'),
                    ),
                    DropdownMenuItem(
                      value: 'view_only',
                      child: Text('👀 Только просмотр экрана (без управления)'),
                    ),
                  ],
                  onChanged: (val) {
                    if (val != null) setState(() => _accessMode = val);
                  },
                ),
                const SizedBox(height: 24),

                // Кнопки действий
                Row(
                  children: [
                    Expanded(
                      child: TextButton(
                        onPressed: _submitting ? null : () => Navigator.of(context).pop(),
                        child: const Text('Отмена', style: TextStyle(color: Color(0xFF94A3B8))),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      flex: 2,
                      child: ElevatedButton(
                        onPressed: _submitting ? null : _submit,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFFEF4444),
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(vertical: 14),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                        ),
                        child: _submitting
                            ? const SizedBox(
                                width: 20,
                                height: 20,
                                child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2),
                              )
                            : const Text(
                                'Отправить SOS запрос',
                                style: TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
                              ),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
