import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/auth_state.dart';
import 'login_screen.dart';

class ConnectScreen extends StatefulWidget {
  const ConnectScreen({super.key});

  @override
  State<ConnectScreen> createState() => _ConnectScreenState();
}

class _ConnectScreenState extends State<ConnectScreen> {
  final _urlController = TextEditingController();
  bool _isLoading = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    final auth = context.read<AuthState>();
    if (auth.serverUrl != null && auth.serverUrl!.isNotEmpty) {
      _urlController.text = auth.serverUrl!;
    } else if (auth.gpo.enforcedServerUrl != null) {
      _urlController.text = auth.gpo.enforcedServerUrl!;
    } else {
      _urlController.text = 'https://';
    }
  }

  Future<void> _handleConnect() async {
    final auth = context.read<AuthState>();
    final url = _urlController.text.trim();
    if (url.isEmpty || url == 'https://' || url == 'http://') {
      setState(() => _error = 'Введите корректный HTTPS адрес сервера');
      return;
    }

    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      await auth.setServerUrl(url);
      final cfg = await auth.api!.getConfig();
      if (mounted) {
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(builder: (_) => LoginScreen(serverConfig: cfg)),
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = 'Не удалось подключиться к серверу: $e';
          _isLoading = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final auth = context.watch<AuthState>();
    final isGpoLocked = auth.gpo.enforcedServerUrl != null;

    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: Card(
              color: const Color(0xFF1E293B),
              elevation: 8,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
              child: Padding(
                padding: const EdgeInsets.all(32),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    const Icon(Icons.shield_outlined, size: 56, color: Color(0xFF38BDF8)),
                    const SizedBox(height: 16),
                    const Text(
                      'Ligament 2FA',
                      textAlign: TextAlign.center,
                      style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold, color: Colors.white),
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'Корпоративный аутентификатор доступа',
                      textAlign: TextAlign.center,
                      style: TextStyle(fontSize: 14, color: Color(0xFF94A3B8)),
                    ),
                    const SizedBox(height: 32),
                    TextField(
                      controller: _urlController,
                      enabled: !isGpoLocked && !_isLoading,
                      style: const TextStyle(color: Colors.white),
                      decoration: InputDecoration(
                        labelText: 'Адрес сервера Ligament',
                        labelStyle: const TextStyle(color: Color(0xFF94A3B8)),
                        prefixIcon: const Icon(Icons.link, color: Color(0xFF38BDF8)),
                        suffixIcon: isGpoLocked
                            ? const Tooltip(
                                message: 'Адрес задан групповой политикой Windows (GPO)',
                                child: Icon(Icons.lock, color: Colors.amber),
                              )
                            : null,
                        filled: true,
                        fillColor: const Color(0xFF0F172A),
                        border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                      ),
                    ),
                    if (isGpoLocked)
                      const Padding(
                        padding: EdgeInsets.only(top: 8),
                        child: Text(
                          '🔒 Настройка заблокирована системным администратором (GPO)',
                          style: TextStyle(fontSize: 12, color: Colors.amber),
                        ),
                      ),
                    if (_error != null) ...[
                      const SizedBox(height: 16),
                      Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: const Color(0xFFEF4444).withOpacity(0.15),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: const Color(0xFFEF4444)),
                        ),
                        child: Text(
                          _error!,
                          style: const TextStyle(color: Color(0xFFFCA5A5), fontSize: 13),
                        ),
                      ),
                    ],
                    const SizedBox(height: 24),
                    ElevatedButton(
                      onPressed: _isLoading ? null : _handleConnect,
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFF0284C7),
                        foregroundColor: Colors.white,
                        padding: const EdgeInsets.symmetric(vertical: 16),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                      ),
                      child: _isLoading
                          ? const SizedBox(
                              height: 20,
                              width: 20,
                              child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                            )
                          : const Text('Подключиться', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
