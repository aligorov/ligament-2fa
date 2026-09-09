import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:window_manager/window_manager.dart';
import 'package:tray_manager/tray_manager.dart';

import 'services/auth_state.dart';
import 'screens/connect_screen.dart';
import 'screens/home_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Инициализация оконного менеджера для Windows, macOS и Linux
  if (!kIsWeb && (Platform.isWindows || Platform.isMacOS || Platform.isLinux)) {
    await windowManager.ensureInitialized();

    const windowOptions = WindowOptions(
      size: Size(440, 720),
      minimumSize: Size(380, 600),
      center: true,
      backgroundColor: Colors.transparent,
      skipTaskbar: false,
      title: 'Ligament 2FA Authenticator',
    );

    await windowManager.waitUntilReadyToShow(windowOptions, () async {
      await windowManager.show();
      await windowManager.focus();
    });
  }

  final authState = AuthState();
  await authState.init();

  runApp(
    ChangeNotifierProvider.value(
      value: authState,
      child: const LigamentApp(),
    ),
  );
}

class LigamentApp extends StatefulWidget {
  const LigamentApp({super.key});

  @override
  State<LigamentApp> createState() => _LigamentAppState();
}

class _LigamentAppState extends State<LigamentApp> with TrayListener, WindowListener {
  @override
  void initState() {
    super.initState();
    if (!kIsWeb && (Platform.isWindows || Platform.isMacOS || Platform.isLinux)) {
      trayManager.addListener(this);
      windowManager.addListener(this);
      _initTray();
    }
  }

  @override
  void dispose() {
    if (!kIsWeb && (Platform.isWindows || Platform.isMacOS || Platform.isLinux)) {
      trayManager.removeListener(this);
      windowManager.removeListener(this);
    }
    super.dispose();
  }

  Future<void> _initTray() async {
    try {
      final auth = context.read<AuthState>();
      final allowExit = auth.gpo.allowExit;

      await trayManager.setIcon(
        Platform.isWindows ? 'assets/icons/app_icon.ico' : 'assets/icons/app_icon.png',
      );

      final menu = Menu(
        items: [
          MenuItem(key: 'show', label: 'Открыть Ligament 2FA'),
          MenuItem.separator(),
          MenuItem(
            key: 'exit',
            label: 'Выход',
            disabled: !allowExit, // GPO политика PreventExit
          ),
        ],
      );
      await trayManager.setContextMenu(menu);
      await trayManager.setToolTip('Ligament 2FA Authenticator');
    } catch (_) {}
  }

  @override
  void onTrayMenuItemClick(MenuItem menuItem) {
    if (menuItem.key == 'show') {
      windowManager.show();
      windowManager.focus();
    } else if (menuItem.key == 'exit') {
      final auth = context.read<AuthState>();
      if (auth.gpo.allowExit) {
        windowManager.destroy();
      }
    }
  }

  @override
  void onWindowClose() async {
    // При закрытии окна не убиваем процесс, а сворачиваем в системный трей
    final isPreventExit = !context.read<AuthState>().gpo.allowExit;
    if (isPreventExit) {
      await windowManager.hide();
    } else {
      await windowManager.destroy();
    }
  }

  @override
  Widget build(BuildContext context) {
    final auth = context.watch<AuthState>();

    return MaterialApp(
      title: 'Ligament 2FA',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        colorScheme: ColorScheme.dark(
          primary: const Color(0xFF38BDF8),
          secondary: const Color(0xFF0284C7),
          surface: const Color(0xFF1E293B),
          background: const Color(0xFF0F172A),
        ),
        scaffoldBackgroundColor: const Color(0xFF0F172A),
        useMaterial3: true,
      ),
      home: auth.isLoggedIn ? const HomeScreen() : const ConnectScreen(),
    );
  }
}
