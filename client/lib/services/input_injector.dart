import 'dart:ffi' as ffi;
import 'dart:io';
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';

// CoreGraphics struct for macOS
final class _CGPoint extends ffi.Struct {
  @ffi.Double()
  external double x;
  @ffi.Double()
  external double y;
}

// Win32 RECT struct for ClipCursor
final class _RECT extends ffi.Struct {
  @ffi.Int32()
  external int left;
  @ffi.Int32()
  external int top;
  @ffi.Int32()
  external int right;
  @ffi.Int32()
  external int bottom;
}

/// Сервис внедрения пользовательского ввода (мышь и клавиатура) на Windows, macOS и Linux.
class InputInjector {
  static final InputInjector instance = InputInjector._();
  InputInjector._() {
    _initMacCG();
    _initWinUser32();
  }

  // macOS CoreGraphics FFI handles
  ffi.DynamicLibrary? _cgLib;
  ffi.DynamicLibrary? _cfLib;
  int Function()? _cgMainDisplayID;
  int Function(int)? _cgDisplayPixelsWide;
  int Function(int)? _cgDisplayPixelsHigh;
  int Function(_CGPoint)? _cgWarpMouseCursorPosition;
  int Function(int)? _cgAssociateMouse;
  void Function(ffi.Pointer<ffi.Void>)? _cfRelease;
  ffi.Pointer<ffi.Void> Function(ffi.Pointer<ffi.Void>, int, _CGPoint, int)? _cgEventCreateMouseEvent;
  ffi.Pointer<ffi.Void> Function(ffi.Pointer<ffi.Void>, int, bool)? _cgEventCreateKeyboardEvent;
  void Function(int, ffi.Pointer<ffi.Void>)? _cgEventPost;

  // Windows User32 FFI handles
  ffi.DynamicLibrary? _user32Lib;
  int Function(int, int)? _winSetCursorPos;
  void Function(int, int, int, int, int)? _winMouseEvent;
  void Function(int, int, int, int)? _winKeybdEvent;
  int Function(int)? _winBlockInput;
  int Function(ffi.Pointer<_RECT>)? _winClipCursor;
  int Function()? _winLockWorkStation;
  int Function(int)? _winGetSystemMetrics;

  void _initMacCG() {
    if (kIsWeb || !Platform.isMacOS) return;
    try {
      _cgLib = ffi.DynamicLibrary.open('/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics');
      _cfLib = ffi.DynamicLibrary.open('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation');

      _cgMainDisplayID = _cgLib!.lookupFunction<ffi.Uint32 Function(), int Function()>('CGMainDisplayID');
      _cgDisplayPixelsWide = _cgLib!.lookupFunction<ffi.IntPtr Function(ffi.Uint32), int Function(int)>('CGDisplayPixelsWide');
      _cgDisplayPixelsHigh = _cgLib!.lookupFunction<ffi.IntPtr Function(ffi.Uint32), int Function(int)>('CGDisplayPixelsHigh');
      _cgWarpMouseCursorPosition = _cgLib!.lookupFunction<ffi.Int32 Function(_CGPoint), int Function(_CGPoint)>('CGWarpMouseCursorPosition');
      _cgAssociateMouse = _cgLib!.lookupFunction<ffi.Int32 Function(ffi.Uint32), int Function(int)>('CGAssociateMouseAndMouseCursorPosition');
      _cfRelease = _cfLib!.lookupFunction<ffi.Void Function(ffi.Pointer<ffi.Void>), void Function(ffi.Pointer<ffi.Void>)>('CFRelease');

      _cgEventCreateMouseEvent = _cgLib!.lookupFunction<
          ffi.Pointer<ffi.Void> Function(ffi.Pointer<ffi.Void>, ffi.Uint32, _CGPoint, ffi.Uint32),
          ffi.Pointer<ffi.Void> Function(ffi.Pointer<ffi.Void>, int, _CGPoint, int)>('CGEventCreateMouseEvent');

      _cgEventCreateKeyboardEvent = _cgLib!.lookupFunction<
          ffi.Pointer<ffi.Void> Function(ffi.Pointer<ffi.Void>, ffi.Uint16, ffi.Bool),
          ffi.Pointer<ffi.Void> Function(ffi.Pointer<ffi.Void>, int, bool)>('CGEventCreateKeyboardEvent');

      _cgEventPost = _cgLib!.lookupFunction<
          ffi.Void Function(ffi.Uint32, ffi.Pointer<ffi.Void>),
          void Function(int, ffi.Pointer<ffi.Void>)>('CGEventPost');
    } catch (e) {
      debugPrint('input_injector: ошибка загрузки macOS CoreGraphics: $e');
    }
  }

  void _initWinUser32() {
    if (kIsWeb || !Platform.isWindows) return;
    try {
      _user32Lib = ffi.DynamicLibrary.open('user32.dll');
      _winSetCursorPos = _user32Lib!.lookupFunction<
          ffi.Int32 Function(ffi.Int32, ffi.Int32),
          int Function(int, int)>('SetCursorPos');
      _winMouseEvent = _user32Lib!.lookupFunction<
          ffi.Void Function(ffi.Uint32, ffi.Uint32, ffi.Uint32, ffi.Uint32, ffi.IntPtr),
          void Function(int, int, int, int, int)>('mouse_event');
      _winKeybdEvent = _user32Lib!.lookupFunction<
          ffi.Void Function(ffi.Uint8, ffi.Uint8, ffi.Uint32, ffi.IntPtr),
          void Function(int, int, int, int)>('keybd_event');
      _winBlockInput = _user32Lib!.lookupFunction<
          ffi.Int32 Function(ffi.Int32),
          int Function(int)>('BlockInput');
      _winClipCursor = _user32Lib!.lookupFunction<
          ffi.Int32 Function(ffi.Pointer<_RECT>),
          int Function(ffi.Pointer<_RECT>)>('ClipCursor');
      _winLockWorkStation = _user32Lib!.lookupFunction<
          ffi.Int32 Function(),
          int Function()>('LockWorkStation');
      _winGetSystemMetrics = _user32Lib!.lookupFunction<
          ffi.Int32 Function(ffi.Int32),
          int Function(int)>('GetSystemMetrics');
    } catch (e) {
      debugPrint('input_injector: ошибка загрузки user32.dll: $e');
    }
  }

  /// Получение физических размеров основного экрана (пиксели)
  (int width, int height) getScreenSize() {
    if (kIsWeb) return (1920, 1080);
    if (Platform.isMacOS) {
      if (_cgMainDisplayID != null && _cgDisplayPixelsWide != null && _cgDisplayPixelsHigh != null) {
        final disp = _cgMainDisplayID!();
        final w = _cgDisplayPixelsWide!(disp);
        final h = _cgDisplayPixelsHigh!(disp);
        return (w > 0 ? w : 1920, h > 0 ? h : 1080);
      }
    } else if (Platform.isWindows) {
      final w = _winGetSystemMetrics?.call(0) ?? 1920; // SM_CXSCREEN = 0
      final h = _winGetSystemMetrics?.call(1) ?? 1080; // SM_CYSCREEN = 1
      return (w > 0 ? w : 1920, h > 0 ? h : 1080);
    }
    return (1920, 1080);
  }

  /// Перемещение курсора мыши в абсолютные координаты 0..1
  void moveMouse(double normX, double normY) {
    if (kIsWeb) return;
    final (w, h) = getScreenSize();
    final px = (normX * w).clamp(0, w - 1).toDouble();
    final py = (normY * h).clamp(0, h - 1).toDouble();

    if (Platform.isMacOS) {
      final pt = calloc<_CGPoint>();
      pt.ref.x = px;
      pt.ref.y = py;
      _cgWarpMouseCursorPosition?.call(pt.ref);
      calloc.free(pt);
      _postMacMouseEvent(5, px, py, 0); // 5 = kCGEventMouseMoved
    } else if (Platform.isWindows) {
      _winSetCursorPos?.call(px.round(), py.round());
      const mouseEventfMove = 0x0001;
      const mouseEventfAbsolute = 0x8000;
      final absX = (normX * 65535).round().clamp(0, 65535);
      final absY = (normY * 65535).round().clamp(0, 65535);
      _winMouseEvent?.call(mouseEventfMove | mouseEventfAbsolute, absX, absY, 0, 0);
    } else if (Platform.isLinux) {
      Process.run('xdotool', ['mousemove', px.round().toString(), py.round().toString()]);
    }
  }

  /// Нажатие или отпускание кнопки мыши (0: Left, 1: Middle, 2: Right)
  void mouseAction({
    required String action, // 'down' | 'up' | 'click'
    required int button,
    required double normX,
    required double normY,
  }) {
    if (kIsWeb) return;
    final (w, h) = getScreenSize();
    final px = (normX * w).clamp(0, w - 1).toDouble();
    final py = (normY * h).clamp(0, h - 1).toDouble();

    if (Platform.isMacOS) {
      final pt = calloc<_CGPoint>();
      pt.ref.x = px;
      pt.ref.y = py;
      _cgWarpMouseCursorPosition?.call(pt.ref);
      calloc.free(pt);

      int eventDown = 1; // kCGEventLeftMouseDown
      int eventUp = 2;   // kCGEventLeftMouseUp
      int mouseBtn = 0;  // kCGMouseButtonLeft

      if (button == 2) {
        eventDown = 3; // kCGEventRightMouseDown
        eventUp = 4;   // kCGEventRightMouseUp
        mouseBtn = 1;  // kCGMouseButtonRight
      } else if (button == 1) {
        eventDown = 25; // kCGEventOtherMouseDown
        eventUp = 26;   // kCGEventOtherMouseUp
        mouseBtn = 2;   // kCGMouseButtonCenter
      }

      if (action == 'down') {
        _postMacMouseEvent(eventDown, px, py, mouseBtn);
      } else if (action == 'up') {
        _postMacMouseEvent(eventUp, px, py, mouseBtn);
      } else {
        _postMacMouseEvent(eventDown, px, py, mouseBtn);
        _postMacMouseEvent(eventUp, px, py, mouseBtn);
      }
    } else if (Platform.isWindows) {
      _winSetCursorPos?.call(px.round(), py.round());
      const leftDown = 0x0002;
      const leftUp = 0x0004;
      const rightDown = 0x0008;
      const rightUp = 0x0010;
      const midDown = 0x0020;
      const midUp = 0x0040;
      const mouseEventfAbsolute = 0x8000;
      final absX = (normX * 65535).round().clamp(0, 65535);
      final absY = (normY * 65535).round().clamp(0, 65535);

      int flagDown = leftDown;
      int flagUp = leftUp;

      if (button == 2) {
        flagDown = rightDown;
        flagUp = rightUp;
      } else if (button == 1) {
        flagDown = midDown;
        flagUp = midUp;
      }

      if (action == 'down') {
        _winMouseEvent?.call(flagDown | mouseEventfAbsolute, absX, absY, 0, 0);
      } else if (action == 'up') {
        _winMouseEvent?.call(flagUp | mouseEventfAbsolute, absX, absY, 0, 0);
      } else {
        _winMouseEvent?.call(flagDown | mouseEventfAbsolute, absX, absY, 0, 0);
        _winMouseEvent?.call(flagUp | mouseEventfAbsolute, absX, absY, 0, 0);
      }
    } else if (Platform.isLinux) {
      final btnStr = button == 2 ? '3' : (button == 1 ? '2' : '1');
      if (action == 'down') {
        Process.run('xdotool', ['mousedown', btnStr]);
      } else if (action == 'up') {
        Process.run('xdotool', ['mouseup', btnStr]);
      } else {
        Process.run('xdotool', ['click', btnStr]);
      }
    }
  }

  void _postMacMouseEvent(int type, double x, double y, int button) {
    if (_cgEventCreateMouseEvent == null || _cgEventPost == null || _cfRelease == null) return;
    final pt = calloc<_CGPoint>();
    pt.ref.x = x;
    pt.ref.y = y;
    final event = _cgEventCreateMouseEvent!(ffi.Pointer.fromAddress(0), type, pt.ref, button);
    calloc.free(pt);
    if (event.address != 0) {
      _cgEventPost!(0, event); // 0 = kCGHIDEventTap
      _cgEventPost!(1, event); // 1 = kCGSessionEventTap
      _cfRelease!(event);
    }
  }

  /// Прокрутка колеса мыши
  void mouseWheel(double deltaY) {
    if (kIsWeb) return;
    if (Platform.isMacOS) {
      final (w, h) = getScreenSize();
      _postMacMouseEvent(22, (w / 2), (h / 2), 0); // 22 = kCGEventScrollWheel
    } else if (Platform.isWindows) {
      final dy = (-deltaY * 40).round();
      _winMouseEvent?.call(0x0800, 0, 0, dy, 0); // 0x0800 = MOUSEEVENTF_WHEEL
    } else if (Platform.isLinux) {
      final click = deltaY > 0 ? '5' : '4';
      Process.run('xdotool', ['click', click]);
    }
  }

  /// Ввод клавиши (key down / up)
  void keyAction({required String action, required String key, int? keyCode}) {
    if (kIsWeb) return;
    final isDown = action == 'down';

    if (Platform.isMacOS) {
      final macCode = _mapToMacKeyCode(key, keyCode);
      if (macCode != null && _cgEventCreateKeyboardEvent != null && _cgEventPost != null && _cfRelease != null) {
        final ev = _cgEventCreateKeyboardEvent!(ffi.Pointer.fromAddress(0), macCode, isDown);
        if (ev.address != 0) {
          _cgEventPost!(0, ev); // 0 = kCGHIDEventTap
          _cgEventPost!(1, ev); // 1 = kCGSessionEventTap
          _cfRelease!(ev);
        }
      }
    } else if (Platform.isWindows) {
      final winCode = _mapToWinKeyCode(key, keyCode);
      if (winCode != 0) {
        final flags = isDown ? 0 : 0x0002; // 0x0002 = KEYEVENTF_KEYUP
        _winKeybdEvent?.call(winCode, 0, flags, 0);
      }
    } else if (Platform.isLinux) {
      final act = isDown ? 'keydown' : 'keyup';
      Process.run('xdotool', [act, key]);
    }
  }

  /// Блокировка или разблокировка ввода у локального пользователя (мышь/клавиатура)
  void setInputBlocked(bool blocked) {
    if (kIsWeb) return;
    try {
      if (Platform.isWindows) {
        if (blocked) {
          // 1. Аппаратно запираем физический курсор мыши в точку 0,0
          // ClipCursor работает без повышенных прав UAC/Admin!
          final rect = calloc<_RECT>();
          rect.ref.left = 0;
          rect.ref.top = 0;
          rect.ref.right = 1;
          rect.ref.bottom = 1;
          _winClipCursor?.call(rect);
          calloc.free(rect);

          // 2. Блокируем ввод через BlockInput (если процесс имеет права админа)
          _winBlockInput?.call(1);
        } else {
          // Освобождаем курсор мыши
          _winClipCursor?.call(ffi.Pointer.fromAddress(0));
          _winBlockInput?.call(0);
        }
      } else if (Platform.isMacOS) {
        // CGAssociateMouseAndMouseCursorPosition: 0 отключает физическое движение курсора мышью
        _cgAssociateMouse?.call(blocked ? 0 : 1);
      }
    } catch (e) {
      debugPrint('input_injector: ошибка изменения блокировки ввода: $e');
    }
  }

  /// Вызов системных горячих клавиш (Пуск, Ctrl+Alt+Del, Alt+Tab и т.д.)
  Future<void> triggerHotkey(String hotkey) async {
    if (kIsWeb) return;

    if (Platform.isWindows) {
      const vkTab = 0x09;
      const vkShift = 0x10;
      const vkControl = 0x11;
      const vkMenu = 0x12; // Alt
      const vkEscape = 0x1B;
      const vkLWin = 0x5B;
      const vkF4 = 0x73;
      const keyUp = 0x0002;

      switch (hotkey) {
        case 'win_key':
          _winKeybdEvent?.call(vkLWin, 0, 0, 0);
          _winKeybdEvent?.call(vkLWin, 0, keyUp, 0);
          break;
        case 'win_r':
          final vkR = 'R'.codeUnitAt(0);
          _winKeybdEvent?.call(vkLWin, 0, 0, 0);
          _winKeybdEvent?.call(vkR, 0, 0, 0);
          _winKeybdEvent?.call(vkR, 0, keyUp, 0);
          _winKeybdEvent?.call(vkLWin, 0, keyUp, 0);
          break;
        case 'win_d':
          final vkD = 'D'.codeUnitAt(0);
          _winKeybdEvent?.call(vkLWin, 0, 0, 0);
          _winKeybdEvent?.call(vkD, 0, 0, 0);
          _winKeybdEvent?.call(vkD, 0, keyUp, 0);
          _winKeybdEvent?.call(vkLWin, 0, keyUp, 0);
          break;
        case 'win_e':
          final vkE = 'E'.codeUnitAt(0);
          _winKeybdEvent?.call(vkLWin, 0, 0, 0);
          _winKeybdEvent?.call(vkE, 0, 0, 0);
          _winKeybdEvent?.call(vkE, 0, keyUp, 0);
          _winKeybdEvent?.call(vkLWin, 0, keyUp, 0);
          break;
        case 'win_x':
          final vkX = 'X'.codeUnitAt(0);
          _winKeybdEvent?.call(vkLWin, 0, 0, 0);
          _winKeybdEvent?.call(vkX, 0, 0, 0);
          _winKeybdEvent?.call(vkX, 0, keyUp, 0);
          _winKeybdEvent?.call(vkLWin, 0, keyUp, 0);
          break;
        case 'win_i':
          final vkI = 'I'.codeUnitAt(0);
          _winKeybdEvent?.call(vkLWin, 0, 0, 0);
          _winKeybdEvent?.call(vkI, 0, 0, 0);
          _winKeybdEvent?.call(vkI, 0, keyUp, 0);
          _winKeybdEvent?.call(vkLWin, 0, keyUp, 0);
          break;
        case 'win_l':
          _winLockWorkStation?.call();
          break;
        case 'ctrl_c':
          final vkC = 'C'.codeUnitAt(0);
          _winKeybdEvent?.call(vkControl, 0, 0, 0);
          _winKeybdEvent?.call(vkC, 0, 0, 0);
          _winKeybdEvent?.call(vkC, 0, keyUp, 0);
          _winKeybdEvent?.call(vkControl, 0, keyUp, 0);
          break;
        case 'ctrl_v':
          final vkV = 'V'.codeUnitAt(0);
          _winKeybdEvent?.call(vkControl, 0, 0, 0);
          _winKeybdEvent?.call(vkV, 0, 0, 0);
          _winKeybdEvent?.call(vkV, 0, keyUp, 0);
          _winKeybdEvent?.call(vkControl, 0, keyUp, 0);
          break;
        case 'ctrl_a':
          final vkA = 'A'.codeUnitAt(0);
          _winKeybdEvent?.call(vkControl, 0, 0, 0);
          _winKeybdEvent?.call(vkA, 0, 0, 0);
          _winKeybdEvent?.call(vkA, 0, keyUp, 0);
          _winKeybdEvent?.call(vkControl, 0, keyUp, 0);
          break;
        case 'task_mgr':
        case 'ctrl_alt_del':
        case 'ctrl_shift_esc':
          // Ctrl+Shift+Esc гарантированно открывает Диспетчер задач без требования SAS
          _winKeybdEvent?.call(vkControl, 0, 0, 0);
          _winKeybdEvent?.call(vkShift, 0, 0, 0);
          _winKeybdEvent?.call(vkEscape, 0, 0, 0);
          _winKeybdEvent?.call(vkEscape, 0, keyUp, 0);
          _winKeybdEvent?.call(vkShift, 0, keyUp, 0);
          _winKeybdEvent?.call(vkControl, 0, keyUp, 0);
          break;
        case 'alt_tab':
          _winKeybdEvent?.call(vkMenu, 0, 0, 0);
          _winKeybdEvent?.call(vkTab, 0, 0, 0);
          _winKeybdEvent?.call(vkTab, 0, keyUp, 0);
          _winKeybdEvent?.call(vkMenu, 0, keyUp, 0);
          break;
        case 'alt_f4':
          _winKeybdEvent?.call(vkMenu, 0, 0, 0);
          _winKeybdEvent?.call(vkF4, 0, 0, 0);
          _winKeybdEvent?.call(vkF4, 0, keyUp, 0);
          _winKeybdEvent?.call(vkMenu, 0, keyUp, 0);
          break;
        case 'esc':
          _winKeybdEvent?.call(vkEscape, 0, 0, 0);
          _winKeybdEvent?.call(vkEscape, 0, keyUp, 0);
          break;
      }
    } else if (Platform.isMacOS) {
      switch (hotkey) {
        case 'win_key':
        case 'spotlight':
        case 'cmd_space':
          // Cmd + Space (Spotlight)
          _postMacKey(55, true); // Cmd
          _postMacKey(49, true); // Space
          _postMacKey(49, false);
          _postMacKey(55, false);
          break;
        case 'task_mgr':
        case 'ctrl_alt_del':
        case 'cmd_opt_esc':
          // Cmd + Option + Escape (Завершить принудительно)
          _postMacKey(55, true); // Cmd
          _postMacKey(58, true); // Option
          _postMacKey(53, true); // Esc
          _postMacKey(53, false);
          _postMacKey(58, false);
          _postMacKey(55, false);
          break;
        case 'alt_tab':
        case 'cmd_tab':
          // Cmd + Tab
          _postMacKey(55, true);
          _postMacKey(48, true);
          _postMacKey(48, false);
          _postMacKey(55, false);
          break;
        case 'alt_f4':
          // Cmd + Q
          _postMacKey(55, true);
          _postMacKey(12, true);
          _postMacKey(12, false);
          _postMacKey(55, false);
          break;
        case 'ctrl_c':
        case 'cmd_c':
          _postMacKey(55, true);
          _postMacKey(8, true);
          _postMacKey(8, false);
          _postMacKey(55, false);
          break;
        case 'ctrl_v':
        case 'cmd_v':
          _postMacKey(55, true);
          _postMacKey(9, true);
          _postMacKey(9, false);
          _postMacKey(55, false);
          break;
        case 'ctrl_a':
        case 'cmd_a':
          _postMacKey(55, true);
          _postMacKey(0, true);
          _postMacKey(0, false);
          _postMacKey(55, false);
          break;
        case 'esc':
          _postMacKey(53, true);
          _postMacKey(53, false);
          break;
      }
    }
  }

  void _postMacKey(int code, bool down) {
    if (_cgEventCreateKeyboardEvent == null || _cgEventPost == null || _cfRelease == null) return;
    final ev = _cgEventCreateKeyboardEvent!(ffi.Pointer.fromAddress(0), code, down);
    if (ev.address != 0) {
      _cgEventPost!(0, ev);
      _cfRelease!(ev);
    }
  }

  int? _mapToMacKeyCode(String key, int? code) {
    if (code != null && code > 0) return code;
    switch (key.toLowerCase()) {
      case 'enter':
      case 'return': return 36;
      case 'tab': return 48;
      case 'space':
      case ' ': return 49;
      case 'backspace':
      case 'delete': return 51;
      case 'escape':
      case 'esc': return 53;
      case 'command':
      case 'meta': return 55;
      case 'shift': return 56;
      case 'option':
      case 'alt': return 58;
      case 'control':
      case 'ctrl': return 59;
      case 'arrowleft': return 123;
      case 'arrowright': return 124;
      case 'arrowdown': return 125;
      case 'arrowup': return 126;
      case 'a': return 0;
      case 's': return 1;
      case 'd': return 2;
      case 'f': return 3;
      case 'h': return 4;
      case 'g': return 5;
      case 'z': return 6;
      case 'x': return 7;
      case 'c': return 8;
      case 'v': return 9;
      case 'b': return 11;
      case 'q': return 12;
      case 'w': return 13;
      case 'e': return 14;
      case 'r': return 15;
      case 'y': return 16;
      case 't': return 17;
      default:
        if (key.length == 1) {
          final cu = key.toUpperCase().codeUnitAt(0);
          if (cu >= 65 && cu <= 90) {
            const macLetters = [0, 11, 8, 2, 14, 3, 5, 4, 34, 38, 40, 37, 46, 45, 31, 35, 12, 15, 1, 17, 32, 9, 13, 7, 16, 6];
            return macLetters[cu - 65];
          }
        }
        return null;
    }
  }

  int _mapToWinKeyCode(String key, int? code) {
    if (code != null && code > 0) return code;
    switch (key.toLowerCase()) {
      case 'enter': return 0x0D; // VK_RETURN
      case 'tab': return 0x09;   // VK_TAB
      case 'space':
      case ' ': return 0x20;     // VK_SPACE
      case 'backspace': return 0x08; // VK_BACK
      case 'delete': return 0x2E; // VK_DELETE
      case 'escape':
      case 'esc': return 0x1B;    // VK_ESCAPE
      case 'control':
      case 'ctrl': return 0x11;   // VK_CONTROL
      case 'alt': return 0x12;    // VK_MENU
      case 'shift': return 0x10;  // VK_SHIFT
      case 'meta':
      case 'win': return 0x5B;    // VK_LWIN
      case 'arrowleft': return 0x25; // VK_LEFT
      case 'arrowright': return 0x27; // VK_RIGHT
      case 'arrowup': return 0x26;   // VK_UP
      case 'arrowdown': return 0x28; // VK_DOWN
      default:
        if (key.isNotEmpty) {
          return key.toUpperCase().codeUnitAt(0);
        }
        return 0;
    }
  }
}
