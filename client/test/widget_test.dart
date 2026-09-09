import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:ligament_authenticator/services/auth_state.dart';
import 'package:ligament_authenticator/screens/approval_modal.dart';

void main() {
  testWidgets('ApprovalModal renders challenge metadata and buttons', (WidgetTester tester) async {
    final prompt = {
      'challenge_id': '00000000-0000-0000-0000-000000000001',
      'who': 'test_employee',
      'ip': '192.168.1.50',
      'ua': 'Chrome / Windows',
      'service': 'Wi-Fi: Corporate-Secure',
      'number_match': '',
      'expires_in_seconds': 60,
    };

    final authState = AuthState();

    await tester.pumpWidget(
      MaterialApp(
        home: ChangeNotifierProvider.value(
          value: authState,
          child: Scaffold(
            body: ApprovalModal(prompt: prompt),
          ),
        ),
      ),
    );

    expect(find.text('Запрос на вход'), findsOneWidget);
    expect(find.text('Wi-Fi: Corporate-Secure'), findsOneWidget);
    expect(find.text('test_employee'), findsOneWidget);
    expect(find.text('192.168.1.50'), findsOneWidget);
    expect(find.text('Принять'), findsOneWidget);
    expect(find.text('Отклонить'), findsOneWidget);
  });
}
