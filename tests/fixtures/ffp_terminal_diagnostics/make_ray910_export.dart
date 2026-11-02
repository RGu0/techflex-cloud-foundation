// Generates ray910_export.ndjson with the client's own export code.
//
// Copy packages/app_common/lib/src/redactor.dart and diagnostics_bundle.dart
// from gait-insole-flutter (README.md names the commit) next to this file,
// then run `dart run make_ray910_export.dart > ray910_export.ndjson`.
// The layout mirrors DiagnosticsExporter._build / _command
// (apps/insole_app/lib/application/diagnostics_export.dart): the identities
// the terminal holds are registered, log lines are the logger's LogRecord
// JSON as written (raw here, to exercise the export-time redaction), and
// command entries carry the CommandLogEntry fields.
import 'dart:convert';
import 'dart:io';

import 'diagnostics_bundle.dart';
import 'redactor.dart';

const tenantId = '5a1f0c3e-7b2d-4e8a-9c6f-2d4b8e1a0f37';
const terminalId = 'c3d9e2f1-6a4b-4f0c-8e7d-9b2a1c0d3e5f';

String record(
  String t,
  String level,
  String cat,
  String msg, {
  Map<String, Object?> fields = const {},
  String? error,
  String? stack,
}) => jsonEncode({
  't': t,
  'level': level,
  'cat': cat,
  'msg': msg,
  if (fields.isNotEmpty) 'fields': fields,
  'error': ?error,
  'stack': ?stack,
});

Map<String, Object?> command(
  String t,
  String name,
  String params,
  String expected,
  String actual,
  int elapsedMs,
  String status,
  String ending, {
  String? rejection,
  String summary = '',
}) => {
  't': t,
  'command': name,
  'params': params,
  'expected_reply': expected,
  'actual_reply': actual,
  'elapsed_ms': elapsedMs,
  'status': status,
  'ending': ending,
  'rejection': ?rejection,
  if (summary.isNotEmpty) 'summary': summary,
};

void main() {
  final redactor = Redactor();
  // subjectIdentityValues: display name, institution id, contact.
  for (final value in ['王芳', 'Li Wei', 'A-0042', '13900001111', 'Zhang']) {
    redactor.registerSensitiveValue(value);
  }
  final logLines = [
    record('2026-10-29T06:40:00.000Z', 'info', 'app', 'app started', fields: {
      'app_version': '1.6.0+42',
      'telemetry': true,
    }),
    record('2026-10-29T06:40:02.120Z', 'info', 'ble', 'connected', fields: {
      'device_name': 'Insole-L-0042',
      'left_mac_address': 'C0:FF:EE:00:00:01',
      'rssi': -61,
      'frame': '0102 3040 5060',
    }),
    record('2026-10-29T06:41:10.000Z', 'info', 'subject', 'subject 王芳 selected',
        fields: {
          'subject_uuid': '8d0b9c1e-5f2a-4c4e-9b8a-0d6f3e2a1b7c',
          'subject_name': '王芳',
          'institutionNo': 'A-0042',
          'contactTel': '13900001111',
          'visits': [
            {'doctor_name': 'Zhang', 'room': 3},
          ],
        }),
    'this line was cut short by a cras',
    record('2026-10-29T06:42:00.000Z', 'warning', 'sync',
        'upload failed for li.wei@example.com, call １３８ １２３４ ５６７８',
        fields: {
          '13812345678': {'attempts': 2},
          'note': 'Li Wei asked to retry; id 11010519491231002X',
        },
        error: 'SocketException: Connection reset (OS Error: 0755-1234-5678)',
        stack: '#0      SyncWorker.run (package:insole_app/sync.dart:88:7)'),
    record('2026-10-29T06:43:00.000Z', 'error', 'ble', 'notify timeout',
        error: 'TimeoutException after 0:00:05.000000'),
  ];
  final commands = [
    command('2026-10-29T06:40:03.000Z', 'READ_BATTERY', '', 'BAT', 'BAT 3987', 42,
        'success', 'replied'),
    command('2026-10-29T06:40:04.000Z', 'SET_RATE', 'hz=100', 'OK', '', 5000,
        'failure', 'timeout', rejection: 'timeout', summary: 'no reply in 5000 ms'),
  ];
  final text = DiagnosticsBundle.build(
    redactor: redactor,
    header: {
      'exported_at': '2026-10-29T06:51:33.000Z',
      'app_version': '1.6.0+42',
      'cloud_environment': 'integration',
      'platform': 'android',
      'os_version': '15',
      'terminal_id': terminalId,
      'tenant_id': tenantId,
    },
    logLines: logLines,
    commands: commands,
  );
  stdout.write(text);
}
