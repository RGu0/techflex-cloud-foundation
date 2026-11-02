# RAY-910 export fixture

`ray910_export.ndjson` is a diagnostic export produced by the client's own
code: gait-insole-flutter `origin/main` `e3bb2b44377466b03f8ccaaca72f63c3b77b66bc`,
files `packages/app_common/lib/src/redactor.dart` and
`packages/app_common/lib/src/diagnostics_bundle.dart`, run by
`make_ray910_export.dart` (Dart 3.13.5) with the layout of
`apps/insole_app/lib/application/diagnostics_export.dart`.

The input deliberately holds identity data (registered names, an institution
number, phone numbers in full and half width, an e-mail, a resident ID, a
map keyed by a phone number) and one line that is not JSON, so the fixture
shows what the client's redaction leaves for the cloud's whitelist to accept.

Header ids: tenant `5a1f0c3e-7b2d-4e8a-9c6f-2d4b8e1a0f37`, terminal
`c3d9e2f1-6a4b-4f0c-8e7d-9b2a1c0d3e5f`.

To regenerate, copy the two client files next to the generator and run
`dart run make_ray910_export.dart > ray910_export.ndjson`.
