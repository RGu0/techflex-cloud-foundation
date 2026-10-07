# Independent installations and refresh families

`DeviceTrustService` registers separate installations within the same tenant.
Each installation has its own UUID and credential versions: rotating one
refuses its old fingerprint; revoking one leaves other installations usable.
Platform hints such as `ios` and `android` are descriptive and prove no
physical-device identity. An installation owns no License.

`RefreshSessionService.issue` starts a distinct family by default. Rotation
preserves that family. A used refresh token replay revokes its entire family,
including the legitimate successor, while other families remain usable.
`revoke_family` has the same family boundary; `revoke` affects one session.

Public compatibility tests in `tests/test_multi_installation_isolation.py`
exercise three installations in one tenant and three independent refresh
families for one account, independent rotation, individual revocation and
family replay. They also retain tenant-scoped hardware lease refusal and an
unaffected refresh family from another tenant. These are real reference
services, not production HTTP activation or seat-policy acceptance.

Applications must persist the authenticated tenant, installation ID and its
refresh-family association. Never reuse one family across independent
installations: the intended family-wide replay response would sign them all
out. Terminal revocation must coordinate its installation credential and
associated refresh family; the library does not automatically join them.
Validate tenant ownership before administration operations: primitive IDs
are not authorization. Persistent adapters must provide transaction and
concurrency guarantees appropriate to the application's rotation/revocation.

Account/password activation, client-supplied installation ID mapping,
terminal names/listing/rename, institution seats and atomic quota counting,
signed business License issuance, and live deployment remain application
responsibilities. The library sets no seat defaults, creates no business
License fields, and does not turn a hardware lease into an account-wide
login lease. These tests do not assert deployment or adoption by another
repository.
