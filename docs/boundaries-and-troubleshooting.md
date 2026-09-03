# Boundaries & Troubleshooting

Audience: engineers and agents integrating `techflex-cloud-foundation`.
This page states what the library owns versus what your application owns,
which capabilities are provisional, and what each public error means.

## Application vs library boundary

Aligned with RAY-341. When in doubt: the library owns *mechanisms*, the
application owns *policy and identity of its own business*.

| Area | Library owns | Application owns |
| -- | -- | -- |
| Transport | `SecureTransport`/`AuthorizedTransport`, correlation IDs, one-shot 401 refresh | Endpoints per environment, `TokenProvider`/`CredentialVault` implementations |
| Cloud config | Vendored `integration` default, schema validator | Production/staging profiles, injected via `parse_cloud_default_config`; never vendored here |
| Durability | `atomic_write`, `connect_durable`, sealed containers, markers | What to store, where, and when to delete |
| Uploads | Manifest format, operation queue, object-store contract | Artifact kinds, business payload schemas |
| License | Trust-bundle verification, entitlement decision shape, lifecycle states | SKU, pricing, terms, which capabilities exist |
| Data lifecycle | Eligibility/retention/deletion decision & receipt types | Which artifacts may upload, retention windows, consent and legal-hold decisions |
| Cloud platform | Provider-neutral contracts (`ImmutableObjectStore`, `DatabaseRuntime`) | Cloud accounts, domains, certificates, KMS keys, physical bucket names, production credentials |
| Compliance | Redacted release evidence | Regional privacy, clinical, and production acceptance |

## Provisional capabilities

A capability proven by exactly one consuming product is **provisional** until
a second consumer confirms it. Currently provisional:

- The vendored `integration` cloud default bundle (FeetForcePlate evidence
  only, RAY-364).

Everything else in the v1 API is covered by the library's own test suite and
the independent wheel-consumer validation.

## Error catalogue

All library errors are typed and specific; the library never returns a bare
boolean for a security-relevant failure. Each family has a base class —
`CloudConfigError`, `TokenError`, `ManifestError`, `ObjectStoreError`,
`LifecycleError`, `ProvenanceError` — so callers may catch precisely (`except
TokenExpired`) or broadly (`except TokenError`). Grouped by family:

### Cloud configuration (`cloud_config`)

| Error | Meaning | What to do |
| -- | -- | -- |
| `CloudConfigChannelUnknown` | Channel has no vendored bundle | Pass `integration`, or supply your own document via `parse_cloud_default_config` |
| `CloudConfigMalformed` | Field missing/invalid (e.g. non-https `api_base_url`, non-PEM CA, key not 32 bytes) | Fix the document; do not patch around the validator |
| `CloudConfigVersionUnsupported` | Unknown `schema_version` | Upgrade the library or downgrade the document; versions are refused, never guessed |

### Tokens (`tokens`)

| Error | Meaning | What to do |
| -- | -- | -- |
| `TokenMalformed` | Not a well-formed compact token | Check transport corruption / wrong endpoint |
| `TokenSignatureInvalid` | Signature does not verify | Wrong secret/key id — re-enroll credentials |
| `TokenHeaderMismatch` | `kid`/`typ` is not this codec's | Token was issued for another key or purpose |
| `TokenAudienceMismatch` | `aud` is not this audience | Token presented to the wrong service |
| `TokenExpired` | `exp` in the past | Refresh via your `TokenProvider` |

### Manifests (`manifest`)

| Error | Meaning | What to do |
| -- | -- | -- |
| `ManifestMalformed` | Structural violation (bad digest form, unsafe path, duplicate entries) | Fix the producer; do not accept the manifest |
| `ManifestVersionUnsupported` | Unknown format/schema version | Negotiate a supported version |
| `ManifestIntegrityError` | Payload bytes != committed digest/size | Discard the payload; re-stage from source |

### Object store (`object_store`)

| Error | Meaning | What to do |
| -- | -- | -- |
| `ObjectSizeMismatch` / `ObjectDigestMismatch` | Stored bytes failed verification | Retry with correct bytes; never force-write |
| `ObjectConflict` | Same key, different content | Raw artifacts are immutable — pick a new key (digest-derived) or quarantine |

### Sealed storage (`sealed_store`)

| Error | Meaning | What to do |
| -- | -- | -- |
| `SealVerificationError` | Ciphertext/header failed verification | Treat as tamper or corruption; quarantine the file |

### Local state (`keystore`, `local_sqlite`, `lifecycle`, `provenance`)

| Error | Meaning | What to do |
| -- | -- | -- |
| `KeyProviderUnavailable` | Local key cannot be obtained | User/operator intervention; not retryable |
| `LifecycleMalformed` / `LifecycleVersionUnsupported` | Invalid or unknown lifecycle document | Fix policy/record; versions are refused |
| `ProvenanceMalformed` / `ProvenanceVersionUnsupported` | Invalid or unknown provenance record | Same rule: refuse, never guess |

### Platform configuration (`platform_config`)

`PlatformConfigError` / `PlatformConfigMalformed` /
`PlatformConfigVersionUnsupported` govern server-side deployment profiles;
the same refuse-unknown-version rule applies.

## Audit-log trust boundary (`local_audit`)

`ChainedAppendLog` is tamper-*evident*, not tamper-*proof*, and the evidence
it produces is bounded by its retention window. Three limits matter when you
rely on it:

**A self-consistent forgery is undetectable from inside the directory.**
`verified_records()` checks that every record's digest recomputes and links to
the record before it. A forged chain built the same way satisfies both checks,
so replacing the whole log directory leaves nothing behind for the log itself
to notice.

Closing that gap requires an anchor kept **outside** the directory. Record
`head_digest()` — the digest of the oldest surviving record — somewhere the
log's writer cannot reach (a server, a separate device, an operator's notes),
and compare it when you read the log back. A mismatch you did not cause means
the retained chain is not the one you anchored.

**Rotation legitimately advances the anchor.** Generations rotate with bounded
retention, and the oldest is deleted. When that happens `head_digest()`
changes without anything being wrong, and every record before the new head is
gone: no local evidence remains that it ever existed. So a caller re-anchors
after rotation, and treats "before the current head" as outside what this
directory can prove. If your retention requirement is longer than the window,
copy generations off the device before they rotate out — the library owns the
mechanism, your application owns the retention policy.

**Recovery repairs the tail, and can drop a record.** A crash between the
record bytes and their terminating newline leaves an unterminated final line.
On the next open, a line that is a complete record with a correct digest is
completed with its newline and kept; anything else is a torn write and is
truncated away. A record can therefore be missing after a crash even though
`append()` returned — that append had not reached durable storage. Records
that survive recovery are intact and verifiable; recovery never leaves a
generation half-readable.

## General rules

- A validation failure is a signal to fix the input, never to bypass the
  check.
- Unknown versions and channels fail closed.
- If you need a capability the boundary table assigns to the application,
  implement it on your side; if you believe it belongs in the library, file a
  Linear issue rather than forking the mechanism.
