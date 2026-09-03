# API Reference

Generated from `techflex_cloud_foundation.__all__` by
`scripts/generate_api_reference.py`; do not edit by hand. Docstrings are the
single source of truth — update the code and regenerate:

```bash
uv run --locked --extra dev python scripts/generate_api_reference.py --project-root . --output docs/api-reference.md
```

Every exported symbol is listed with its defining module and signature.


## `techflex_cloud_foundation.cloud_config`


### `CloudConfigChannelUnknown`


The requested channel has no vendored default bundle.


### `CloudConfigError`


Base class for cloud default configuration failures.


### `CloudConfigMalformed`


The document or a referenced resource is structurally invalid.


### `CloudConfigVersionUnsupported`


The document declares a schema version this build refuses.


### `CloudDefaultConfig(meta: 'CloudDefaultConfigMeta', ca_bundle_pem: 'bytes', license_public_key: 'bytes') -> None`


A validated cloud default with its resource bytes resolved.


### `CloudDefaultConfigMeta(schema_version: 'str', channel: 'str', api_base_url: 'str', license_key_id: 'str', ca_bundle_resource: 'str', license_public_key_resource: 'str') -> None`


A validated cloud default document, before resource resolution.


### `load_default_cloud_config(channel: 'str' = 'integration') -> 'CloudDefaultConfig'`


Load the vendored default bundle for ``channel``.


### `parse_cloud_default_config(document: 'Mapping[str, Any]') -> 'CloudDefaultConfigMeta'`


Validate a cloud default document against the supported schema.


## `techflex_cloud_foundation.database`


### `DatabaseRuntime(pool: '_Pool', health: 'HealthProbe') -> None`


Own one server-side pool; repositories own SQL and transaction contents.


### `HealthProbe(*args, **kwargs)`


Base class for protocol classes.


### `TransactionScope(*args, **kwargs)`


Base class for protocol classes.


## `techflex_cloud_foundation.diagnostics`


### `AuditSink(*args, **kwargs)`


Base class for protocol classes.


### `MetricsSink(*args, **kwargs)`


Base class for protocol classes.


## `techflex_cloud_foundation.durability`


### `AtomicFileWriter(*args, **kwargs)`


Staged file writer: temporary until ``commit``, discarded on ``abort``.


### `StagedAtomicFileWriter(destination: 'str | Path', *, mode: 'int' = 384, fsync_dir: 'bool' = True) -> 'None'`


Default ``AtomicFileWriter``: temp file, fsync, atomic rename.


### `atomic_write(destination: 'str | Path', payload: 'bytes', *, mode: 'int' = 384, fsync_dir: 'bool' = True) -> 'Path'`


Write ``payload`` to ``destination`` in one crash-safe operation.


### `fsync_directory(path: 'str | Path') -> 'None'`


Persist a renamed directory entry where the platform exposes handles.


### `set_private_file_mode(path: 'str | Path', descriptor: 'int | None' = None) -> 'None'`


Restrict a file to owner-only (0o600) on POSIX; best-effort on Windows.


### `write_all(descriptor: 'int', data: 'bytes') -> 'None'`


Write every byte despite short writes, or raise ``OSError``.


## `techflex_cloud_foundation.entitlement`


### `EntitlementDecision(license_id: 'UUID', application_id: 'str', capabilities: 'frozenset[str]', policy_revision: 'int', evaluated_at: 'datetime') -> None`


EntitlementDecision(license_id: 'UUID', application_id: 'str', capabilities: 'frozenset[str]', policy_revision: 'int', evaluated_at: 'datetime')


### `EntitlementResolver(*args, **kwargs)`


Base class for protocol classes.


### `LicenseLifecycle()`


**undocumented — add a docstring**


### `LicenseRecord(license_id: 'UUID', state: 'LicenseState', version: 'int', tenant_id: 'UUID | None' = None, account_id: 'UUID | None' = None, hardware_id: 'str | None' = None) -> None`


LicenseRecord(license_id: 'UUID', state: 'LicenseState', version: 'int', tenant_id: 'UUID | None' = None, account_id: 'UUID | None' = None, hardware_id: 'str | None' = None)


### `LicenseState(value, names=None, *, module=None, qualname=None, type=None, start=1, boundary=None)`


Enum where members are also (and must be) strings


### `SignedTrustBundle(bundle: 'TrustBundle', signature: 'str') -> None`


SignedTrustBundle(bundle: 'TrustBundle', signature: 'str')


### `TrustBundle(revision: 'int', issued_at: 'datetime', signing_keys: 'Mapping[str, bytes]', revoked_key_ids: 'tuple[str, ...]', policy: 'Mapping[str, bool]') -> None`


TrustBundle(revision: 'int', issued_at: 'datetime', signing_keys: 'Mapping[str, bytes]', revoked_key_ids: 'tuple[str, ...]', policy: 'Mapping[str, bool]')


### `TrustBundleVerifier(root_public_key: 'bytes') -> 'None'`


**undocumented — add a docstring**


## `techflex_cloud_foundation.gateway`


### `ErrorEnvelope(code: 'str', message: 'str', correlation_id: 'str') -> None`


The stable error body: code, message, and correlation id.


### `GatewayAuthenticationRefused`


The credential is missing, malformed, expired, or mismatched.


### `GatewayError`


Base class for request validation failures.


### `GatewayMalformed`


A request component is structurally invalid.


### `GatewayPayloadTooLarge`


The payload exceeds the configured size cap.


### `GatewayRateLimited(message: 'str', *, retry_after_seconds: 'float') -> 'None'`


The principal exceeded its rate policy; retry after the given delay.


### `GatewayTenantMismatch`


The payload names a tenant other than the authenticated one.


### `InMemoryRateLimitStore() -> 'None'`


Volatile token-bucket reference, suitable for tests and integration.


### `RateLimitPolicy(max_requests: 'int', window_seconds: 'int') -> None`


Token-bucket policy per authenticated principal.


### `RateLimitStore(*args, **kwargs)`


Persistence boundary for rate buckets; production binds shared state.


### `RequestValidator(codec: 'HmacTokenCodec', *, max_payload_bytes: 'int', rate_limit: 'RateLimitPolicy | None' = None, rate_store: 'RateLimitStore | None' = None) -> 'None'`


One validation pipeline: authenticate, cap, rate-limit, bind tenant.


### `TrustedRequestContext(tenant_id: 'str', subject_id: 'str', correlation_id: 'str', token_digest: 'str', token_expires_at: 'datetime | None') -> None`


What a validated request may rely on; tenant is token-derived only.


## `techflex_cloud_foundation.ingestion`


### `ArtifactReceipt(session_id: 'UUID', manifest_digest: 'str', manifest_object_key: 'str', eligibility_reason: 'str', eligibility_policy_version: 'str', completed_at: 'datetime', idempotency_key: 'str') -> None`


The final, immutable completion receipt for one ingestion session.


### `InMemoryIngestionStore() -> 'None'`


Volatile reference store, suitable for tests and integration runs.


### `IngestionAccessDenied`


The principal may not perform this operation.


### `IngestionConflict`


A slot or idempotency key already holds different content.


### `IngestionEligibilityRejected`


Completion was attempted without an allowing eligibility decision.


### `IngestionError`


Base class for ingestion plane failures.


### `IngestionMalformed`


A request or record is structurally invalid.


### `IngestionPrincipal(tenant_id: 'str', uploader_id: 'str', allow_upload: 'bool', expires_at: 'datetime') -> None`


Narrow data-plane principal derived from trusted authentication.


### `IngestionSchemaUnsupported`


The declared payload schema version is not served by this deployment.


### `IngestionService(objects: 'ImmutableObjectStore', sessions: 'IngestionSessionStore', *, supported_payload_schemas: 'frozenset[str]') -> 'None'`


Orchestrates sessions, verified parts, and the final receipt.


### `IngestionSessionStore(*args, **kwargs)`


Persistence boundary; production binds PostgreSQL, tests use memory.


### `IngestionStateError`


The session state does not allow this operation.


### `PartAcknowledgement(session_id: 'UUID', index: 'int', sha256: 'str', object_key: 'str', idempotent_replay: 'bool' = False) -> None`


Per-part receipt; a part ack is not session completion.


### `PartListResponse(session_id: 'UUID', received: 'tuple[PartAcknowledgement, ...]', missing: 'tuple[int, ...]') -> None`


PartListResponse(session_id: 'UUID', received: 'tuple[PartAcknowledgement, ...]', missing: 'tuple[int, ...]')


### `PartMetadata(index: 'int', sha256: 'str', size: 'int', payload_schema: 'str') -> None`


Client-declared facts about one part; verified against actual bytes.


### `SessionState(value, names=None, *, module=None, qualname=None, type=None, start=1, boundary=None)`


Enum where members are also (and must be) strings


### `SessionStatus(session_id: 'UUID', state: 'SessionState', payload_schema: 'str', part_count: 'int', received_count: 'int', conflicted_indices: 'tuple[int, ...]', receipt: 'ArtifactReceipt | None') -> None`


SessionStatus(session_id: 'UUID', state: 'SessionState', payload_schema: 'str', part_count: 'int', received_count: 'int', conflicted_indices: 'tuple[int, ...]', receipt: 'ArtifactReceipt | None')


## `techflex_cloud_foundation.keystore`


### `AesGcmBlobCodec(key_provider: 'KeyProvider') -> 'None'`


AES-256-GCM envelope whose key is fetched per use, never persisted.


### `FileKeyProvider(key_file: 'str | Path') -> 'None'`


Local 32-byte key file, created atomically with owner-only permissions.


### `KeyProvider(*args, **kwargs)`


Key handle boundary implemented by an OS secure-storage adapter.


### `KeyProviderUnavailable`


The key handle exists but cannot be reached at this moment.


## `techflex_cloud_foundation.lifecycle`


### `DeletionDecision(artifact_digest: 'str', reason: 'str', decided_by: 'str', decided_at: 'datetime', policy_version: 'str', format_version: 'int' = 1) -> None`


An explicit, attributable authorization to delete one artifact.


### `DeletionReceipt(artifact_digest: 'str', decision_digest: 'str', deleted_at: 'datetime', format_version: 'int' = 1) -> None`


Proof that a deletion happened, committing to its explicit decision.


### `EligibilityDecision(purpose: 'str', allowed: 'bool', reason: 'str', policy_version: 'str', decided_at: 'datetime') -> None`


The policy's answer for one upload attempt, with its reasoning.


### `LifecycleError`


Base class for eligibility, retention, and deletion failures.


### `LifecycleMalformed`


A policy, decision, or receipt is structurally invalid.


### `LifecycleVersionUnsupported`


A serialized record declares a format version this build refuses.


### `Purpose(name: 'str', default_retention: 'RetentionClass', upload_allowed: 'bool' = True, deletion_requires_confirmation: 'bool' = True) -> None`


One declared use of uploaded artifacts and its retention behavior.


### `RetentionClass(value, names=None, *, module=None, qualname=None, type=None, start=1, boundary=None)`


Neutral retention tiers; concrete durations stay deployment policy.


### `UploadEligibilityPolicy(purposes: 'tuple[Purpose, ...]', policy_version: 'str') -> None`


Named purposes under one versioned policy; unknown purposes refuse.


## `techflex_cloud_foundation.local_audit`


### `ChainedAppendLog(root: 'str | Path', *, max_generation_bytes: 'int' = 1048576, generations: 'int' = 3) -> 'None'`


Append-only hash-chained log with rotation and crash recovery.


### `ChainedRecord(payload: 'Mapping[str, object]', sha256: 'str', previous_sha256: 'str | None') -> None`


One verified log entry: opaque payload plus its chain position.


## `techflex_cloud_foundation.local_sqlite`


### `DurableConnection(connection: 'sqlite3.Connection') -> 'None'`


Thread-safe wrapper around an SQLite connection.


### `LocalSqlitePolicy(journal_mode: 'str' = 'WAL', synchronous: 'str' = 'FULL', busy_timeout_ms: 'int' = 5000, foreign_keys: 'bool' = True) -> None`


Durability pragmas applied to a local SQLite connection.


### `LocalSqliteStatus(journal_mode: 'str', synchronous: 'str', busy_timeout_ms: 'int', foreign_keys: 'bool', schema_version: 'int') -> None`


Live PRAGMA values read back from a connection for self-checks.


### `Migration(version: 'int', apply: 'Callable[[sqlite3.Connection], None]') -> None`


A single user_version migration applied to a connection.


### `UserVersionMigrator(migrations: 'Iterable[Migration]') -> 'None'`


Applies ordered PRAGMA user_version migrations, each in a transaction.


### `connect_durable(path: 'str | Path', policy: 'LocalSqlitePolicy' = LocalSqlitePolicy(journal_mode='WAL', synchronous='FULL', busy_timeout_ms=5000, foreign_keys=True)) -> 'DurableConnection'`


Open a local SQLite database with the durability policy applied.


### `inspect_durability(connection: 'sqlite3.Connection | DurableConnection') -> 'LocalSqliteStatus'`


Read the live durability pragmas and schema version of a connection.


## `techflex_cloud_foundation.manifest`


### `ArtifactEntry(path: 'str', size: 'int', sha256: 'str', codec: 'str | None' = None, parts: 'tuple[ArtifactPart, ...]' = ()) -> None`


One named payload member with its complete digest and optional parts.


### `ArtifactManifest(entries: 'tuple[ArtifactEntry, ...]', artifact_kind: 'str', format_version: 'int' = 1, schema_version: 'int' = 1, codec_version: 'int' = 1, parent: 'ParentReference | None' = None, annotations: 'dict[str, str]' = <factory>) -> None`


Versioned, content-addressed description of one artifact payload.


### `ArtifactPart(index: 'int', offset: 'int', size: 'int', sha256: 'str') -> None`


One byte range of an entry, digest-addressed for resumable transfer.


### `ManifestError`


Base class for manifest failures.


### `ManifestIntegrityError`


Payload bytes do not match the size or digest the manifest commits to.


### `ManifestMalformed`


The serialized form or a field value is structurally invalid.


### `ManifestVersionUnsupported`


The manifest declares a format or schema version this build refuses.


### `ParentReference(digest: 'str', relationship: 'str') -> None`


Link to the manifest this artifact derives from.


### `verify_entry_payload(entry: 'ArtifactEntry', chunks: 'Iterable[bytes]') -> 'None'`


Check streamed payload bytes against the entry's size and complete digest.


## `techflex_cloud_foundation.object_store`


### `FileSystemObjectStore(root: 'str | Path') -> 'None'`


Private filesystem object storage with verified atomic publication.


### `ImmutableObjectStore(*args, **kwargs)`


Content-addressed, verify-on-write object storage boundary.


### `InMemoryObjectStore() -> 'None'`


Volatile reference implementation, suitable for tests and integration.


### `ObjectConflict`


An immutable key already exists with different content.


### `ObjectDigestMismatch`


Streamed payload digest differs from the declared sha256.


### `ObjectSizeMismatch`


Streamed payload length differs from the declared size.


### `ObjectStoreError`


Base class for object-store failures.


### `StoredObject(object_key: 'str', sha256: 'str', size_bytes: 'int') -> None`


StoredObject(object_key: 'str', sha256: 'str', size_bytes: 'int')


## `techflex_cloud_foundation.platform_config`


### `BucketBinding(role: 'BucketRole', physical_bucket: 'str', policy: 'BucketPolicy') -> None`


One logical role mapped to one physical bucket under one policy.


### `BucketEncryption(value, names=None, *, module=None, qualname=None, type=None, start=1, boundary=None)`


Enum where members are also (and must be) strings


### `BucketPolicy(encryption: 'BucketEncryption', versioning: 'bool', retention: 'RetentionClass') -> None`


Access/shape constraints one physical bucket binding must satisfy.


### `BucketRole(value, names=None, *, module=None, qualname=None, type=None, start=1, boundary=None)`


Logical bucket roles; physical bucket names stay deployment values.


### `DeploymentProfile(environment: 'Environment', region: 'str', ingress: 'IngressProfile', kms: 'SecretRef', databases: 'Mapping[str, SecretRef]', buckets: 'tuple[BucketBinding, ...]', products: 'tuple[ProductRegistration, ...]') -> None`


A validated, immutable deployment profile.


### `Environment(value, names=None, *, module=None, qualname=None, type=None, start=1, boundary=None)`


Enum where members are also (and must be) strings


### `IngressProfile(public_base_url: 'str', port: 'int', public_ca: 'bool') -> None`


Public entrypoint shape; production rules are enforced by the profile.


### `PlatformConfigError`


Base class for platform deployment profile failures.


### `PlatformConfigMalformed`


The document or a field value is structurally invalid.


### `PlatformConfigVersionUnsupported`


The document declares a schema version this build refuses.


### `ProductRegistration(product_id: 'str', supported_schema_versions: 'tuple[str, ...]') -> None`


One registered product and the schema versions this deployment serves.


### `SecretProvider(value, names=None, *, module=None, qualname=None, type=None, start=1, boundary=None)`


Where a secret's bytes live; the profile names only the location.


### `SecretRef(provider: 'SecretProvider', locator: 'str') -> None`


A reference to secret material held elsewhere; never the material.


### `parse_deployment_profile(document: 'Mapping[str, Any]') -> 'DeploymentProfile'`


Validate a deployment profile document against the supported schema.


## `techflex_cloud_foundation.product_registry`


### `ClientDeclaration(product_id: 'str', protocol_version: 'str', schema_version: 'str', config_version: 'str', client_version: 'str') -> None`


The versions a client declares; every field is required, never guessed.


### `CompatibilityDecision(kind: 'CompatibilityDecisionKind', product_id: 'str', reason: 'str', migration_path: 'tuple[str, ...]' = (), minimum_version: 'str | None' = None) -> None`


The registry's explicit answer for one declaration, with its reasoning.


### `CompatibilityDecisionKind(value, names=None, *, module=None, qualname=None, type=None, start=1, boundary=None)`


The explicit outcome of a compatibility decision; none is implicit.


### `ProductCatalog(products: 'tuple[ProductRecord, ...]', schema_version: 'str' = 'techflex-product-catalog/1') -> None`


A validated, immutable catalog of registered products.


### `ProductCompatibilityPolicy(*args, **kwargs)`


Injected product version semantics; the registry never hardcodes them.


### `ProductRecord(product_id: 'str', supported_client_versions: 'tuple[str, ...]' = (), supported_protocol_versions: 'tuple[str, ...]' = (), supported_schema_versions: 'tuple[str, ...]' = (), adapter_entrypoints: 'tuple[str, ...]' = (), migration_order: 'tuple[str, ...]' = (), minimum_versions: 'Mapping[str, str]' = <factory>) -> None`


One registered product: supported version sets, adapter entrypoints,


### `ProductRegistry(catalog: 'ProductCatalog', policy: 'ProductCompatibilityPolicy') -> None`


Compatibility decisions over a catalog under an injected policy.


### `ProductRegistryError`


Base class for product registry and compatibility failures.


### `ProductRegistryMalformed`


A catalog document, record, or declaration is structurally invalid.


### `ProductRegistryVersionUnsupported`


A catalog document declares a schema version this build refuses.


### `VersionRelation(value, names=None, *, module=None, qualname=None, type=None, start=1, boundary=None)`


How one declared version relates to a registered version.


### `parse_product_catalog(document: 'Any') -> 'ProductCatalog'`


Validate a versioned catalog document against the supported schema.


## `techflex_cloud_foundation.provenance`


### `AdjudicationKind(value, names=None, *, module=None, qualname=None, type=None, start=1, boundary=None)`


Enum where members are also (and must be) strings


### `AdjudicationRecord(kind: 'AdjudicationKind', rationale: 'str', decided_at: 'datetime', rule_version: 'str | None' = None, adjudicator: 'str | None' = None) -> None`


Who or what produced a decision, kept apart from the raw facts.


### `ProvenanceError`


Base class for provenance and validity failures.


### `ProvenanceMalformed`


A record is structurally invalid.


### `ProvenanceRecord(artifact_digest: 'str', sources: 'tuple[str, ...]', transform: 'str', transform_version: 'str', created_at: 'datetime', validity: 'tuple[ValidityEvidence, ...]' = (), format_version: 'int' = 1) -> None`


Lineage of one derived artifact: sources, transform, layered validity.


### `ProvenanceVersionUnsupported`


The record declares a format version this build refuses.


### `ValidityEvidence(level: 'str', status: 'ValidityStatus', adjudication: 'AdjudicationRecord | None' = None, evidence_digest: 'str | None' = None) -> None`


One level's outcome plus the adjudication and facts behind it.


### `ValidityStatus(value, names=None, *, module=None, qualname=None, type=None, start=1, boundary=None)`


Evaluation outcome for one level; absence of evidence stays explicit.


## `techflex_cloud_foundation.reliability`


### `OperationHandler(*args, **kwargs)`


Base class for protocol classes.


### `OperationState(value, names=None, *, module=None, qualname=None, type=None, start=1, boundary=None)`


Enum where members are also (and must be) strings


### `OperationStore(*args, **kwargs)`


Base class for protocol classes.


### `ReliableOperation(operation_id: 'UUID', kind: 'str', payload_ref: 'str', payload_digest: 'str', idempotency_key: 'str', created_at: 'datetime') -> None`


ReliableOperation(operation_id: 'UUID', kind: 'str', payload_ref: 'str', payload_digest: 'str', idempotency_key: 'str', created_at: 'datetime')


### `RetryPolicy(base_delay: 'timedelta' = datetime.timedelta(seconds=5), cap_delay: 'timedelta' = datetime.timedelta(seconds=900)) -> None`


RetryPolicy(base_delay: 'timedelta' = datetime.timedelta(seconds=5), cap_delay: 'timedelta' = datetime.timedelta(seconds=900))


### `SqliteOperationStore(path: 'str | Path', *, policy: 'LocalSqlitePolicy | None' = None) -> 'None'`


Reference durable store for new applications; no application schema dependency.


## `techflex_cloud_foundation.sealed_store`


### `AesGcmSealEncryptor(key_provider: 'KeyProvider') -> 'None'`


AES-256-GCM encryptor; the nonce is prepended to the ciphertext.


### `Marker(marker_id: 'str', payload: 'Mapping[str, Any]', path: 'Path') -> None`


A pending registration marker found during recovery.


### `MarkerRegistry(marker_dir: 'str | Path') -> 'None'`


Exactly-once coupling between a filesystem action and bookkeeping.


### `SealEncryptor(*args, **kwargs)`


AEAD boundary; the header is supplied as associated data.


### `SealVerificationError`


A sealed container failed structural, digest, or decryption checks.


### `SealedArtifact(path: 'Path', header: 'Mapping[str, Any]', payload_sha256: 'str', byte_count: 'int') -> None`


A published sealed container on disk.


### `finalize_delete(trash_path: 'str | Path') -> 'None'`


Permanently remove a file from the trash window.


### `quarantine_file(path: 'str | Path', quarantine_dir: 'str | Path') -> 'Path'`


Move an unreadable or tampered artifact aside, never silently delete it.


### `read_sealed(path: 'str | Path', encryptor: 'SealEncryptor') -> 'tuple[Mapping[str, Any], bytes]'`


Verify then decrypt a sealed container; return (header, plaintext).


### `restore_delete(trash_path: 'str | Path', destination: 'str | Path') -> 'Path'`


Bring a file back out of the trash window.


### `reversible_delete(path: 'str | Path', trash_dir: 'str | Path') -> 'Path'`


Move a file into a trash window instead of deleting it outright.


### `verify_sealed(path: 'str | Path') -> 'tuple[Mapping[str, Any], str]'`


Structurally verify a sealed container; return (header, payload sha256).


### `write_sealed(destination: 'str | Path', plaintext: 'bytes', *, header: 'Mapping[str, Any]', encryptor: 'SealEncryptor') -> 'SealedArtifact'`


Publish one sealed container atomically and verify it after writing.


## `techflex_cloud_foundation.tokens`


### `HmacTokenCodec(*, secret: 'bytes', key_id: 'str', token_type: 'str', audience: 'str') -> 'None'`


Issues and verifies HS256 tokens for one key id, type, and audience.


### `TokenAudienceMismatch`


The payload audience differs from the expected audience.


### `TokenError`


Base class for token issue/verification failures.


### `TokenExpired`


The token's exp claim is in the past.


### `TokenHeaderMismatch`


The header does not pin the expected alg/kid/typ.


### `TokenIssuer(*args, **kwargs)`


Server-side token boundary; claims belong to the application.


### `TokenMalformed`


The token does not have three base64url segments.


### `TokenSignatureInvalid`


The signature does not match the signing input.


## `techflex_cloud_foundation.transport`


### `AuthorizedTransport(transport: 'SecureTransport', tokens: 'TokenProvider') -> 'None'`


**undocumented — add a docstring**


### `CredentialVault(*args, **kwargs)`


Base class for protocol classes.


### `SecureTransport(base_url: 'str', *, verify: 'bool | str' = True, transport: 'httpx.BaseTransport | None' = None, timeout: 'httpx.Timeout | None' = None) -> 'None'`


**undocumented — add a docstring**


### `TokenProvider(*args, **kwargs)`


Base class for protocol classes.
