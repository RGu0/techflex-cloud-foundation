from uuid import uuid4

from pydantic import SecretStr, ValidationError
import pytest

from techflex_cloud_foundation.contracts.capture_grants import (
    CaptureCredential,
    CaptureGrant,
    CaptureGrantBatchRequest,
    CaptureGrantBatchResponse,
    MigrationPermitResponse,
    RetireCaptureGrantRequest,
    SessionAuthorization,
    UploadMigrationPermitRequest,
)


@pytest.mark.parametrize("count", [0, 51])
def test_grant_batch_rejects_out_of_range_count(count: int) -> None:
    with pytest.raises(ValidationError):
        CaptureGrantBatchRequest(count=count)


def test_grant_batch_accepts_fifty_and_response_redacts_grants() -> None:
    secret = "g" * 32
    grant = CaptureGrant(session_id=uuid4(), token=SecretStr(secret))
    response = CaptureGrantBatchResponse(grants=(grant,))
    assert CaptureGrantBatchRequest(count=50).count == 50
    assert response.grants == (grant,)
    assert secret not in repr(grant)
    assert secret not in repr(response)


def test_authorization_headers_are_exact_and_redacted_from_repr() -> None:
    secret = "x" * 32
    credential = CaptureCredential(session_id=uuid4(), kind="grant", token=SecretStr(secret))
    authorization = SessionAuthorization(**credential.model_dump(), manifest_sha256="a" * 64)
    assert authorization.headers() == {
        "X-Capture-Authorization": f"grant {secret}",
        "X-Expected-Manifest-SHA256": "a" * 64,
    }
    assert secret not in repr(credential)
    assert secret not in repr(authorization)


def test_migration_authorization_has_distinct_header_scheme() -> None:
    secret = "m" * 32
    authorization = SessionAuthorization(
        session_id=uuid4(), kind="migration_permit", token=SecretStr(secret),
        manifest_sha256="b" * 64,
    )
    assert authorization.headers()["X-Capture-Authorization"] == f"migration_permit {secret}"


@pytest.mark.parametrize("digest", ["A" * 64, "a" * 63, "z" * 64])
def test_authorization_rejects_invalid_manifest_digest(digest: str) -> None:
    with pytest.raises(ValidationError):
        SessionAuthorization(
            session_id=uuid4(), kind="grant", token=SecretStr("x" * 32),
            manifest_sha256=digest,
        )


@pytest.mark.parametrize("model", [CaptureGrant, CaptureCredential, MigrationPermitResponse])
def test_credentials_reject_short_tokens_without_leaking_them(model: type) -> None:
    secret = "short-secret"
    fields = {"session_id": uuid4(), "token": SecretStr(secret)}
    if model is CaptureCredential:
        fields["kind"] = "grant"
    with pytest.raises(ValidationError) as caught:
        model(**fields)
    assert secret not in str(caught.value)


def test_retirement_and_migration_request_preserve_review_fields() -> None:
    session_id = uuid4()
    retirement = RetireCaptureGrantRequest(session_id=session_id, reason="cancelled")
    request = UploadMigrationPermitRequest(
        tenant_id=uuid4(), account_id=uuid4(), license_id=uuid4(),
        installation_id=uuid4(), hardware_id="usb-serial-0123456789abcdef0123",
        session_id=session_id, request_sha256="a" * 64, manifest_sha256="b" * 64,
        final_subject_uuid=uuid4(), consent_record_id=uuid4(), consent_sha256="c" * 64,
        evidence_reference="evidence/ray-513/review-1", reason="LEGACY_VALID_SESSION_REVIEWED",
        identity_conflict=False, reconciliation_reference=None,
        local_valid_reviewed=True, immutable_manifest_reviewed=True,
        original_consent_reviewed=True, historical_authorization_reviewed=True,
    )
    assert retirement.session_id == request.session_id
    assert request.historical_authorization_reviewed is True


def test_migration_request_requires_nonempty_reason_and_valid_digest() -> None:
    fields = dict(
        tenant_id=uuid4(), account_id=uuid4(), license_id=uuid4(),
        installation_id=uuid4(), hardware_id="usb-serial-0123456789abcdef0123",
        session_id=uuid4(), request_sha256="A" * 64, manifest_sha256="b" * 64,
        final_subject_uuid=uuid4(), consent_record_id=uuid4(), consent_sha256="c" * 64,
        evidence_reference="audit/513", reason="", identity_conflict=False,
        reconciliation_reference=None, local_valid_reviewed=True,
        immutable_manifest_reviewed=True, original_consent_reviewed=True,
        historical_authorization_reviewed=True,
    )
    with pytest.raises(ValidationError):
        UploadMigrationPermitRequest(**fields)
