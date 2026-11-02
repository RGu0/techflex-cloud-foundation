from __future__ import annotations

from typing import Any


class PlatformError(Exception):
    code = "E-CLD-500"
    http_status = 500
    retryable = False
    action = "CONTACT_SUPPORT"

    def __init__(self, message: str, **details: Any) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class AuthenticationError(PlatformError):
    code = "E-AUT-401"
    http_status = 401
    action = "REFRESH_CREDENTIAL"


class ActivationCodeInvalid(AuthenticationError):
    code = "E-ACT-401"
    action = "REQUEST_ACTIVATION_CODE"


# RAY-656 terminal credential failures. Each condition has its own code so a
# client never infers revocation from a generic 401; network failures carry no
# envelope at all.
class TerminalCredentialsRejected(AuthenticationError):
    code = "E-TRM-401-CREDENTIALS"
    action = "VERIFY_CREDENTIALS"


class TerminalRevoked(AuthenticationError):
    code = "E-TRM-401-REVOKED"
    action = "CONTACT_ADMINISTRATOR"


class TerminalRefreshReplayed(AuthenticationError):
    code = "E-TRM-401-REFRESH-REPLAYED"
    action = "REACTIVATE_TERMINAL"


class TerminalRefreshExpired(AuthenticationError):
    code = "E-TRM-401-REFRESH-EXPIRED"
    action = "REACTIVATE_TERMINAL"


class TerminalRefreshInvalid(AuthenticationError):
    code = "E-TRM-401-REFRESH-INVALID"
    action = "REACTIVATE_TERMINAL"


class TerminalLicenseInactive(PlatformError):
    code = "E-TRM-403-LICENSE-INACTIVE"
    http_status = 403
    action = "CONTACT_ADMINISTRATOR"


class TerminalSeatLimitReached(PlatformError):
    code = "E-TRM-409-SEAT-LIMIT"
    http_status = 409
    action = "FREE_TERMINAL_SEAT"


class TerminalInstallationConflict(PlatformError):
    code = "E-TRM-409-INSTALLATION-CONFLICT"
    http_status = 409
    action = "REGENERATE_INSTALLATION_ID"


# RAY-778 institutional insole inventory. The two registration conflicts
# carry the existing pair in ``details.existing`` so the client can show it.
class InsoleIdentityRegistered(PlatformError):
    code = "E-INV-409-IDENTITY-REGISTERED"
    http_status = 409
    action = "SHOW_EXISTING_INSOLE"


class InsoleNumberTaken(PlatformError):
    code = "E-INV-409-NUMBER-TAKEN"
    http_status = 409
    action = "SHOW_EXISTING_INSOLE"


class InsoleRetired(PlatformError):
    code = "E-INV-409-RETIRED"
    http_status = 409
    action = "REFRESH_INVENTORY"


class InsoleReadingInFuture(PlatformError):
    code = "E-INV-422-READING-IN-FUTURE"
    http_status = 422
    action = "CHECK_TERMINAL_CLOCK"


class InsoleCursorInvalid(PlatformError):
    code = "E-INV-400-CURSOR-INVALID"
    http_status = 400
    action = "RESTART_FULL_SYNC"


# RAY-907 institutional subject sync. The revision conflict carries the
# current record in ``details.current``; the number conflict names the owner
# with ``details.subject_uuid`` and ``details.external_id_masked``.
class SubjectCursorInvalid(PlatformError):
    code = "E-SUB-400-CURSOR-INVALID"
    http_status = 400
    action = "RESTART_FULL_SYNC"


class SubjectRevisionConflict(PlatformError):
    code = "E-SUB-409-REVISION-CONFLICT"
    http_status = 409
    action = "MERGE_AND_RETRY"


class SubjectNumberTaken(PlatformError):
    code = "E-SUB-409-NUMBER-TAKEN"
    http_status = 409
    action = "SHOW_EXISTING_SUBJECT"


class SubjectNotEditable(PlatformError):
    code = "E-SUB-409-NOT-EDITABLE"
    http_status = 409
    action = "REFRESH_SUBJECTS"


class SubjectUnknownTag(PlatformError):
    code = "E-SUB-422-UNKNOWN-TAG"
    http_status = 422
    action = "REFRESH_TAGS"


# RAY-802 terminal diagnostic packages. A rejection names only the line and a
# fixed reason in ``details``; the content itself is never echoed.
class DiagnosticTooLarge(PlatformError):
    code = "E-DIA-413-TOO-LARGE"
    http_status = 413
    action = "TRIM_DIAGNOSTICS"


class DiagnosticDigestMismatch(PlatformError):
    code = "E-DIA-422-DIGEST-MISMATCH"
    http_status = 422
    # The body changed in transit; the same package may be sent again.
    retryable = True
    action = "RETRY_UPLOAD"


class DiagnosticContentRejected(PlatformError):
    code = "E-DIA-422-CONTENT-REJECTED"
    http_status = 422
    action = "UPDATE_CLIENT"


class TenantAccessDenied(PlatformError):
    code = "E-AUT-403"
    http_status = 403
    action = "CONTACT_ADMINISTRATOR"


class SessionHeldForReportCopy(PlatformError):
    code = "E-RPT-423"
    http_status = 423
    action = "RETRY_AFTER_HOLD_RELEASE"


class ResourceNotFound(PlatformError):
    code = "E-API-404"
    http_status = 404
    action = "VERIFY_REFERENCE"


class RequestContractError(PlatformError):
    code = "E-API-400"
    http_status = 400
    action = "FIX_REQUEST"


class IdempotencyConflict(PlatformError):
    code = "E-API-409"
    http_status = 409
    action = "EXPORT_DIAGNOSTIC"


class SegmentDigestConflict(PlatformError):
    code = "E-SYN-409"
    http_status = 409
    action = "EXPORT_DIAGNOSTIC"


class ManifestConflict(SegmentDigestConflict):
    pass


class DigestMismatch(PlatformError):
    code = "E-CLD-422"
    http_status = 422
    action = "RESEAL_SEGMENT"


class SizeMismatch(DigestMismatch):
    pass


class SchemaUnsupported(PlatformError):
    code = "E-CLD-422"
    http_status = 422
    action = "UPDATE_CLIENT"


class ManifestIncomplete(PlatformError):
    code = "E-CLD-422"
    http_status = 422
    action = "UPLOAD_MISSING_SEGMENTS"


class QualityGateRejected(PlatformError):
    code = "E-CLD-422"
    http_status = 422
    action = "REPEAT_SCREENING"


class RepositoryUnavailable(PlatformError):
    code = "E-CLD-503"
    http_status = 503
    retryable = True
    action = "RETRY_LATER"
