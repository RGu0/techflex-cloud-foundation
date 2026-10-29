import base64
import binascii
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import socket
from typing import Annotated, Any, cast
from uuid import UUID, uuid4

import asyncpg  # type: ignore[import-untyped]
from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

from techflex_cloud_foundation.contracts.access_control import (
    ActivateAccountRequest,
    HardwareLeaseRequest,
    InventoryActivationRequest,
    LicenseControlRequest,
    LoginRequest,
    LogoutRequest,
    PlatformLoginRequest,
    ProvisionTenantRequest,
    RefreshRequest,
    SensitiveAccessGrantRequest,
)
from techflex_cloud_foundation.contracts.capture_grants import (
    CaptureGrantBatchRequest,
    RetireCaptureGrantRequest,
    SessionAuthorization,
    UploadMigrationPermitRequest,
)
from techflex_cloud_foundation.contracts.client_sync import decode_segment_metadata
from techflex_cloud_foundation.contracts.cloud import (
    AnySessionManifest,
    ConsentCreateRequest,
    ConsentRevokeRequest,
    EnrollmentRequest,
    HeartbeatRequest,
    InsoleSessionManifest,
    SessionCreateRequest,
    SessionManifest,
    SubjectCreateRequest,
    SubjectResolveRequest,
    parse_session_manifest,
)
from techflex_cloud_foundation.contracts.identity_recovery import (
    RecoveryCaseCreateRequest,
    RecoveryComparisonRequest,
    RecoveryRegistrationRequest,
)
from techflex_cloud_foundation.contracts.insole_inventory import (
    INSOLE_PAGE_MAX_LIMIT,
    InsoleRegistrationRequest,
    InsoleReportRequest,
)
from techflex_cloud_foundation.contracts.operations import (
    ActivationCodeIssueRequest,
    DataAccessRequest,
    DeviceRegistrationRequest,
    LicenseIssueRequest,
    LicenseRenewRequest,
    LicenseRevokeRequest,
    SiteCreateRequest,
    TerminalStatusChangeRequest,
    UpgradePolicyRequest,
    UpgradePolicyStatusRequest,
)
from techflex_cloud_foundation.contracts.terminal_access import (
    TerminalActivationRequest,
    TerminalRefreshRequest,
    TerminalRenameRequest,
)
from techflex_cloud_foundation.contracts.validation_telemetry import (
    DeviceValidationTelemetryBatchRequest,
)
from techflex_cloud_foundation.platform_errors import (
    AuthenticationError,
    PlatformError,
    RepositoryUnavailable,
    RequestContractError,
    ResourceNotFound,
    TenantAccessDenied,
)
from techflex_cloud_foundation.server.access_auth import (
    PlatformAccessContext,
    PlatformAccessTokenIssuer,
    TenantAccessContext,
    TenantAccessTokenIssuer,
    TerminalAccessContext,
    TerminalAccessTokenIssuer,
)
from techflex_cloud_foundation.server.auth import TerminalContext, TerminalTokenIssuer
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.operations_auth import OperationsTokenIssuer
from techflex_cloud_foundation.server.principal import (
    IngestionPrincipal,
    legacy_terminal_principal,
    tenant_ingestion_principal,
)
from techflex_cloud_foundation.server.report_copy.models import LocalBasicCopyRequest
from techflex_cloud_foundation.server.session_hold.models import (
    HoldApplyBody,
    HoldApplyRequest,
    HoldDispositionBody,
    HoldDispositionRequest,
    HoldReleaseBody,
    HoldReleaseRequest,
)


@dataclass(frozen=True, slots=True)
class ServiceContainer:
    ingestion: IngestionService | None = None
    token_issuer: TerminalTokenIssuer | None = None
    subjects: Any = None
    devices: Any = None
    heartbeats: Any = None
    operations: Any = None
    operations_tokens: OperationsTokenIssuer | None = None
    tenant_access: Any = None
    tenant_tokens: TenantAccessTokenIssuer | None = None
    hardware_leases: Any = None
    capture_grants: Any = None
    platform_identities: Any = None
    platform_access: Any = None
    platform_tokens: PlatformAccessTokenIssuer | None = None
    platform_sensitive: Any = None
    platform_reports: Any = None
    platform_subjects: Any = None
    validation_telemetry: Any = None
    identity_recovery: Any = None
    session_holds: Any = None
    report_copies: Any = None
    terminal_access: Any = None
    terminal_tokens: TerminalAccessTokenIssuer | None = None
    insole_inventory: Any = None


# RAY-834: database failures a retry can cure. Anything else unhandled is a
# server defect the client cannot fix by retrying.
_TRANSIENT_ERRORS = (
    asyncpg.PostgresConnectionError,
    asyncpg.TooManyConnectionsError,
    # Restart, failover, startup and cancel (57xxx).
    asyncpg.OperatorInterventionError,
    asyncpg.DeadlockDetectedError,
    asyncpg.SerializationError,
    ConnectionError,
    TimeoutError,
    socket.gaierror,
)


def _unhandled_error(exc: Exception) -> PlatformError:
    if isinstance(exc, _TRANSIENT_ERRORS):
        return RepositoryUnavailable("服务暂不可用，请稍后重试")
    return PlatformError("服务器内部错误")


def _meta(request: Request) -> dict[str, str]:
    return {
        "request_id": str(request.state.request_id),
        "correlation_id": str(request.state.correlation_id),
        "server_time": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }


def _data_response(request: Request, data: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=jsonable_encoder({"data": data, "meta": _meta(request)}),
        headers={"X-Correlation-ID": str(request.state.correlation_id)},
    )


_MANIFEST_MODELS = (SessionManifest, InsoleSessionManifest)


async def _session_manifest_body(request: Request) -> AnySessionManifest:
    """Validate the complete body against the model its schema_version names."""
    raw = await request.body()
    # FastAPI's own rule: only application/json or a +json subtype is JSON.
    media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if raw and not (media_type == "application/json" or (
        media_type.startswith("application/") and media_type.endswith("+json")
    )):
        raise RequestValidationError(
            [{"type": "model_attributes_type", "loc": ("body",),
              "msg": "Input should be a valid dictionary or object", "input": None}]
        )
    if not raw:
        raise RequestValidationError(
            [{"type": "missing", "loc": ("body",), "msg": "Field required", "input": None}]
        )
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        # FastAPI reports the decode position after "body".
        position = (exc.pos,) if isinstance(exc, json.JSONDecodeError) else ()
        raise RequestValidationError(
            [{"type": "json_invalid", "loc": ("body", *position), "msg": "JSON decode error",
              "input": {}, "ctx": {"error": str(exc)}}]
        ) from exc
    try:
        return parse_session_manifest(value)
    except ValidationError as exc:
        raise RequestValidationError(
            [{**error, "loc": ("body", *error["loc"])} for error in exc.errors()]
        ) from exc


def _with_manifest_schemas(app: FastAPI) -> None:
    """The complete body is parsed by hand, so register its two models."""
    default_openapi = app.openapi

    def openapi() -> dict[str, Any]:
        if app.openapi_schema is None:
            document = default_openapi()
            schemas = document.setdefault("components", {}).setdefault("schemas", {})
            for model in _MANIFEST_MODELS:
                schema = model.model_json_schema(ref_template="#/components/schemas/{model}")
                schemas.update(schema.pop("$defs", {}))
                schemas[model.__name__] = schema
        return cast(dict[str, Any], app.openapi_schema)

    app.openapi = openapi  # type: ignore[method-assign]


def create_app(container: ServiceContainer) -> FastAPI:
    app = FastAPI(
        title="FeetForcePlate Cloud API",
        version="1.0.0",
        description="Institutional screening ingestion API; it does not provide disease diagnosis.",
    )
    app.state.services = container

    @app.middleware("http")
    async def correlation_context(request: Request, call_next: Any) -> Any:
        request.state.request_id = uuid4()
        raw_correlation = request.headers.get("X-Correlation-ID")
        try:
            request.state.correlation_id = UUID(raw_correlation) if raw_correlation else uuid4()
        except ValueError:
            request.state.correlation_id = uuid4()
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "code": "E-API-400",
                        "message": "X-Correlation-ID 必须是 UUID",
                        "retryable": False,
                        "action": "FIX_REQUEST",
                        "details": {},
                    },
                    "meta": _meta(request),
                },
                headers={"X-Correlation-ID": str(request.state.correlation_id)},
            )
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = str(request.state.correlation_id)
        if request.url.path.startswith("/v1/reports") or request.url.path.endswith("/basic-report-copy"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(PlatformError)
    async def platform_error_handler(request: Request, exc: PlatformError) -> Any:
        allowed_details = {
            "session_id",
            "segment_index",
            "schema_version",
            "session_schema",
            "segment_schema",
            "expected",
            "actual",
            "missing_or_mismatched",
            "extra",
            "scope",
            "terminal_id",
            "device_id",
            "subject_uuid",
            "validity_status",
            "object_key",
            "existing",
        }
        details = {key: value for key, value in exc.details.items() if key in allowed_details}
        return JSONResponse(
            status_code=exc.http_status,
            content=jsonable_encoder(
                {
                    "error": {
                        "code": exc.code,
                        "message": exc.message,
                        "retryable": exc.retryable,
                        "action": exc.action,
                        "details": details,
                    },
                    "meta": _meta(request),
                }
            ),
        )

    # RAY-834: an unhandled exception gets the same envelope instead of a bare
    # 500. Starlette re-raises it after this response, so the traceback is still
    # logged; nothing from the exception reaches the client.
    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> Any:
        if not hasattr(request.state, "request_id"):
            request.state.request_id = uuid4()
            request.state.correlation_id = uuid4()
        response = await platform_error_handler(request, _unhandled_error(exc))
        response.headers["X-Correlation-ID"] = str(request.state.correlation_id)
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> Any:
        safe_fields = [".".join(str(part) for part in error["loc"]) for error in exc.errors()]
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "E-API-422",
                    "message": "请求字段不符合版本化契约",
                    "retryable": False,
                    "action": "FIX_REQUEST",
                    "details": {"fields": safe_fields},
                },
                "meta": _meta(request),
            },
        )

    def terminal_context(
        authorization: Annotated[str, Header(alias="Authorization")],
        terminal_header_id: Annotated[UUID, Header(alias="X-Terminal-ID")],
    ) -> TerminalContext:
        if container.token_issuer is None:
            raise RepositoryUnavailable("终端身份服务暂不可用")
        scheme, separator, token = authorization.partition(" ")
        if separator != " " or scheme.lower() != "bearer" or not token:
            raise AuthenticationError("缺少有效终端 Bearer 凭据")
        context = container.token_issuer.verify(token)
        if context.terminal_id != terminal_header_id:
            raise TenantAccessDenied(
                "X-Terminal-ID 与终端凭据不一致",
                terminal_id=str(terminal_header_id),
            )
        return context

    def heartbeat_context(
        authorization: Annotated[str, Header(alias="Authorization")],
        terminal_header_id: Annotated[UUID, Header(alias="X-Terminal-ID")],
    ) -> IngestionPrincipal | TerminalContext:
        scheme, separator, token = authorization.partition(" ")
        if separator != " " or scheme.lower() != "bearer" or not token:
            raise AuthenticationError("缺少有效终端 Bearer 凭据")
        context: IngestionPrincipal | TerminalContext
        if container.tenant_tokens is not None:
            context = tenant_ingestion_principal(container.tenant_tokens.verify(token))
        elif container.token_issuer is not None:
            context = container.token_issuer.verify(token)
        else:
            raise RepositoryUnavailable("终端身份服务暂不可用")
        if context.terminal_id != terminal_header_id:
            raise TenantAccessDenied(
                "X-Terminal-ID 与终端凭据不一致",
                terminal_id=str(terminal_header_id),
            )
        return context

    HeartbeatDependency = Annotated[
        IngestionPrincipal | TerminalContext,
        Depends(heartbeat_context),
    ]

    def operations_context(
        authorization: Annotated[str, Header(alias="Authorization")],
    ) -> Any:
        if container.operations_tokens is None:
            raise RepositoryUnavailable("运营身份服务暂不可用")
        scheme, separator, token = authorization.partition(" ")
        if separator != " " or scheme.lower() != "bearer" or not token:
            raise AuthenticationError("缺少有效运营 Bearer 凭据")
        return container.operations_tokens.verify(token)

    OperationsDependency = Annotated[object, Depends(operations_context)]

    def tenant_context(
        authorization: Annotated[str, Header(alias="Authorization")],
    ) -> TenantAccessContext:
        if container.tenant_tokens is None:
            raise RepositoryUnavailable("机构身份服务暂不可用")
        scheme, separator, token = authorization.partition(" ")
        if separator != " " or scheme.lower() != "bearer" or not token:
            raise AuthenticationError("缺少有效机构 Bearer 凭据")
        return container.tenant_tokens.verify(token)

    TenantAccessDependency = Annotated[TenantAccessContext, Depends(tenant_context)]

    def terminal_access_context(
        authorization: Annotated[str, Header(alias="Authorization")],
    ) -> TerminalAccessContext:
        if container.terminal_tokens is None:
            raise RepositoryUnavailable("终端身份服务暂不可用")
        scheme, separator, token = authorization.partition(" ")
        if separator != " " or scheme.lower() != "bearer" or not token:
            raise AuthenticationError("缺少有效终端 Bearer 凭据")
        return container.terminal_tokens.verify(token)

    TerminalAccessDependency = Annotated[
        TerminalAccessContext, Depends(terminal_access_context)
    ]

    def data_context(
        authorization: Annotated[str, Header(alias="Authorization")],
        terminal_header_id: Annotated[
            UUID | None,
            Header(alias="X-Terminal-ID"),
        ] = None,
    ) -> IngestionPrincipal:
        scheme, separator, token = authorization.partition(" ")
        if separator != " " or scheme.lower() != "bearer" or not token:
            raise AuthenticationError("缺少有效数据 Bearer 凭据")
        if container.tenant_tokens is not None:
            return tenant_ingestion_principal(container.tenant_tokens.verify(token))
        if container.token_issuer is None:
            raise RepositoryUnavailable("数据身份服务暂不可用")
        if terminal_header_id is None:
            raise AuthenticationError("缺少 X-Terminal-ID")
        terminal = container.token_issuer.verify(token)
        if terminal.terminal_id != terminal_header_id:
            raise TenantAccessDenied(
                "X-Terminal-ID 与终端凭据不一致",
                terminal_id=str(terminal_header_id),
            )
        return legacy_terminal_principal(terminal)

    DataDependency = Annotated[IngestionPrincipal, Depends(data_context)]

    async def terminal_data_context(
        authorization: Annotated[str, Header(alias="Authorization")],
        terminal_header_id: Annotated[
            UUID | None,
            Header(alias="X-Terminal-ID"),
        ] = None,
    ) -> IngestionPrincipal:
        # RAY-728 D1: the subject, consent and session routes also accept an
        # activated terminal's access token. Hardware-bound tenant and legacy
        # terminal tokens keep their existing path unchanged.
        try:
            return data_context(authorization, terminal_header_id)
        except (AuthenticationError, RepositoryUnavailable) as rejected:
            if container.terminal_access is None or container.terminal_tokens is None:
                raise
            scheme, separator, token = authorization.partition(" ")
            if separator != " " or scheme.lower() != "bearer" or not token:
                raise
            try:
                terminal = container.terminal_tokens.verify(token)
            except AuthenticationError:
                raise rejected from None
        if (
            terminal_header_id is not None
            and terminal_header_id != terminal.client_installation_id
        ):
            raise TenantAccessDenied(
                "X-Terminal-ID 与终端凭据不一致",
                terminal_id=str(terminal_header_id),
            )
        return cast(IngestionPrincipal, await container.terminal_access.data_principal(terminal))

    TerminalDataDependency = Annotated[
        IngestionPrincipal, Depends(terminal_data_context)
    ]

    async def platform_context(
        authorization: Annotated[str, Header(alias="Authorization")],
    ) -> PlatformAccessContext:
        if (
            container.platform_identities is None
            or container.platform_tokens is None
        ):
            raise RepositoryUnavailable("平台身份服务暂不可用")
        scheme, separator, token = authorization.partition(" ")
        if separator != " " or scheme.lower() != "bearer" or not token:
            raise AuthenticationError("缺少有效平台 Bearer 凭据")
        return cast(PlatformAccessContext, await container.platform_identities.verify_access_token(token))

    PlatformAccessDependency = Annotated[PlatformAccessContext, Depends(platform_context)]

    async def migration_platform_context(
        authorization: Annotated[str, Header(alias="Authorization")],
    ) -> PlatformAccessContext:
        try:
            return await platform_context(authorization)
        except AuthenticationError:
            raise TenantAccessDenied("platform owner approval required") from None

    MigrationPlatformDependency = Annotated[PlatformAccessContext, Depends(migration_platform_context)]

    def source_fingerprint(request: Request) -> bytes:
        host = request.client.host if request.client is not None else "unknown"
        return hashlib.sha256(f"tenant|{host}".encode()).digest()

    def _platform_source_fingerprint(request: Request) -> bytes:
        host = request.client.host if request.client is not None else "unknown"
        return hashlib.sha256(f"platform|{host}".encode()).digest()

    def operations_service() -> Any:
        if container.operations is None:
            raise RepositoryUnavailable("运营控制面暂不可用")
        return container.operations

    if container.tenant_access is not None and container.tenant_tokens is not None:

        @app.post("/v1/access/activate")
        async def access_activate(request: Request, body: ActivateAccountRequest) -> Any:
            result = await container.tenant_access.activate(
                body,
                source_fingerprint=source_fingerprint(request),
            )
            return _data_response(request, result, 201)

        @app.post("/v1/access/inventory-activate")
        async def access_inventory_activate(
            request: Request, body: InventoryActivationRequest
        ) -> Any:
            result = await container.tenant_access.activate_inventory(
                body,
                source_fingerprint=source_fingerprint(request),
            )
            return _data_response(request, result, 201)

        @app.post("/v1/access/login")
        async def access_login(request: Request, body: LoginRequest) -> Any:
            result = await container.tenant_access.login(
                body,
                source_fingerprint=source_fingerprint(request),
            )
            return _data_response(request, result)

        @app.post("/v1/access/refresh")
        async def access_refresh(request: Request, body: RefreshRequest) -> Any:
            result = await container.tenant_access.refresh(body)
            return _data_response(request, result)

        @app.post("/v1/access/logout")
        async def access_logout(request: Request, body: LogoutRequest) -> Any:
            await container.tenant_access.logout(body)
            return _data_response(request, {"logged_out": True})

        @app.get("/v1/access/license")
        async def access_license(
            request: Request,
            context: TenantAccessDependency,
        ) -> Any:
            result = await container.tenant_access.current_license(context)
            return _data_response(request, result)

    if container.terminal_access is not None and container.terminal_tokens is not None:

        @app.post("/v1/access/terminal-activate")
        async def terminal_activate(request: Request, body: TerminalActivationRequest) -> Any:
            result = await container.terminal_access.activate(
                body,
                source_fingerprint=source_fingerprint(request),
            )
            return _data_response(request, result, 201)

        @app.post("/v1/access/terminal-refresh")
        async def terminal_refresh(request: Request, body: TerminalRefreshRequest) -> Any:
            result = await container.terminal_access.refresh(body)
            return _data_response(request, result)

        @app.get("/v1/access/terminals")
        async def terminal_list(request: Request, context: TerminalAccessDependency) -> Any:
            result = await container.terminal_access.list_terminals(context)
            return _data_response(request, result)

        @app.patch("/v1/access/terminals/{client_installation_id}")
        async def terminal_rename(
            request: Request,
            client_installation_id: UUID,
            body: TerminalRenameRequest,
            context: TerminalAccessDependency,
        ) -> Any:
            result = await container.terminal_access.rename_terminal(
                context, client_installation_id, body
            )
            return _data_response(request, result)

        @app.post("/v1/access/terminals/{client_installation_id}/revoke")
        async def terminal_revoke(
            request: Request,
            client_installation_id: UUID,
            context: TerminalAccessDependency,
        ) -> Any:
            result = await container.terminal_access.revoke_terminal(
                context, client_installation_id
            )
            return _data_response(request, result)

    if container.insole_inventory is not None and container.terminal_tokens is not None:

        # RAY-778: institutional insole inventory, terminal credentials only.
        @app.post("/v1/inventory/insoles")
        async def insole_register(
            request: Request,
            body: InsoleRegistrationRequest,
            context: TerminalAccessDependency,
            idempotency_key: Annotated[
                str, Header(alias="Idempotency-Key", min_length=1, max_length=256)
            ],
        ) -> Any:
            result, created = await container.insole_inventory.register(
                context, body, idempotency_key
            )
            return _data_response(request, result, 201 if created else 200)

        @app.get("/v1/inventory/insoles")
        async def insole_changes(
            request: Request,
            context: TerminalAccessDependency,
            cursor: Annotated[str | None, Query(max_length=128)] = None,
            limit: Annotated[int | None, Query(ge=1, le=INSOLE_PAGE_MAX_LIMIT)] = None,
        ) -> Any:
            result = await container.insole_inventory.changes(
                context, cursor=cursor, limit=limit
            )
            return _data_response(request, result)

        @app.post("/v1/inventory/insoles/{insole_id}/reports")
        async def insole_report(
            request: Request,
            insole_id: UUID,
            body: InsoleReportRequest,
            context: TerminalAccessDependency,
        ) -> Any:
            result = await container.insole_inventory.report(context, insole_id, body)
            return _data_response(request, result)

        @app.post("/v1/inventory/insoles/{insole_id}/retire")
        async def insole_retire(
            request: Request,
            insole_id: UUID,
            context: TerminalAccessDependency,
        ) -> Any:
            result = await container.insole_inventory.retire(context, insole_id)
            return _data_response(request, result)

    if container.validation_telemetry is not None and container.tenant_tokens is not None:

        @app.post("/v1/telemetry/device-validation")
        async def upload_device_validation_telemetry(
            request: Request,
            body: DeviceValidationTelemetryBatchRequest,
            context: TenantAccessDependency,
        ) -> Any:
            result = container.validation_telemetry.ingest(context, body)
            return _data_response(request, result, 202)

    if container.hardware_leases is not None and container.tenant_tokens is not None:

        @app.post("/v1/access/hardware-lease")
        async def acquire_hardware_lease(
            request: Request,
            body: HardwareLeaseRequest,
            context: TenantAccessDependency,
        ) -> Any:
            result = await container.hardware_leases.acquire(context, body)
            return _data_response(request, result, 201)

        @app.put("/v1/access/hardware-lease/{lease_id}")
        async def renew_hardware_lease(
            request: Request,
            lease_id: UUID,
            context: TenantAccessDependency,
        ) -> Any:
            result = await container.hardware_leases.renew(context, lease_id)
            return _data_response(request, result)

        @app.delete("/v1/access/hardware-lease/{lease_id}")
        async def release_hardware_lease(
            request: Request,
            lease_id: UUID,
            context: TenantAccessDependency,
        ) -> Any:
            await container.hardware_leases.release(context, lease_id)
            return _data_response(request, {"released": True})

    if container.platform_identities is not None:

        @app.post("/v1/platform/login")
        async def platform_login(request: Request, body: PlatformLoginRequest) -> Any:
            result = await container.platform_identities.login(
                body,
                source_fingerprint=_platform_source_fingerprint(request),
            )
            return _data_response(request, result)

    if container.platform_access is not None and container.platform_tokens is not None:

        @app.post("/v1/platform/tenants")
        async def platform_create_tenant(
            request: Request,
            body: ProvisionTenantRequest,
            context: PlatformAccessDependency,
        ) -> Any:
            result = await container.platform_access.provision_tenant(context, body)
            return _data_response(request, result, 201)

        @app.post("/v1/platform/tenants/{tenant_id}/licenses")
        async def platform_add_tenant_license(
            request: Request,
            tenant_id: UUID,
            body: ProvisionTenantRequest,
            context: PlatformAccessDependency,
        ) -> Any:
            result = await container.platform_access.add_tenant_access_group(
                context,
                tenant_id,
                body,
            )
            return _data_response(request, result, 201)

        @app.patch("/v1/platform/licenses/{license_id}")
        async def platform_control_license(
            request: Request,
            license_id: UUID,
            body: LicenseControlRequest,
            context: PlatformAccessDependency,
        ) -> Any:
            result = await container.platform_access.control_license(
                context,
                license_id,
                body,
            )
            return _data_response(request, result)

    if container.platform_sensitive is not None and container.platform_tokens is not None:

        @app.get("/v1/platform/tenants")
        async def platform_list_tenants(
            request: Request,
            context: PlatformAccessDependency,
        ) -> Any:
            result = await container.platform_sensitive.list_tenants(context)
            return _data_response(request, result)

        @app.post("/v1/platform/sensitive-access-grants")
        async def platform_issue_sensitive_grant(
            request: Request,
            body: SensitiveAccessGrantRequest,
            context: PlatformAccessDependency,
        ) -> Any:
            result = await container.platform_sensitive.issue_grant(context, body)
            return _data_response(request, result, 201)

    if (
        container.platform_reports is not None
        and container.platform_tokens is not None
    ):

        @app.get("/v1/platform/tenants/{tenant_id}/reports")
        async def platform_list_reports(
            request: Request,
            tenant_id: UUID,
            context: PlatformAccessDependency,
        ) -> Any:
            if container.session_holds is None:
                raise RepositoryUnavailable("report hold check unavailable")
            binding = getattr(container.platform_reports, "session_for_report", None)
            if binding is None:
                raise RepositoryUnavailable("report session binding unavailable")
            result = await container.platform_reports.list_masked_reports(
                context,
                tenant_id,
            )
            visible = []
            for row in result:
                if getattr(row, "tenant_id", None) != tenant_id:
                    raise RepositoryUnavailable("report tenant binding unavailable")
                session_id = await binding(context, tenant_id, row.report_id)
                if not isinstance(session_id, UUID):
                    raise RepositoryUnavailable("report session binding unavailable")
                hold = await container.session_holds.status(context, tenant_id, session_id)
                if not hold.held:
                    visible.append(row)
            return _data_response(request, visible)

    if container.session_holds is not None and container.platform_tokens is not None:

        @app.post("/v1/platform/tenants/{tenant_id}/sessions/{session_id}/hold")
        async def platform_apply_session_hold(
            request: Request,
            tenant_id: UUID,
            session_id: UUID,
            body: HoldApplyBody,
            context: PlatformAccessDependency,
            idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
        ) -> Any:
            result = await container.session_holds.apply(
                context,
                HoldApplyRequest(
                    tenant_id=tenant_id,
                    session_id=session_id,
                    ticket_reference=body.ticket_reference,
                    reason_code=body.reason_code,
                ),
                idempotency_key,
            )
            return _data_response(request, result, 201)

        @app.get("/v1/platform/tenants/{tenant_id}/sessions/{session_id}/hold")
        async def platform_session_hold_status(
            request: Request,
            tenant_id: UUID,
            session_id: UUID,
            context: PlatformAccessDependency,
        ) -> Any:
            result = await container.session_holds.status(context, tenant_id, session_id)
            return _data_response(request, result)

        @app.post("/v1/platform/tenants/{tenant_id}/sessions/{session_id}/hold/disposition")
        async def platform_dispose_session_hold(
            request: Request,
            tenant_id: UUID,
            session_id: UUID,
            body: HoldDispositionBody,
            context: PlatformAccessDependency,
            idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
        ) -> Any:
            result = await container.session_holds.dispose(
                context,
                HoldDispositionRequest(
                    tenant_id=tenant_id,
                    session_id=session_id,
                    **body.model_dump(),
                ),
                idempotency_key,
            )
            return _data_response(request, result, 201)

        @app.post("/v1/platform/tenants/{tenant_id}/sessions/{session_id}/hold/release")
        async def platform_release_session_hold(
            request: Request,
            tenant_id: UUID,
            session_id: UUID,
            body: HoldReleaseBody,
            context: PlatformAccessDependency,
            idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
        ) -> Any:
            result = await container.session_holds.release(
                context,
                HoldReleaseRequest(
                    tenant_id=tenant_id,
                    session_id=session_id,
                    **body.model_dump(),
                ),
                idempotency_key,
            )
            return _data_response(request, result)

    if (
        container.platform_subjects is not None
        and container.platform_sensitive is not None
        and container.platform_tokens is not None
    ):

        @app.get("/v1/platform/tenants/{tenant_id}/subjects/{subject_id}/identity")
        async def platform_read_sensitive_identity(
            request: Request,
            tenant_id: UUID,
            subject_id: UUID,
            grant_id: UUID,
            context: PlatformAccessDependency,
        ) -> Any:
            result = await container.platform_sensitive.read_identity(
                context,
                grant_id=grant_id,
                tenant_id=tenant_id,
                subject_id=subject_id,
                identity_loader=lambda: container.platform_subjects.read_identity(
                    tenant_id,
                    subject_id,
                ),
            )
            return _data_response(request, result)

    @app.post("/v1/operations/sites")
    async def operations_create_site(
        request: Request,
        body: SiteCreateRequest,
        context: OperationsDependency,
    ) -> Any:
        result = await operations_service().create_site(context, body)
        return _data_response(request, result, 201)

    @app.post("/v1/operations/devices")
    async def operations_register_device(
        request: Request,
        body: DeviceRegistrationRequest,
        context: OperationsDependency,
    ) -> Any:
        result = await operations_service().register_device(context, body)
        return _data_response(request, result, 201)

    @app.post("/v1/operations/terminals/{terminal_id}/devices/{device_id}")
    async def operations_bind_device(
        request: Request,
        terminal_id: UUID,
        device_id: UUID,
        context: OperationsDependency,
    ) -> Any:
        result = await operations_service().bind_device(context, terminal_id, device_id)
        return _data_response(request, result, 201)

    @app.post("/v1/operations/terminals/{terminal_id}/status")
    async def operations_set_terminal_status(
        request: Request,
        terminal_id: UUID,
        body: TerminalStatusChangeRequest,
        context: OperationsDependency,
    ) -> Any:
        await operations_service().set_terminal_status(context, terminal_id, body.status)
        return _data_response(
            request,
            {"terminal_id": terminal_id, "status": body.status},
        )

    @app.post("/v1/operations/activation-codes")
    async def operations_issue_activation_code(
        request: Request,
        body: ActivationCodeIssueRequest,
        context: OperationsDependency,
    ) -> Any:
        result = await operations_service().issue_activation_code(
            context,
            site_id=body.site_id,
            device_id=body.device_id,
            expires_at=body.expires_at,
        )
        return _data_response(request, result, 201)

    @app.post("/v1/operations/licenses")
    async def operations_issue_license(
        request: Request,
        body: LicenseIssueRequest,
        context: OperationsDependency,
    ) -> Any:
        result = await operations_service().issue_license(context, body)
        return _data_response(request, result, 201)

    @app.post("/v1/operations/licenses/{license_id}/renew")
    async def operations_renew_license(
        request: Request,
        license_id: UUID,
        body: LicenseRenewRequest,
        context: OperationsDependency,
    ) -> Any:
        result = await operations_service().renew_license(context, license_id, body)
        return _data_response(request, result, 201)

    @app.post("/v1/operations/licenses/{license_id}/revoke")
    async def operations_revoke_license(
        request: Request,
        license_id: UUID,
        body: LicenseRevokeRequest,
        context: OperationsDependency,
    ) -> Any:
        result = await operations_service().revoke_license(
            context,
            license_id,
            reason_code=body.reason_code,
        )
        return _data_response(request, result, 201)

    @app.get("/v1/operations/terminals/{terminal_id}/health")
    async def operations_terminal_health(
        request: Request,
        terminal_id: UUID,
        context: OperationsDependency,
    ) -> Any:
        result = await operations_service().get_terminal_health(context, terminal_id)
        return _data_response(request, result)

    @app.post("/v1/operations/upgrade-policies")
    async def operations_create_upgrade_policy(
        request: Request,
        body: UpgradePolicyRequest,
        context: OperationsDependency,
    ) -> Any:
        result = await operations_service().create_upgrade_policy(context, body)
        return _data_response(request, result, 201)

    @app.post("/v1/operations/upgrade-policies/{policy_id}/status")
    async def operations_set_upgrade_policy_status(
        request: Request,
        policy_id: UUID,
        body: UpgradePolicyStatusRequest,
        context: OperationsDependency,
    ) -> Any:
        result = await operations_service().set_upgrade_policy_status(
            context,
            policy_id,
            body.status,
        )
        return _data_response(request, result)

    @app.post("/v1/operations/data-access-authorizations")
    async def operations_authorize_data_access(
        request: Request,
        body: DataAccessRequest,
        context: OperationsDependency,
    ) -> Any:
        result = await operations_service().authorize_data_access(context, body)
        return _data_response(request, result)

    @app.post("/v1/terminals/enroll")
    async def enroll_terminal(
        request: Request,
        body: EnrollmentRequest,
        idempotency_key: Annotated[
            str,
            Header(alias="Idempotency-Key", min_length=1, max_length=256),
        ],
    ) -> Any:
        if container.devices is None:
            raise RepositoryUnavailable("终端激活服务暂不可用")
        result = await container.devices.enroll(body, idempotency_key)
        return _data_response(request, result, 201)

    @app.post("/v1/terminals/{terminal_id}/heartbeats")
    async def record_terminal_heartbeat(
        request: Request,
        terminal_id: UUID,
        body: HeartbeatRequest,
        context: HeartbeatDependency,
        idempotency_key: Annotated[
            str,
            Header(alias="Idempotency-Key", min_length=1, max_length=256),
        ],
    ) -> Any:
        service = container.heartbeats or container.devices
        if service is None:
            raise RepositoryUnavailable("终端心跳服务暂不可用")
        result = await service.record_heartbeat(
            context,
            terminal_id,
            body,
            idempotency_key,
        )
        return _data_response(request, result)

    @app.post("/v1/platform/upload-migration-permits")
    async def approve_upload_migration_permit(
        request: Request, body: UploadMigrationPermitRequest, context: MigrationPlatformDependency,
    ) -> Any:
        if container.capture_grants is None:
            raise RepositoryUnavailable("迁移核准服务暂不可用")
        result = await container.capture_grants.approve_migration(context, body)
        # Only this issuance response reveals the secret, once. Neither the
        # ordinary model serializer nor persistent records expose it.
        response = _data_response(request, {
            "session_id": str(result.session_id), "token": result.token.get_secret_value(),
        }, 201)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/v1/access/capture-grants")
    async def issue_capture_grants(request: Request, body: CaptureGrantBatchRequest, context: DataDependency) -> Any:
        if container.capture_grants is None:
            raise RepositoryUnavailable("采集额度服务暂不可用")
        result = await container.capture_grants.issue(context, body.count)
        # This is the only transport boundary that reveals newly issued secrets.
        response = _data_response(request, {"grants": [
            {"session_id": str(grant.session_id), "token": grant.token.get_secret_value()}
            for grant in result.grants
        ]}, 201)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/v1/access/capture-grants/retire")
    async def retire_capture_grant(request: Request, body: RetireCaptureGrantRequest, context: DataDependency) -> Any:
        if container.capture_grants is None:
            raise RepositoryUnavailable("采集额度服务暂不可用")
        await container.capture_grants.retire(context, body.session_id, body.reason)
        return _data_response(request, {"session_id": str(body.session_id), "state": "RETIRED"})

    @app.post("/v1/sessions")
    async def create_session(
        request: Request,
        body: SessionCreateRequest,
        context: TerminalDataDependency,
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=256)],
        capture_authorization: Annotated[str | None, Header(alias="X-Capture-Authorization")] = None,
        expected_manifest: Annotated[str | None, Header(alias="X-Expected-Manifest-SHA256")] = None,
    ) -> Any:
        authorization = None
        if context.terminal_access and (
            capture_authorization is not None or expected_manifest is not None
        ):
            # RAY-728 D6: capture grants and migration permits are hardware-bound.
            raise TenantAccessDenied("终端凭据不支持采集授权")
        if capture_authorization is not None or expected_manifest is not None:
            try:
                kind, token = (capture_authorization or "").split(" ", 1)
                if any(character.isspace() for character in token):
                    raise ValueError("invalid opaque token")
                authorization = SessionAuthorization(
                    session_id=body.session_id, kind=cast(Any, kind), token=cast(Any, token),
                    manifest_sha256=cast(Any, expected_manifest),
                )
            except ValueError:
                # Never include credential values or Pydantic input in errors.
                raise RequestValidationError([{"loc": ("header", "X-Capture-Authorization"), "type": "value_error", "msg": "invalid authorization headers"}]) from None
        result = await cast(IngestionService, container.ingestion).create_session(context, body, idempotency_key, authorization)
        return _data_response(request, result, 200 if result.idempotent_replay else 201)

    @app.post("/v1/identity-recovery/cases")
    async def create_recovery_case(
        request: Request,
        body: RecoveryCaseCreateRequest,
        context: DataDependency,
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=128)],
    ) -> Any:
        if container.identity_recovery is None:
            raise RepositoryUnavailable("identity recovery is unavailable")
        result = await container.identity_recovery.create_case(context, body, idempotency_key)
        return _data_response(request, result, 201)

    @app.get("/v1/identity-recovery/cases/{case_id}")
    async def get_recovery_case(request: Request, case_id: UUID, context: DataDependency) -> Any:
        if container.identity_recovery is None:
            raise RepositoryUnavailable("identity recovery is unavailable")
        result = await container.identity_recovery.get_case(context, case_id)
        return _data_response(request, result)

    @app.post("/v1/platform/identity-recovery/cases/{case_id}/compare")
    async def compare_recovery_case(
        request: Request, case_id: UUID, body: RecoveryComparisonRequest,
        context: PlatformAccessDependency,
    ) -> Any:
        if container.identity_recovery is None:
            raise RepositoryUnavailable("identity recovery is unavailable")
        result = await container.identity_recovery.compare(
            context, case_id, body.grant_id, body.original_name, body.original_contact,
            tenant_id=body.tenant_id, ticket_reference=body.ticket_reference,
        )
        return _data_response(request, result)

    @app.post("/v1/identity-recovery/cases/{case_id}/register")
    async def register_recovery_case(
        request: Request, case_id: UUID, body: RecoveryRegistrationRequest,
        context: DataDependency,
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=128)],
        capture_authorization: Annotated[str | None, Header(alias="X-Capture-Authorization")] = None,
        expected_manifest: Annotated[str | None, Header(alias="X-Expected-Manifest-SHA256")] = None,
    ) -> Any:
        if container.identity_recovery is None:
            raise RepositoryUnavailable("identity recovery is unavailable")
        authorization = None
        if capture_authorization is not None or expected_manifest is not None:
            try:
                kind, token = (capture_authorization or "").split(" ", 1)
                if any(character.isspace() for character in token):
                    raise ValueError("invalid opaque token")
                authorization = SessionAuthorization(
                    session_id=body.session.session_id, kind=cast(Any, kind), token=cast(Any, token),
                    manifest_sha256=cast(Any, expected_manifest),
                )
            except ValueError:
                raise RequestValidationError([{"loc": ("header", "X-Capture-Authorization"), "type": "value_error", "msg": "invalid authorization headers"}]) from None
        result = await container.identity_recovery.register(
            context, case_id, body, idempotency_key, authorization,
        )
        return _data_response(request, result, 201)

    @app.post("/v1/subjects/resolve")
    async def resolve_subject(
        request: Request,
        body: SubjectResolveRequest,
        context: TerminalDataDependency,
    ) -> Any:
        result = await container.subjects.resolve(context, body)
        if result is None:
            raise ResourceNotFound("当前租户内未找到该受试者编号")
        return _data_response(request, result)

    @app.post("/v1/subjects")
    async def create_subject(
        request: Request,
        body: SubjectCreateRequest,
        context: TerminalDataDependency,
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=256)],
    ) -> Any:
        result = await container.subjects.create_subject(context, body, idempotency_key)
        return _data_response(request, result, 200 if result.conflict else 201)

    @app.post("/v1/consents")
    async def create_consent(
        request: Request,
        body: ConsentCreateRequest,
        context: TerminalDataDependency,
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=256)],
    ) -> Any:
        result = await container.subjects.create_consent(context, body, idempotency_key)
        return _data_response(request, result, 201)

    @app.post("/v1/consents/{consent_record_id}/revoke")
    async def revoke_consent(
        request: Request,
        consent_record_id: UUID,
        body: ConsentRevokeRequest,
        context: TerminalDataDependency,
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=256)],
    ) -> Any:
        result = await container.subjects.revoke_consent(
            context, consent_record_id, body, idempotency_key
        )
        return _data_response(request, result)

    @app.put("/v1/sessions/{session_id}/segments/{segment_index}")
    async def put_segment(
        request: Request,
        session_id: UUID,
        segment_index: int,
        context: TerminalDataDependency,
        content_sha256: Annotated[str, Header(alias="X-Content-SHA256")],
        schema_version: Annotated[str, Header(alias="X-Schema-Version")],
        metadata_header: Annotated[str, Header(alias="X-Segment-Metadata")],
    ) -> Any:
        try:
            metadata = decode_segment_metadata(metadata_header)
        except ValueError as exc:
            raise RequestContractError("X-Segment-Metadata 无效") from exc
        if metadata.sha256 != content_sha256:
            raise RequestContractError("X-Content-SHA256 与分段元数据不一致")
        if metadata.payload_schema_version != schema_version:
            raise RequestContractError("X-Schema-Version 与分段元数据不一致")
        result = await cast(IngestionService, container.ingestion).put_segment(
            context, session_id, segment_index, metadata, request.stream()
        )
        return _data_response(request, result, 200 if result.idempotent_replay else 201)

    @app.get("/v1/sessions/{session_id}/segments")
    async def list_segments(
        request: Request, session_id: UUID, context: TerminalDataDependency
    ) -> Any:
        result = await cast(IngestionService, container.ingestion).list_segments(context, session_id)
        return _data_response(request, result)

    # RAY-825: the body model follows its schema_version, so a manifest is
    # validated only against its own schema and raw-segment/1 errors keep
    # their pre-RAY-825 shape. FastAPI's smart union would try both models.
    @app.post(
        "/v1/sessions/{session_id}/complete",
        openapi_extra={"requestBody": {"required": True, "content": {"application/json": {
            "schema": {"oneOf": [
                {"$ref": f"#/components/schemas/{model.__name__}"}
                for model in _MANIFEST_MODELS
            ]}}}}},
    )
    async def complete_session(
        request: Request,
        session_id: UUID,
        context: TerminalDataDependency,
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=256)],
        content_sha256: Annotated[str, Header(alias="X-Content-SHA256")],
        schema_version: Annotated[str, Header(alias="X-Schema-Version")],
    ) -> Any:
        body = await _session_manifest_body(request)
        if body.schema_version != schema_version:
            raise RequestContractError("X-Schema-Version 与最终清单不一致")
        result = await cast(IngestionService, container.ingestion).complete_session(
            context, session_id, body, content_sha256, idempotency_key
        )
        return _data_response(request, result)

    @app.get("/v1/sessions/{session_id}/status")
    async def session_status(
        request: Request, session_id: UUID, context: TerminalDataDependency
    ) -> Any:
        result = await cast(IngestionService, container.ingestion).get_status(context, session_id)
        return _data_response(request, result)

    def report_copy_service() -> Any:
        if container.report_copies is None:
            raise RepositoryUnavailable("basic report copy service unavailable")
        return container.report_copies

    @app.post("/v1/sessions/{session_id}/basic-report-copy")
    async def upload_local_basic_copy(
        request: Request, session_id: UUID, context: DataDependency,
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=128)],
    ) -> Any:
        payload = bytearray()
        async for chunk in request.stream():
            if len(payload) + len(chunk) > 12 * 1024 * 1024:
                raise RequestContractError("report copy request exceeds size limit")
            payload.extend(chunk)
        try:
            body = json.loads(payload)
            if not isinstance(body, dict):
                raise ValueError("body must be object")
            pdf = base64.b64decode(body["pdf_base64"], validate=True)
            copy = LocalBasicCopyRequest(
                session_id=session_id, report_id=body["report_id"],
                version=body["version"], source=body["source"],
                document_json=body["document_json"], pdf_bytes=pdf,
                document_sha256=body["document_sha256"],
                pdf_sha256=body["pdf_sha256"],
                consent_record_id=UUID(body["consent_record_id"]),
            )
        except (KeyError, ValueError, TypeError, binascii.Error) as exc:
            raise RequestContractError("invalid report copy request") from exc
        result = await report_copy_service().accept(context, copy, idempotency_key)
        return _data_response(request, result, 201)

    @app.get("/v1/reports")
    async def list_local_basic_copies(request: Request, context: TenantAccessDependency) -> Any:
        if not context.capabilities.allow_report_view:
            raise TenantAccessDenied("report view is disabled")
        rows = await report_copy_service().list_for_tenant(context.tenant_id, context.account_id)
        return _data_response(request, [
            {"report_id": row.report_id, "version": row.version, "source": row.source,
             "session_id": row.session_id, "status": "BASIC_READY"}
            for row in rows
        ])

    @app.get("/v1/reports/{report_id}/versions/1")
    async def get_local_basic_copy(request: Request, report_id: str, context: TenantAccessDependency) -> Any:
        if not context.capabilities.allow_report_view:
            raise TenantAccessDenied("report view is disabled")
        row = await report_copy_service().get(context.tenant_id, context.account_id, report_id)
        return _data_response(request, {
            "report_id": row.report_id, "version": row.version, "source": row.source,
            "document": json.loads(row.document_json),
        })

    @app.get("/v1/reports/{report_id}/versions/1/pdf")
    async def export_local_basic_copy(request: Request, report_id: str, context: TenantAccessDependency) -> Any:
        if not context.capabilities.allow_report_view:
            raise TenantAccessDenied("report view is disabled")
        payload = await report_copy_service().export_pdf(context.tenant_id, context.account_id, report_id)
        return Response(
            content=payload, media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{report_id}.pdf"'},
        )

    _with_manifest_schemas(app)
    return app
