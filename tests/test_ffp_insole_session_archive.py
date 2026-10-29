"""RAY-825 R1: insole-session-archive/1 sessions replayed from the published vectors."""
from __future__ import annotations

import base64
import copy
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import unittest
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from techflex_cloud_foundation.contracts.access_control import AccessCapabilities
from techflex_cloud_foundation.contracts.client_sync import (
    canonical_sha256,
    decode_segment_metadata,
    encode_segment_metadata,
)
from techflex_cloud_foundation.contracts.cloud import (
    INSOLE_ARCHIVE_PAYLOAD_SCHEMA,
    INSOLE_MANIFEST_SCHEMA,
    ArchiveSegmentMetadata,
    InsoleSessionManifest,
    ManifestSegment,
    SegmentMetadata,
    SessionManifest,
    parse_session_manifest,
)
from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.server.access_auth import TenantAccessTokenIssuer
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.contract_export import build_vectors
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore

VECTORS = build_vectors()["insole_session_archive"]
ROOT = Path(__file__).resolve().parents[1]


def _b64url(value: dict) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class InsoleArchiveContractTests(unittest.TestCase):
    def test_vector_bytes_are_self_consistent(self) -> None:
        for segment in VECTORS["segments"]:
            payload = base64.b64decode(segment["payload_base64"])
            headers = segment["request_headers"]
            self.assertEqual(hashlib.sha256(payload).hexdigest(), headers["X-Content-SHA256"])
            decoded = decode_segment_metadata(headers["X-Segment-Metadata"])
            self.assertIsInstance(decoded, ArchiveSegmentMetadata)
            self.assertEqual(decoded.model_dump(mode="json"), segment["metadata"])
            self.assertEqual(
                bytes.fromhex(segment["canonical_hex"]),
                base64.urlsafe_b64decode(headers["X-Segment-Metadata"] + "=="),
            )
        manifest = parse_session_manifest(VECTORS["manifest"]["body"])
        self.assertIsInstance(manifest, InsoleSessionManifest)
        self.assertEqual(canonical_sha256(manifest), VECTORS["manifest"]["sha256"])
        self.assertEqual(
            hashlib.sha256(bytes.fromhex(VECTORS["manifest"]["canonical_hex"])).hexdigest(),
            VECTORS["manifest"]["sha256"],
        )
        self.assertEqual(
            VECTORS["segment_metadata_fields"],
            ["payload_schema_version", "segment_index", "sha256", "size_bytes"],
        )

    def test_archive_metadata_rejects_frame_fields_and_other_schemas(self) -> None:
        metadata = dict(VECTORS["segments"][0]["metadata"])
        with self.assertRaises(ValidationError):
            ArchiveSegmentMetadata.model_validate({**metadata, "frame_count": 1})
        with self.assertRaises(ValidationError):
            ArchiveSegmentMetadata.model_validate(
                {**metadata, "payload_schema_version": "raw-segment/1"}
            )
        # Any other schema still decodes as the strict raw-segment model.
        with self.assertRaises(ValidationError):
            decode_segment_metadata(
                _b64url({**metadata, "payload_schema_version": "raw-segment/1"})
            )

    def test_insole_manifest_checks_its_segment_set(self) -> None:
        body = copy.deepcopy(VECTORS["manifest"]["body"])
        with self.assertRaises(ValidationError):
            InsoleSessionManifest.model_validate({**body, "total_frames": 1})
        with self.assertRaises(ValidationError):
            InsoleSessionManifest.model_validate({**body, "total_bytes": body["total_bytes"] + 1})
        with self.assertRaises(ValidationError):
            InsoleSessionManifest.model_validate({**body, "segment_count": 3})
        swapped = {**body, "segments": list(reversed(body["segments"]))}
        with self.assertRaises(ValidationError):
            InsoleSessionManifest.model_validate(swapped)
        without_quality = dict(body)
        del without_quality["local_quality_outcome"]
        with self.assertRaises(ValidationError):
            InsoleSessionManifest.model_validate(without_quality)

    def test_raw_segment_contracts_are_unchanged(self) -> None:
        raw = build_vectors()["segment"]
        decoded = decode_segment_metadata(raw["metadata_header"])
        self.assertIsInstance(decoded, SegmentMetadata)
        self.assertEqual(encode_segment_metadata(decoded), raw["metadata_header"])
        manifest = SessionManifest(
            segment_count=1, total_frames=1, total_bytes=1,
            segments=(ManifestSegment(index=0, sha256="0" * 64, size_bytes=1, frame_count=1),),
            ended_at=datetime(2026, 10, 25, tzinfo=UTC), local_quality_outcome="VALID",
        )
        parsed = parse_session_manifest(manifest.model_dump(mode="json"))
        self.assertIsInstance(parsed, SessionManifest)
        self.assertEqual(canonical_sha256(parsed), canonical_sha256(manifest))
        # The default manifest schema still applies when a raw client omits it.
        body = manifest.model_dump(mode="json")
        del body["schema_version"]
        self.assertEqual(parse_session_manifest(body).schema_version, "session-manifest/1")


class InsoleArchiveMigrationTests(unittest.TestCase):
    def test_migration_relaxes_columns_only_for_the_insole_schemas(self) -> None:
        sql = (ROOT / "src/techflex_cloud_foundation/schema/sql/0016_insole_session_archive.sql").read_text("utf-8")
        self.assertTrue(sql.startswith("BEGIN;") and sql.rstrip().endswith("COMMIT;"))
        for forbidden in ("DROP TABLE", "DROP COLUMN", "GRANT ", "UPDATE ", "DELETE "):
            self.assertNotIn(forbidden, sql)
        self.assertEqual(sql.count("DROP NOT NULL"), 7)
        self.assertIn("WHEN payload_schema_version = 'insole-session-archive/1'", sql)
        self.assertIn("WHEN schema_version = 'insole-session-manifest/1'", sql)
        # Converging: each check is added only when it is missing.
        self.assertEqual(sql.count("ADD CONSTRAINT"), 2)
        self.assertEqual(sql.count("IF NOT EXISTS ("), 2)


class InsoleArchiveApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.now = datetime.now(UTC)
        self.tenant = uuid4()
        self.installation = uuid4()
        self.site_id = uuid4()
        self.device_id = uuid4()
        self.subject_id = uuid4()
        self.consent_id = uuid4()
        repository = InMemoryPlatformRepository()
        repository.add_terminal(self.tenant, self.site_id, self.installation)
        repository.add_device(self.tenant, self.device_id, "insole-pair")
        repository.add_subject(self.tenant, self.subject_id)
        repository.add_consent(self.tenant, self.subject_id, self.consent_id, self.now)
        issuer = TenantAccessTokenIssuer(
            secret=b"tenant-token-secret-must-be-at-least-32-bytes", key_id="tenant/1"
        )
        self.token = issuer.issue(
            tenant_id=self.tenant, account_id=uuid4(), license_id=uuid4(),
            hardware_id="usb-serial-insole00000000000001",
            client_installation_id=self.installation, token_version=1,
            capabilities=AccessCapabilities(
                allow_new_test=True, allow_upload=True, allow_report_view=True
            ),
            now=self.now,
        )
        ingestion = IngestionService(
            repository,
            SegmentObjectStore(InMemoryObjectStore()),
            supported_payload_schemas={"raw-segment/1", INSOLE_ARCHIVE_PAYLOAD_SCHEMA},
            supported_manifest_schemas={"session-manifest/1", INSOLE_MANIFEST_SCHEMA},
        )
        app = create_app(ServiceContainer(ingestion=ingestion, tenant_tokens=issuer))
        self.client = AsyncClient(transport=ASGITransport(app=app), base_url="https://cloud.test")

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    def headers(self, **extra: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", "X-Correlation-ID": str(uuid4()), **extra}

    async def create_session(self, payload_schema: str = INSOLE_ARCHIVE_PAYLOAD_SCHEMA):
        session_id = uuid4()
        response = await self.client.post(
            "/v1/sessions",
            headers=self.headers(**{"Idempotency-Key": f"create:{session_id}"}),
            json={
                "session_id": str(session_id), "subject_uuid": str(self.subject_id),
                "consent_record_id": str(self.consent_id), "site_id": str(self.site_id),
                "terminal_id": str(self.installation),
                "client_installation_id": str(self.installation),
                "device_id": str(self.device_id),
                "test_protocol": {"id": "insole-walk", "version": "1"},
                "versions": {**VECTORS["session_versions"], "payload_schema": payload_schema},
                "started_at": "2026-10-25T12:57:00Z",
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        return session_id

    async def put_parts(self, session_id) -> None:
        for segment in VECTORS["segments"]:
            index = segment["metadata"]["segment_index"]
            response = await self.client.put(
                f"/v1/sessions/{session_id}/segments/{index}",
                headers=self.headers(
                    **segment["request_headers"],
                    **{"Idempotency-Key": f"segment:{session_id}:{index}"},
                ),
                content=base64.b64decode(segment["payload_base64"]),
            )
            self.assertEqual(response.status_code, 201, response.text)

    async def complete(self, session_id, body: dict, *, schema: str | None = None):
        manifest = parse_session_manifest(body)
        return await self.client.post(
            f"/v1/sessions/{session_id}/complete",
            headers=self.headers(**{
                "Idempotency-Key": f"complete:{session_id}",
                "X-Content-SHA256": canonical_sha256(manifest),
                "X-Schema-Version": schema or manifest.schema_version,
            }),
            json=body,
        )

    def error(self, response) -> tuple[int, str, str]:
        error = response.json()["error"]
        return response.status_code, error["code"], error["action"]

    async def test_full_upload_reaches_ingested_from_published_vectors(self) -> None:
        session_id = await self.create_session()
        await self.put_parts(session_id)
        listed = await self.client.get(
            f"/v1/sessions/{session_id}/segments", headers=self.headers()
        )
        self.assertEqual(listed.status_code, 200, listed.text)
        data = listed.json()["data"]
        self.assertEqual([item["index"] for item in data["received"]], [0, 1])
        self.assertEqual(data["missing"], [])
        manifest = VECTORS["manifest"]
        response = await self.client.post(
            f"/v1/sessions/{session_id}/complete",
            headers=self.headers(**{
                **manifest["request_headers"], "Idempotency-Key": f"complete:{session_id}"
            }),
            json=manifest["body"],
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["data"]["ingest_status"], "INGESTED")
        self.assertEqual(response.json()["data"]["manifest_sha256"], manifest["sha256"])
        status = await self.client.get(
            f"/v1/sessions/{session_id}/status", headers=self.headers()
        )
        self.assertEqual(status.json()["data"]["ingest_status"], "INGESTED")
        replay = await self.client.put(
            f"/v1/sessions/{session_id}/segments/0",
            headers=self.headers(**VECTORS["segments"][0]["request_headers"]),
            content=base64.b64decode(VECTORS["segments"][0]["payload_base64"]),
        )
        self.assertEqual(replay.status_code, 200, replay.text)

    async def test_session_manifest_is_rejected_for_archive_session(self) -> None:
        session_id = await self.create_session()
        await self.put_parts(session_id)
        body = VECTORS["manifest"]["body"]
        raw = {
            "schema_version": "session-manifest/1",
            "segment_count": body["segment_count"], "total_bytes": body["total_bytes"],
            "total_frames": 2, "ended_at": body["ended_at"],
            "local_quality_outcome": "VALID",
            "segments": [{**item, "frame_count": 1} for item in body["segments"]],
        }
        response = await self.complete(session_id, raw)
        self.assertEqual(self.error(response), (422, "E-CLD-422", "UPDATE_CLIENT"))

    async def post_complete(self, session_id, body, schema: str):
        return await self.client.post(
            f"/v1/sessions/{session_id}/complete",
            headers=self.headers(**{
                "Idempotency-Key": f"complete:{session_id}", "X-Content-SHA256": "0" * 64,
                "X-Schema-Version": schema,
            }),
            json=body,
        )

    async def test_frame_fields_under_insole_manifest_schema_are_rejected(self) -> None:
        # The body is validated only as the model its schema_version names, so a
        # frame-bearing manifest cannot fall back to SessionManifest.
        session_id = await self.create_session()
        await self.put_parts(session_id)
        body = VECTORS["manifest"]["body"]
        crossed = {**body, "total_frames": 2,
                   "segments": [{**item, "frame_count": 1} for item in body["segments"]]}
        response = await self.post_complete(session_id, crossed, INSOLE_MANIFEST_SCHEMA)
        self.assertEqual(self.error(response), (422, "E-API-422", "FIX_REQUEST"))
        self.assertIn("body.total_frames", response.json()["error"]["details"]["fields"])
        # Nothing was recorded: the correct manifest still completes.
        done = await self.client.post(
            f"/v1/sessions/{session_id}/complete",
            headers=self.headers(**{
                **VECTORS["manifest"]["request_headers"],
                "Idempotency-Key": f"complete-ok:{session_id}",
            }),
            json=body,
        )
        self.assertEqual(done.status_code, 200, done.text)

    async def test_raw_manifest_validation_errors_keep_their_shape(self) -> None:
        session_id = await self.create_session("raw-segment/1")
        body = {"segment_count": 1, "total_frames": 3, "total_bytes": 1,
                "segments": [{"index": 0, "sha256": "0" * 64, "size_bytes": 1,
                              "frame_count": 1}],
                "ended_at": "2026-10-25T12:00:00Z", "local_quality_outcome": "VALID"}
        response = await self.post_complete(session_id, body, "session-manifest/1")
        self.assertEqual(self.error(response), (422, "E-API-422", "FIX_REQUEST"))
        self.assertEqual(response.json()["error"]["details"]["fields"], ["body"])
        del body["segment_count"]
        response = await self.post_complete(session_id, body, "session-manifest/1")
        self.assertEqual(response.json()["error"]["details"]["fields"], ["body.segment_count"])
        empty = await self.client.post(
            f"/v1/sessions/{session_id}/complete",
            headers=self.headers(**{"Idempotency-Key": "k", "X-Content-SHA256": "0" * 64,
                                    "X-Schema-Version": "session-manifest/1"}),
        )
        self.assertEqual(empty.json()["error"]["details"]["fields"], ["body"])
        as_text = await self.client.post(
            f"/v1/sessions/{session_id}/complete",
            headers=self.headers(**{"Idempotency-Key": "k", "X-Content-SHA256": "0" * 64,
                                    "X-Schema-Version": "session-manifest/1",
                                    "Content-Type": "text/plain"}),
            content=json.dumps({**body, "segment_count": 1}),
        )
        self.assertEqual(self.error(as_text), (422, "E-API-422", "FIX_REQUEST"))
        self.assertEqual(as_text.json()["error"]["details"]["fields"], ["body"])

    async def test_insole_manifest_is_rejected_for_raw_session(self) -> None:
        session_id = await self.create_session("raw-segment/1")
        response = await self.complete(session_id, VECTORS["manifest"]["body"])
        self.assertEqual(self.error(response), (422, "E-CLD-422", "UPDATE_CLIENT"))

    async def test_quality_other_than_valid_is_rejected(self) -> None:
        session_id = await self.create_session()
        await self.put_parts(session_id)
        body = {**VECTORS["manifest"]["body"], "local_quality_outcome": "INCOMPLETE"}
        response = await self.complete(session_id, body)
        self.assertEqual(self.error(response), (422, "E-CLD-422", "REPEAT_SCREENING"))

    async def test_frame_fields_in_archive_metadata_are_rejected(self) -> None:
        session_id = await self.create_session()
        segment = VECTORS["segments"][0]
        headers = {
            **segment["request_headers"],
            "X-Segment-Metadata": _b64url({**segment["metadata"], "frame_count": 1}),
        }
        response = await self.client.put(
            f"/v1/sessions/{session_id}/segments/0", headers=self.headers(**headers),
            content=base64.b64decode(segment["payload_base64"]),
        )
        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()["error"]["code"], "E-API-400")

    async def test_raw_segment_part_is_rejected_for_archive_session(self) -> None:
        session_id = await self.create_session()
        raw = build_vectors()["segment"]
        response = await self.client.put(
            f"/v1/sessions/{session_id}/segments/0",
            headers=self.headers(**{
                "X-Content-SHA256": raw["sha256"], "X-Schema-Version": "raw-segment/1",
                "X-Segment-Metadata": raw["metadata_header"],
            }),
            content=base64.b64decode(raw["payload_base64"]),
        )
        self.assertEqual(self.error(response), (422, "E-CLD-422", "UPDATE_CLIENT"))

    async def test_manifest_size_differing_from_part_is_incomplete(self) -> None:
        session_id = await self.create_session()
        await self.put_parts(session_id)
        body = copy.deepcopy(VECTORS["manifest"]["body"])
        body["segments"][1]["size_bytes"] += 1
        body["total_bytes"] += 1
        response = await self.complete(session_id, body)
        self.assertEqual(
            self.error(response), (422, "E-CLD-422", "UPLOAD_MISSING_SEGMENTS")
        )

    async def test_declared_scenarios_are_all_replayed_here(self) -> None:
        self.assertEqual(
            [scenario["name"] for scenario in VECTORS["scenarios"]],
            ["full_upload", "session_manifest_for_archive_session", "quality_not_valid",
             "frame_fields_in_metadata", "manifest_size_differs_from_part"],
        )


if __name__ == "__main__":
    unittest.main()
