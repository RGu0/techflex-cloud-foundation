"""Product-neutral HTTP ingestion, using the real app and terminal credentials."""
from __future__ import annotations

import base64
from datetime import UTC, datetime
import hashlib
import json
import unittest
from uuid import uuid4

from tests import test_ffp_ray815_data_plane_smoke as smoke_fixture


def documents(installation):
    payload = b"gait-synthetic-archive"
    digest = hashlib.sha256(payload).hexdigest()
    session = {"session_id": str(uuid4()), "client_installation_id": str(installation),
               "site_id": None, "started_at": datetime.now(UTC).isoformat(),
               "versions": {"app": "gait/1", "payload_schema": "gait-session-archive/1"}}
    metadata = {"segment_index": 0, "offset": 0, "size_bytes": len(payload),
                "sha256": digest, "payload_schema_version": "gait-session-archive/1"}
    manifest = {"schema_version": "gait-session-manifest/1", "segment_count": 1,
                "total_bytes": len(payload), "codec": "gzip", "archive_size": len(payload),
                "archive_sha256": digest, "part_size": len(payload),
                "segments": [{"index": 0, "offset": 0, "size_bytes": len(payload),
                              "sha256": digest}]}
    return session, metadata, manifest, payload


def canonical(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


class RegistryHttpTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture = smoke_fixture.DataPlaneSmokeTest()
        await self.fixture.asyncSetUp()
        self.client = self.fixture.client
        self.terminal = self.fixture.terminal
        self.headers = self.fixture.headers(self.terminal)

    async def asyncTearDown(self):
        await self.fixture.asyncTearDown()

    async def test_gait_core_upload_and_idempotent_complete(self):
        session, meta, manifest, payload = documents(self.terminal["client_installation_id"])
        headers = {**self.headers, "Idempotency-Key": str(uuid4())}
        created = await self.client.post("/v1/sessions", json=session, headers=headers)
        self.assertEqual(created.status_code, 201, created.text)
        sid = session["session_id"]
        uploaded = await self.client.put(f"/v1/sessions/{sid}/segments/0", content=payload,
            headers={**self.headers, "Content-Type": "application/octet-stream",
                "X-Content-SHA256": meta["sha256"],
                "X-Schema-Version": meta["payload_schema_version"],
                "X-Segment-Metadata": base64.urlsafe_b64encode(canonical(meta)).decode()})
        self.assertEqual(uploaded.status_code, 201, uploaded.text)
        completed_headers = {**self.headers, "Idempotency-Key": str(uuid4()),
            "X-Content-SHA256": hashlib.sha256(canonical(manifest)).hexdigest(),
            "X-Schema-Version": manifest["schema_version"]}
        for _ in range(2):
            response = await self.client.post(f"/v1/sessions/{sid}/complete", json=manifest,
                                              headers=completed_headers)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["data"]["ingest_status"], "INGESTED")
        status = await self.client.get(f"/v1/sessions/{sid}/status", headers=self.headers)
        self.assertEqual(status.json()["data"]["validity_status"], "UNKNOWN")

    async def create(self, session):
        return await self.client.post("/v1/sessions", json=session,
            headers={**self.headers, "Idempotency-Key": session["session_id"]})

    async def upload(self, session, metadata, payload):
        return await self.client.put(
            f"/v1/sessions/{session['session_id']}/segments/{metadata['segment_index']}",
            content=payload, headers={**self.headers,
                "Content-Type": "application/octet-stream",
                "X-Content-SHA256": metadata["sha256"],
                "X-Schema-Version": metadata["payload_schema_version"],
                "X-Segment-Metadata": base64.urlsafe_b64encode(canonical(metadata)).decode()})

    async def complete(self, session, manifest):
        return await self.client.post(f"/v1/sessions/{session['session_id']}/complete",
            json=manifest, headers={**self.headers, "Idempotency-Key": str(uuid4()),
                "X-Content-SHA256": hashlib.sha256(canonical(manifest)).hexdigest(),
                "X-Schema-Version": manifest["schema_version"]})

    async def test_unknown_and_undeclared_fields_rejected(self):
        session, meta, manifest, payload = documents(self.terminal["client_installation_id"])
        for body in (
            {**session, "device_id": str(uuid4())},
            {**session, "versions": {"app": "test", "payload_schema": "unknown/1"}},
        ):
            self.assertEqual((await self.create(body)).status_code, 422)
        self.assertEqual((await self.create(session)).status_code, 201)
        response = await self.upload(session, {**meta, "not_registered": True}, payload)
        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual((await self.complete(session, {**manifest, "codec": "zip"})).status_code,
                         422)

    async def test_create_replay_and_request_conflict(self):
        session, _, _, _ = documents(self.terminal["client_installation_id"])
        self.assertEqual((await self.create(session)).status_code, 201)
        self.assertEqual((await self.create(session)).status_code, 200)
        changed = {**session, "config_snapshot": {"changed": True}}
        self.assertEqual((await self.create(changed)).status_code, 409)

    async def test_terminal_ownership_and_header_guards(self):
        session, meta, manifest, payload = documents(self.terminal["client_installation_id"])
        self.assertEqual((await self.create({**session,
            "client_installation_id": str(uuid4())})).status_code, 403)
        self.assertEqual((await self.create(session)).status_code, 201)
        other = await self.fixture.activate()
        self.headers = self.fixture.headers(other)
        self.assertEqual((await self.upload(session, meta, payload)).status_code, 403)
        self.assertEqual((await self.complete(session, manifest)).status_code, 403)
        response = await self.client.get(f"/v1/sessions/{session['session_id']}/status",
                                         headers=self.headers)
        self.assertEqual(response.status_code, 403)

    async def test_corrupt_bytes_and_changed_metadata_are_not_replays(self):
        session, meta, manifest, payload = documents(self.terminal["client_installation_id"])
        self.assertEqual((await self.create(session)).status_code, 201)
        self.assertEqual((await self.upload(session, meta, b"bad bytes")).status_code, 422)
        self.assertEqual((await self.upload(session, meta, payload)).status_code, 201)
        response = await self.upload(session, {**meta, "offset": 1}, payload)
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual((await self.complete(session, manifest)).status_code, 409)

    async def test_metadata_offset_must_match_manifest_even_when_bytes_match(self):
        session, meta, manifest, payload = documents(self.terminal["client_installation_id"])
        self.assertEqual((await self.create(session)).status_code, 201)
        self.assertEqual((await self.upload(session, {**meta, "offset": 2}, payload)).status_code,
                         201)
        response = await self.complete(session, manifest)
        self.assertEqual(response.status_code, 422, response.text)

    async def test_multi_part_and_nonvalid_quality_are_ingested_without_analysis(self):
        session, meta, manifest, payload = documents(self.terminal["client_installation_id"])
        self.assertEqual((await self.create(session)).status_code, 201)
        manifest["segment_count"] = 2
        manifest["segments"] = []
        offset = 0
        for index, part in enumerate((payload[:10], payload[10:])):
            digest = hashlib.sha256(part).hexdigest()
            item = {"index": index, "offset": offset, "size_bytes": len(part), "sha256": digest}
            manifest["segments"].append(item)
            metadata = {**meta, "segment_index": index, "offset": offset,
                        "size_bytes": len(part), "sha256": digest}
            self.assertEqual((await self.upload(session, metadata, part)).status_code, 201)
            offset += len(part)
        manifest["local_quality_outcome"] = "INVALID"
        self.assertEqual((await self.complete(session, manifest)).status_code, 200)
        response = await self.client.get(f"/v1/sessions/{session['session_id']}/status",
                                         headers=self.headers)
        self.assertEqual(response.json()["data"]["validity_status"], "INVALID")
        self.assertEqual(response.json()["data"]["analysis_status"], "NOT_REQUESTED")


class LegacyAdapterTests(unittest.TestCase):
    def test_raw_manifest_retains_omitted_schema_default(self):
        from techflex_cloud_foundation.contracts.cloud import (
            SessionManifest,
            parse_session_manifest,
        )
        manifest = {"segment_count": 1, "total_bytes": 2, "total_frames": 1,
                    "segments": [{"index": 0, "size_bytes": 2, "sha256": "a" * 64,
                                  "frame_count": 1}],
                    "ended_at": "2026-11-03T00:00:00Z", "local_quality_outcome": "VALID"}
        parsed = parse_session_manifest(manifest)
        self.assertIsInstance(parsed, SessionManifest)
        self.assertEqual(parsed.schema_version, "session-manifest/1")

    def test_legacy_metadata_replay_remains_digest_only(self):
        from techflex_cloud_foundation.contracts.cloud import SegmentMetadata
        from techflex_cloud_foundation.contracts.registered import segment_metadata_matches
        first = SegmentMetadata(segment_index=0, start_frame_index=0, frame_count=1,
            start_monotonic_ns=1, end_monotonic_ns=2, compression="none", cipher="aes-256-gcm",
            size_bytes=10, sha256="a" * 64, payload_schema_version="raw-segment/1")
        changed = first.model_copy(update={"frame_count": 2})
        self.assertTrue(segment_metadata_matches(first, changed))
