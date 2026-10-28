from __future__ import annotations

from datetime import UTC, datetime
import unittest
from uuid import uuid4

from pydantic import ValidationError

from techflex_cloud_foundation.contracts.client_sync import (
    canonical_sha256,
    decode_segment_metadata,
    encode_segment_metadata,
)
from techflex_cloud_foundation.contracts.cloud import (
    ManifestSegment,
    MissingValueState,
    ProfileValue,
    SegmentMetadata,
    SessionManifest,
)


class ContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.metadata = SegmentMetadata(
            segment_index=3,
            start_frame_index=360,
            frame_count=120,
            start_monotonic_ns=123_000_000_000,
            end_monotonic_ns=133_000_000_000,
            compression="zstd",
            cipher="aes-256-gcm",
            size_bytes=32,
            sha256="a" * 64,
            payload_schema_version="raw-segment/1",
        )

    def test_segment_metadata_header_round_trips(self) -> None:
        encoded = encode_segment_metadata(self.metadata)

        self.assertEqual(decode_segment_metadata(encoded), self.metadata)

    def test_canonical_manifest_digest_is_order_independent(self) -> None:
        first = {"b": 2, "a": {"d": 4, "c": 3}}
        second = {"a": {"c": 3, "d": 4}, "b": 2}

        self.assertEqual(canonical_sha256(first), canonical_sha256(second))

    def test_profile_missing_state_cannot_carry_value(self) -> None:
        with self.assertRaises(ValidationError):
            ProfileValue(state=MissingValueState.UNKNOWN, value=168.0)

    def test_provided_profile_state_requires_value(self) -> None:
        with self.assertRaises(ValidationError):
            ProfileValue(state=MissingValueState.PROVIDED, value=None)

    def test_manifest_requires_contiguous_unique_indices(self) -> None:
        with self.assertRaises(ValidationError):
            SessionManifest(
                segment_count=2,
                total_frames=20,
                total_bytes=64,
                segments=[
                    ManifestSegment(index=0, sha256="a" * 64, size_bytes=32, frame_count=10),
                    ManifestSegment(index=2, sha256="b" * 64, size_bytes=32, frame_count=10),
                ],
                ended_at=datetime.now(UTC),
                local_quality_outcome="VALID",
                schema_version="session-manifest/1",
            )

    def test_contracts_reject_unknown_fields(self) -> None:
        payload = self.metadata.model_dump()
        payload["tenant_id"] = uuid4()

        with self.assertRaises(ValidationError):
            SegmentMetadata.model_validate(payload)


if __name__ == "__main__":
    unittest.main()
