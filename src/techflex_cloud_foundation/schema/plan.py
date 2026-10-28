"""The ordered migration plan: which SQL, in which order, and how to tell it ran.

The order and the probes reproduce ``install-seed-release.sh`` of the
FeetForcePlate cloud, so a database installed by that script upgrades in place.
Two filenames are shared by two migrations (``0009`` and ``0010``); they are
kept as shipped and told apart by their full name.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from importlib import resources


class MigrationPlanError(Exception):
    """The packaged SQL does not match the plan."""


@dataclass(frozen=True, slots=True)
class Probe:
    """A catalog question whose answer says the step already ran."""

    relation: str | None = None
    column: tuple[str, str, str] | None = None

    def __post_init__(self) -> None:
        if (self.relation is None) == (self.column is None):
            raise ValueError("a probe names exactly one of relation or column")


@dataclass(frozen=True, slots=True)
class MigrationStep:
    """One unit of the plan.

    ``probe`` is the catalog test that says the step ran; a step without one
    must converge (safe to run again), which ``converges`` states explicitly.
    ``requires_roles`` are database roles that must exist before the SQL runs.
    ``sha256`` is the digest of the SQL text and is pinned here so a changed
    file cannot ship unnoticed.
    """

    step_id: str
    filename: str | None
    sha256: str
    probe: Probe | None = None
    converges: bool = False
    requires_roles: tuple[str, ...] = ()
    inline_sql: str | None = None

    def __post_init__(self) -> None:
        if (self.filename is None) == (self.inline_sql is None):
            raise ValueError("a step has exactly one of filename or inline_sql")
        if self.probe is None and not self.converges:
            raise ValueError(f"{self.step_id}: a step without a probe must converge")


def _sql_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_step_sql(step: MigrationStep) -> str:
    """Return the SQL of a step, refusing text that differs from the pinned digest."""
    if step.inline_sql is not None:
        text = step.inline_sql
    else:
        assert step.filename is not None
        raw = (resources.files(__package__) / "sql" / step.filename).read_bytes()
        if hashlib.sha256(raw).hexdigest() != step.sha256:
            raise MigrationPlanError(f"{step.filename} differs from the pinned checksum")
        return raw.decode("utf-8")
    if _sql_digest(text) != step.sha256:
        raise MigrationPlanError(f"{step.step_id} differs from the pinned checksum")
    return text


_BACKUP_ROLE = "ffp_seed_backup"

_REPORT_COPY_GRANTS = """GRANT USAGE ON SCHEMA reporting TO ffp_seed_backup;
GRANT SELECT ON reporting.local_basic_report_copies TO ffp_seed_backup;"""

_TERMINAL_GRANTS = """GRANT SELECT ON iam.access_terminals, iam.terminal_refresh_sessions,
iam.terminal_directory, iam.terminal_refresh_directory
TO ffp_seed_backup;"""

_INSOLE_GRANTS = """GRANT SELECT ON device.insole_revision_counters, device.insole_pairs,
device.insole_identities, device.insole_registration_keys
TO ffp_seed_backup;"""

_RECOVERY_GRANTS = """GRANT SELECT ON ops.identity_recovery_cases, ops.identity_recovery_receipts,
ops.identity_recovery_comparisons, ops.identity_recovery_registrations
TO ffp_seed_backup;"""


def _file(
    stem: str,
    sha256: str,
    *,
    probe: Probe | None = None,
    converges: bool = False,
    requires_roles: tuple[str, ...] = (),
) -> MigrationStep:
    return MigrationStep(
        step_id=stem,
        filename=f"{stem}.sql",
        sha256=sha256,
        probe=probe,
        converges=converges,
        requires_roles=requires_roles,
    )


def _grant(step_id: str, sql: str) -> MigrationStep:
    return MigrationStep(
        step_id=step_id,
        filename=None,
        sha256=_sql_digest(sql),
        converges=True,
        requires_roles=(_BACKUP_ROLE,),
        inline_sql=sql,
    )


# Order is the installer's. The login roles (ffp_seed_*) are created by the
# deployment between 0010_session_expected_manifest and 0008; this plan only
# states which steps need them.
DEFAULT_PLAN: tuple[MigrationStep, ...] = (
    _file(
        "0001_p3_cloud_platform",
        "0115859e756a45c41487fdc0293fd12ad32d3eb76747c1173e24c758965986fb",
        probe=Probe(relation="iam.tenants"),
    ),
    _file(
        "0002_p5_device_operations",
        "5137c9c5024737644298fea0cac44c364164702aa167edc854000c8066e9b88e",
        probe=Probe(relation="iam.users"),
    ),
    _file(
        "0003_seed_mvp_access_control",
        "1aa1ffff783687a6f5f7c714f45038c4bc115f605ff6b9195e6ea8b2828a9634",
        probe=Probe(relation="iam.tenant_accounts"),
    ),
    _file(
        "0004_allow_unsigned_revoked_license",
        "b21bc9c8211072adc11fcb10e221223d9e64f7302ef86267f61ac4f1befda867",
        converges=True,
    ),
    _file(
        "0005_sales_inventory_activation",
        "a31d6bd4ca1705425ff87c39df2dc627770a7586e50c847fdb53b7f852088206",
        probe=Probe(relation="sales.inventory_batches"),
    ),
    _file(
        "0006_inventory_activation_pairing",
        "74776b51152cd2ba421fc216db0e9b90008f85f64e6f832e45faa5aa504af6af",
        probe=Probe(column=("sales", "inventory_batches", "activation_binding_mode")),
    ),
    _file(
        "0007_completion_receipt_fields",
        "298af981dbf1a684bcbc733ae87fba4ee748a982160c8c4dd05ebbbecddb6af4",
        probe=Probe(column=("screening", "session_manifests", "eligibility_reason")),
    ),
    _file(
        "0009_capture_grants",
        "a4de5f2532df482c74cc7905fa5c9a081063d129ea2e74770097390947930d39",
        probe=Probe(relation="screening.capture_grants"),
    ),
    _file(
        "0010_session_expected_manifest",
        "0a86743c197d4091e48c0fbd75300a664230a0d99fd9edec719f3d28ef73d16e",
        probe=Probe(column=("screening", "sessions", "expected_manifest_sha256")),
    ),
    # 0008 itself needs no role. It names ffp_seed_backup so the run pauses here,
    # where the installer ran its role step, instead of after 0008 and 0009.
    _file(
        "0008_activation_projection_grants",
        "b246cd434cd3313f1680cd54002a675237cbbe2985a23f16d71d35426b983dc9",
        converges=True,
        requires_roles=(_BACKUP_ROLE,),
    ),
    _file(
        "0009_unverified_session_holds",
        "8388f4ee44b8ca7512550815ffe31ff36008226b4f9daea1659262197589aea4",
        probe=Probe(relation="ops.session_holds"),
    ),
    _file(
        "0010_local_basic_report_copies",
        "f4fb8b36bfd2a03ca448785cf2edbf36f14b7e77e1f55ffd07bca2f0924a4125",
        probe=Probe(relation="reporting.local_basic_report_copies"),
        requires_roles=(_BACKUP_ROLE,),
    ),
    _grant("grants_0010_report_copies_to_backup", _REPORT_COPY_GRANTS),
    _file(
        "0011_controlled_identity_recovery",
        "9fe5e859187f4497d18b5b0b9ed6fa1d9174b82e2866f8c2378d30fb51429f6d",
        probe=Probe(relation="ops.identity_recovery_cases"),
    ),
    _file(
        "0012_terminal_activation",
        "7cbcfd115843c1c5d737d5ca5e9147a793b712e25dbf8b952845c66031eca9b5",
        probe=Probe(relation="iam.access_terminals"),
    ),
    _grant("grants_0012_terminals_to_backup", _TERMINAL_GRANTS),
    _file(
        "0013_insole_inventory",
        "c36cd735e4d7b50d213bd63aa64e2c92209246919b726468055c2dd3c96f5460",
        probe=Probe(relation="device.insole_pairs"),
    ),
    _grant("grants_0013_insole_to_backup", _INSOLE_GRANTS),
    _file(
        "0014_recovery_bound_migration_permits",
        "4d3ca9e9fd3dd93cb9032e19fdaf07c561e61f4432372f38b1146b1390a1006f",
        probe=Probe(column=("screening", "upload_migration_permits", "original_envelope_sha256")),
    ),
    _grant("grants_0014_recovery_to_backup", _RECOVERY_GRANTS),
    _file(
        "0015_terminal_data_plane_projection",
        "9757deb149a6512ec07880b419d5ff42218d217c56334c6b379fb3a3b5ed11ce",
        converges=True,
    ),
    _file(
        "0016_insole_session_archive",
        "971d7bafdab1479a89e9dfe51094ed0ab944c4f21a37f9effd5907783e0561b9",
        converges=True,
    ),
    _file(
        "0017_schema_migrations",
        "18a71103f11040c46ab33a15272b8a1c3c2e3ad65f5d4c6f7ec7ef7bba7b1182",
        probe=Probe(relation="ops.schema_migrations"),
    ),
)
