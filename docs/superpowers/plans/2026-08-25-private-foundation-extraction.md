# Private Foundation Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (\`- [ ]\`) syntax for tracking.

**Goal:** Deliver \`techflex-cloud-foundation\` 0.1.1 as a private, independently buildable Python distribution with security, provenance, and isolation validation.

**Architecture:** The repository root becomes the package project and preserves the existing \`techflex_cloud_foundation\` import namespace. Tests and release tooling move with the public implementation; FeetForcePlate remains an external consumer and supplies historical-baseline provenance only.

**Tech Stack:** Python 3.11, uv, Hatchling, pytest, Ruff, mypy, httpx, cryptography, asyncpg optional extra, GitHub Actions, pip-audit.

**Spec:** \`docs/superpowers/specs/2026-08-25-private-foundation-extraction-design.md\`

## Global Constraints

- Release \`techflex-cloud-foundation\` version \`0.1.1\`; retain import namespace \`techflex_cloud_foundation\`.
- Require Python \`>=3.11\`, \`cryptography>=42,<51\`, and \`httpx>=0.28,<1\`.
- Keep \`asyncpg>=0.30,<1\` only in the optional \`server\` extra.
- Never copy FeetForcePlate \`client/\`, \`cloud/\`, \`shared/\`, business schema/SQL/RLS/migrations, devices, reports, credentials, raw frames, or customer data.
- Build wheel and sdist without committing \`dist/\`, virtual environments, audit exports, or generated evidence.
- Preserve \`legacy-httpx-client/1\`; reject P95 overhead above 5 percent and peak-memory overhead above 10 percent.
- After bootstrap files exist, run every test/lint/build through \`project_command.py --project-root <scope-worktree> --action <action>\`.

## File Structure

| Path | Responsibility |
| --- | --- |
| \`pyproject.toml\`, \`.python-version\`, \`uv.lock\` | Root package metadata, runtime pin, reproducible dependencies. |
| \`dev\`, \`dev.ps1\` | Governed cross-platform setup/test/lint/build entrypoints. |
| \`src/techflex_cloud_foundation/\` | Stable public transport, entitlement, reliability, diagnostics, and database contracts. |
| \`tests/test_public_contracts.py\` | RAY-269 public behavioral contracts. |
| \`scripts/record_foundation_release_baseline.py\` | Redacted provenance, SBOM and enforced benchmark comparison. |
| \`tests/test_release_baseline.py\` | Release-evidence and budget refusal contracts. |
| \`tests/test_repository_isolation.py\` | Static no-FeetForcePlate dependency boundary. |
| \`tests/test_wheel_consumer.py\`, \`tests/consumer_program.py\` | Clean-environment artifact consumer proof. |
| \`.github/workflows/quality.yml\` | Cross-platform quality, audit, artifact evidence. |
| \`README.md\`, \`CHANGELOG.md\`, \`SECURITY.md\` | Private package, semantic versioning, and disclosure guidance. |

### Task 1: Establish standalone metadata and governed entrypoints

**Files:**
- Create: \`pyproject.toml\`, \`.python-version\`, \`dev\`, \`dev.ps1\`, \`.gitignore\`, \`tests/test_project_metadata.py\`
- Modify: \`README.md\`
- Generate: \`uv.lock\`

**Interfaces:**
- Consumes: RAY-269 package metadata.
- Produces: \`./dev setup|test|lint|build\` and \`pwsh -File dev.ps1 setup|test|lint|build\`.

- [ ] **Step 1: Write the failing metadata test**

    \`\`\`python
    import tomllib
    from pathlib import Path

    def test_root_project_is_the_foundation_distribution() -> None:
        project = tomllib.loads(Path("pyproject.toml").read_text())["project"]
        assert project["name"] == "techflex-cloud-foundation"
        assert project["version"] == "0.1.1"
        assert project["requires-python"] == ">=3.11"
        assert project["optional-dependencies"]["server"] == ["asyncpg>=0.30,<1"]
    \`\`\`

- [ ] **Step 2: Run the test to verify failure**

  Run: \`python -m pytest tests/test_project_metadata.py -v\`
  Expected: FAIL because root \`pyproject.toml\` is absent.

- [ ] **Step 3: Add minimal root project configuration**

    \`\`\`toml
    [project]
    name = "techflex-cloud-foundation"
    version = "0.1.1"
    requires-python = ">=3.11"
    dependencies = ["cryptography>=42,<51", "httpx>=0.28,<1"]

    [project.optional-dependencies]
    server = ["asyncpg>=0.30,<1"]
    dev = ["pytest>=8,<10", "ruff>=0.12,<1", "mypy>=1.17,<2", "pip-audit>=2.10,<3"]
    \`\`\`

  Implement \`dev\` and \`dev.ps1\` so every action uses \`uv sync --locked --extra dev\`; \`build\` uses \`uv build --out-dir <temporary-dir>\`.

- [ ] **Step 4: Generate lock and validate through the governed command**

  Run: \`uv lock\` once to bootstrap the newly declared locked project, then \`project_command.py --project-root . --action test\`.
  Expected: PASS for \`tests/test_project_metadata.py\`.

- [ ] **Step 5: Commit**

    \`\`\`bash
    git add pyproject.toml .python-version uv.lock dev dev.ps1 .gitignore README.md tests/test_project_metadata.py
    git commit -m "Set up standalone foundation package"
    \`\`\`

### Task 2: Move the public implementation and behavioral contracts

**Files:**
- Create: \`src/techflex_cloud_foundation/__init__.py\`, \`database.py\`, \`diagnostics.py\`, \`entitlement.py\`, \`reliability.py\`, \`transport.py\`, \`py.typed\`, \`tests/test_public_contracts.py\`
- Modify: \`pyproject.toml\`, \`dev\`, \`dev.ps1\`, \`uv.lock\`

**Interfaces:**
- Consumes: the validated RAY-269 package source.
- Produces: unchanged public \`SecureTransport\`, \`AuthorizedTransport\`, \`ReliableOperation\`, \`SqliteOperationStore\`, \`RetryPolicy\`, \`TrustBundle\`, \`TrustBundleVerifier\`, and \`EntitlementDecision\`.

- [ ] **Step 1: Write the failing public-import contract**

    \`\`\`python
    from techflex_cloud_foundation import ReliableOperation, SecureTransport

    def test_consumer_imports_only_public_package() -> None:
        assert ReliableOperation.__module__.startswith("techflex_cloud_foundation")
        assert SecureTransport.__module__.startswith("techflex_cloud_foundation")
    \`\`\`

- [ ] **Step 2: Run governed test to verify failure**

  Run: \`project_command.py --project-root . --action test\`
  Expected: FAIL with \`ModuleNotFoundError: techflex_cloud_foundation\`.

- [ ] **Step 3: Copy only the seven public implementation files and port contracts**

  Port exact RAY-269 tests for retry-after deadlines, refresh-once after 401, caller-supplied correlation-ID reuse, signed monotonic trust bundles, immutable application-scoped entitlements, and SQLite interrupted-lease recovery.

    \`\`\`python
    def test_operation_store_recovers_only_interrupted_leases(tmp_path: Path) -> None:
        store = SqliteOperationStore(tmp_path / "operations.sqlite3")
        operation = ReliableOperation.create(
            kind="example.upload", payload_ref="spool/session-2",
            payload_digest="b" * 64, idempotency_key="example:session-2",
        )
        store.enqueue(operation)
        assert store.lease_due(now=datetime.now(UTC)) is not None
        store.recover_interrupted_leases(now=datetime.now(UTC))
        assert store.get(operation.operation_id).state is OperationState.READY
    \`\`\`

- [ ] **Step 4: Run public contracts, lint, and typing**

  Run: \`project_command.py --project-root . --action test\`, then \`lint\`.
  Expected: PASS; \`ruff check .\` and \`mypy src/techflex_cloud_foundation\` have no errors.

- [ ] **Step 5: Commit**

    \`\`\`bash
    git add src/techflex_cloud_foundation tests/test_public_contracts.py pyproject.toml dev dev.ps1 uv.lock
    git commit -m "Extract public cloud foundation contracts"
    \`\`\`

### Task 3: Port release provenance and enforced performance comparison

**Files:**
- Create: \`scripts/record_foundation_release_baseline.py\`, \`tests/test_release_baseline.py\`
- Modify: \`dev\`, \`dev.ps1\`, \`pyproject.toml\`

**Interfaces:**
- Consumes: \`SecureTransport\`, \`uv.lock\`, a distribution directory, and Git HEAD.
- Produces: \`build_release_evidence(...)\`, \`assert_performance_budget(...)\`, and redacted JSON evidence.

- [ ] **Step 1: Write failing budget tests**

    \`\`\`python
    import pytest
    from scripts.record_foundation_release_baseline import assert_performance_budget

    def test_performance_budget_rejects_threshold_excess() -> None:
        baseline = {"p95_operation_seconds": 1.0, "peak_memory_bytes": 100}
        with pytest.raises(ValueError, match="P95"):
            assert_performance_budget(
                {"p95_operation_seconds": 1.051, "peak_memory_bytes": 110}, baseline
            )
    \`\`\`

- [ ] **Step 2: Run governed test to verify failure**

  Run: \`project_command.py --project-root . --action test\`
  Expected: FAIL because \`scripts.record_foundation_release_baseline\` is absent.

- [ ] **Step 3: Port the self-contained release tool**

  Retain:

    \`\`\`python
    PRE_EXTRACTION_BASELINE_REVISION = "6e76234f0ec466f4fa62f6368ea646ec8b37979e"
    LEGACY_HTTPX_WORKLOAD = "legacy-httpx-client/1"
    \`\`\`

  Make \`--package-root\` default to \`Path(".")\`; read root metadata and call:

    \`\`\`python
    assert_performance_budget(
        evidence["performance"],
        evidence["performance_baseline"]["performance"],
    )
    \`\`\`

- [ ] **Step 4: Run release tests and governed build**

  Run: \`project_command.py --project-root . --action test\`, then \`build\`.
  Expected: PASS; wheel and sdist build into a temporary directory and thresholds above 5/10 percent are rejected.

- [ ] **Step 5: Commit**

    \`\`\`bash
    git add scripts/record_foundation_release_baseline.py tests/test_release_baseline.py dev dev.ps1 pyproject.toml uv.lock
    git commit -m "Add independent release evidence gate"
    \`\`\`

### Task 4: Prove source and built-artifact isolation

**Files:**
- Create: \`tests/test_repository_isolation.py\`, \`tests/test_wheel_consumer.py\`, \`tests/consumer_program.py\`
- Modify: \`.gitignore\`, \`dev\`, \`dev.ps1\`

**Interfaces:**
- Consumes: a built wheel and a temporary virtual environment.
- Produces: proof that installation succeeds with no source-tree \`PYTHONPATH\` and only public imports.

- [ ] **Step 1: Write failing isolation tests**

    \`\`\`python
    FORBIDDEN = ("feetforceplate", "client.", "cloud.", "shared.")

    def test_tracked_source_has_no_application_import_boundary_leak() -> None:
        texts = [path.read_text() for path in Path("src").rglob("*.py")]
        assert not [token for token in FORBIDDEN if any(token in text for text in texts)]
    \`\`\`

    \`\`\`python
    def test_wheel_consumer_runs_without_source_tree_on_pythonpath(tmp_path: Path) -> None:
        wheel = build_one_wheel(tmp_path / "dist")
        environment = create_venv(tmp_path / "venv")
        install_wheel(environment, wheel)
        result = run_consumer(environment, Path("tests/consumer_program.py"))
        assert result.returncode == 0, result.stderr
    \`\`\`

- [ ] **Step 2: Run governed test to verify helper failure**

  Run: \`project_command.py --project-root . --action test\`
  Expected: FAIL because \`build_one_wheel\`, \`create_venv\`, \`install_wheel\`, and \`run_consumer\` are undefined.

- [ ] **Step 3: Implement helpers and public-only consumer**

    \`\`\`python
    from techflex_cloud_foundation import (
        EntitlementDecision, ReliableOperation, RetryPolicy, SecureTransport,
        SqliteOperationStore, TrustBundle,
    )

    assert SecureTransport and ReliableOperation and RetryPolicy
    assert SqliteOperationStore and TrustBundle and EntitlementDecision
    \`\`\`

  Create the environment using \`sys.executable -m venv\`, install the exact wheel with \`pip --no-deps\`, clear \`PYTHONPATH\`, and assert \`importlib.util.find_spec("client") is None\`.

- [ ] **Step 4: Run full governed validation**

  Run: \`project_command.py --project-root . --action test\`, \`lint\`, then \`build\`.
  Expected: PASS; both source isolation and clean-wheel consumption are proven.

- [ ] **Step 5: Commit**

    \`\`\`bash
    git add tests/test_repository_isolation.py tests/test_wheel_consumer.py tests/consumer_program.py .gitignore dev dev.ps1
    git commit -m "Verify standalone foundation artifacts"
    \`\`\`

### Task 5: Add CI, private-package documentation, and supply-chain evidence

**Files:**
- Create: \`.github/workflows/quality.yml\`, \`CHANGELOG.md\`, \`SECURITY.md\`
- Modify: \`README.md\`, \`tests/test_release_baseline.py\`

**Interfaces:**
- Consumes: governed actions and the release-evidence CLI.
- Produces: macOS/Ubuntu/Windows checks and a Linux audit/artifact evidence job.

- [ ] **Step 1: Write failing workflow contract**

    \`\`\`python
    def test_release_workflow_enforces_a_locked_audit_and_budget() -> None:
        workflow = Path(".github/workflows/quality.yml").read_text()
        assert "pip-audit --strict" in workflow
        assert "--baseline-strategy legacy-httpx-client/1" in workflow
        assert "uv build --out-dir foundation-dist" in workflow
    \`\`\`

- [ ] **Step 2: Run governed test to verify failure**

  Run: \`project_command.py --project-root . --action test\`
  Expected: FAIL with \`FileNotFoundError\` for \`.github/workflows/quality.yml\`.

- [ ] **Step 3: Implement CI and documentation**

  Matrix jobs run \`./dev test\`, \`./dev lint\`, and \`./dev build\` on Ubuntu, macOS, and Windows. The release job runs \`uv export --locked --extra dev\`, \`pip-audit --strict\`, \`uv build --out-dir foundation-dist\`, and the release tool with \`--baseline-strategy legacy-httpx-client/1\`; upload only distributions and redacted evidence.

  Set the changelog's first independent entry to \`0.1.1\`. Document private-only use and vulnerability reporting without addresses, tokens, or credentials.

- [ ] **Step 4: Run governed checks and inspect evidence**

  Run: \`project_command.py --project-root . --action test\`, \`lint\`, then \`build\`.
  Expected: PASS; evidence contains only revision, dependency inventory, checksums, and benchmark summaries.

- [ ] **Step 5: Commit**

    \`\`\`bash
    git add .github/workflows/quality.yml README.md CHANGELOG.md SECURITY.md tests/test_release_baseline.py
    git commit -m "Add private release validation workflow"
    \`\`\`

### Task 6: Review readiness and governed delivery evidence

**Files:**
- Create: \`.project-context/evidence/ray-271/repository-extraction-contracts/review/README.md\`, \`ci/README.md\`, \`acceptance/README.md\`
- Modify: Draft PR and RAY-271 comment

**Interfaces:**
- Consumes: final scope head, R2, CI results, release evidence.
- Produces: non-secret review, CI, and acceptance records for scope completion.

- [ ] **Step 1: Create Draft PR**

  Title: \`RAY-271 [repository-extraction-contracts] Extract private foundation package\`.
  Body names R2, version 0.1.1, source boundary, and exclusion of FeetForcePlate consumer migration.

- [ ] **Step 2: Verify review head**

  Run: \`scope_completion_gate.py verify-review-head --worktree <scope-worktree> --issue RAY-271 --scope repository-extraction-contracts --pr-url <draft-pr-url>\`.
  Expected: \`review_head_verified\` and \`review_policy: self\`.

- [ ] **Step 3: Write redacted evidence**

  Store head SHA, R2, command results, artifact checksums, and CI URLs only. Never store tokens, keys, credentials, customer data, raw frames, or package contents.

- [ ] **Step 4: Run final governed validation and wait for CI**

  Run: \`project_command.py --project-root <scope-worktree> --action test\`, then \`lint\`, then \`build\`.
  Expected: all pass locally; required PR checks pass remotely.

- [ ] **Step 5: Push the final head and request review**

    \`\`\`bash
    git status --short
    git push origin linear/ray-271/repository-extraction-contracts
    \`\`\`

  Evidence stays in \`.project-context\`; do not stage it into Git.

## Plan Self-Review

- Spec coverage: Tasks 1–2 establish the independent package and public boundary; Task 3 enforces provenance and the historic budget; Task 4 proves source and wheel isolation; Task 5 provides cross-platform CI and private supply-chain documentation; Task 6 creates the governed review records.
- Placeholder scan: no unfinished marker, indefinite work, or omitted acceptance test remains.
- Type consistency: \`techflex_cloud_foundation\`, \`build_release_evidence\`, \`assert_performance_budget\`, and \`legacy-httpx-client/1\` have one spelling throughout.
