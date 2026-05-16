from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any, Final

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]

SECURITY_GATE_FILE: Final[Path] = REPO_ROOT / ".security-quality-gate.json"
ROUTE_INVENTORY_FILE: Final[Path] = REPO_ROOT / ".route-inventory.json"
SMOKETEST_FILE: Final[Path] = REPO_ROOT / ".smoketest-results.json"

RESULT_FILE: Final[Path] = REPO_ROOT / ".verify-results.json"


@dataclass(frozen=True, slots=True)
class ArtifactStatus:
    name: str
    ok: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class VerificationReport:
    overall_status: str
    artifacts: tuple[ArtifactStatus, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_status": self.overall_status,
            "artifacts": [a.to_dict() for a in self.artifacts],
        }


def _read_json(path: Path) -> Any:
    data = path.read_text(encoding="utf-8")
    return json.loads(data)


def _verify_security_gate() -> ArtifactStatus:
    if not SECURITY_GATE_FILE.exists():
        return ArtifactStatus(
            name="security-quality-gate",
            ok=False,
            detail=f"missing artifact: {SECURITY_GATE_FILE.name}",
        )

    try:
        payload = _read_json(SECURITY_GATE_FILE)
    except Exception as exc:  # noqa: BLE001
        return ArtifactStatus(
            name="security-quality-gate",
            ok=False,
            detail=f"failed to parse JSON: {exc.__class__.__name__}",
        )

    status = str(payload.get("status", "")).lower()
    if status != "ok":
        return ArtifactStatus(
            name="security-quality-gate",
            ok=False,
            detail=f"gate status is {status!r}, expected 'ok'",
        )

    minimum_coverage = payload.get("minimum_coverage")
    if not isinstance(minimum_coverage, int):
        return ArtifactStatus(
            name="security-quality-gate",
            ok=False,
            detail="minimum_coverage is missing or not an integer",
        )

    return ArtifactStatus(
        name="security-quality-gate",
        ok=True,
        detail=f"status ok, minimum_coverage={minimum_coverage}",
    )


def _verify_route_inventory() -> ArtifactStatus:
    if not ROUTE_INVENTORY_FILE.exists():
        return ArtifactStatus(
            name="route-inventory",
            ok=False,
            detail=f"missing artifact: {ROUTE_INVENTORY_FILE.name}",
        )

    try:
        payload = _read_json(ROUTE_INVENTORY_FILE)
    except Exception as exc:  # noqa: BLE001
        return ArtifactStatus(
            name="route-inventory",
            ok=False,
            detail=f"failed to parse JSON: {exc.__class__.__name__}",
        )

    modules = payload.get("modules")
    if not isinstance(modules, list) or not modules:
        return ArtifactStatus(
            name="route-inventory",
            ok=False,
            detail="modules list is missing or empty",
        )

    summary = payload.get("summary") or {}
    if not isinstance(summary, dict) or not summary:
        return ArtifactStatus(
            name="route-inventory",
            ok=False,
            detail="summary is missing or empty",
        )

    return ArtifactStatus(
        name="route-inventory",
        ok=True,
        detail=f"{len(modules)} modules across {len(summary)} surfaces",
    )


def _verify_smoketest() -> ArtifactStatus:
    if not SMOKETEST_FILE.exists():
        return ArtifactStatus(
            name="smoketest",
            ok=False,
            detail=f"missing artifact: {SMOKETEST_FILE.name}",
        )

    try:
        payload = _read_json(SMOKETEST_FILE)
    except Exception as exc:  # noqa: BLE001
        return ArtifactStatus(
            name="smoketest",
            ok=False,
            detail=f"failed to parse JSON: {exc.__class__.__name__}",
        )

    overall_status = str(payload.get("overall_status", "")).lower()
    if overall_status != "ok":
        return ArtifactStatus(
            name="smoketest",
            ok=False,
            detail=f"overall smoketest status is {overall_status!r}, expected 'ok'",
        )

    checks = payload.get("checks") or []
    if not isinstance(checks, list) or not checks:
        return ArtifactStatus(
            name="smoketest",
            ok=False,
            detail="checks list is missing or empty",
        )

    failed = [c for c in checks if not bool(c.get("ok"))]
    if failed:
        names = ", ".join(str(c.get("name")) for c in failed[:5])
        more = "" if len(failed) <= 5 else f" (+{len(failed) - 5} more)"
        return ArtifactStatus(
            name="smoketest",
            ok=False,
            detail=f"{len(failed)} failing checks: {names}{more}",
        )

    return ArtifactStatus(
        name="smoketest",
        ok=True,
        detail=f"{len(checks)} checks all passing",
    )


def _write_report(report: VerificationReport) -> None:
    RESULT_FILE.write_text(
        json.dumps(report.to_dict(), indent=2),
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify IronClaw deployment artifacts (security gate, route inventory, smoketest).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print verification report JSON to stdout in addition to writing it to disk.",
    )
    args = parser.parse_args(argv)

    artifacts = [
        _verify_security_gate(),
        _verify_route_inventory(),
        _verify_smoketest(),
    ]

    overall_ok = all(a.ok for a in artifacts)
    overall_status = "ok" if overall_ok else "fail"

    report = VerificationReport(
        overall_status=overall_status,
        artifacts=tuple(artifacts),
    )
    _write_report(report)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))

    print("IRONCLAW VERIFY:", overall_status.upper())
    for artifact in artifacts:
        label = "OK" if artifact.ok else "FAIL"
        print(f"[{label}] {artifact.name}: {artifact.detail}")

    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
