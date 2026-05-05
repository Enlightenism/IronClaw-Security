from __future__ import annotations

import argparse
import json
from typing import Any

from app.services.adapter_manifest import (
    build_adapter_manifest,
    summarize_adapter_manifest,
)
from app.services.integration_registry import (
    IntegrationRegistry,
    get_integration,
    initialize_integration_registry,
)
from app.services.policy_bundle_signing import (
    PolicyBundle,
    export_signed_bundle,
    initialize_policy_signing_keys,
    sign_policy_bundle,
)


def _emit(payload: dict[str, Any], *, pretty: bool = True) -> None:
    if pretty:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True))


def build_package_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ironclaw package",
        description="Build a portable installer/security package for an IronClaw integration.",
    )
    parser.add_argument("integration_id")
    parser.add_argument("--requested-by", default="cli")
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact JSON output.",
    )
    return parser


def run_package_command(
    integration_id: str,
    *,
    requested_by: str | None = "cli",
    registry: IntegrationRegistry | None = None,
    compact: bool = False,
) -> tuple[int, dict[str, Any]]:
    active_registry = registry or initialize_integration_registry()

    record = get_integration(active_registry, integration_id)
    if record is None:
        raise KeyError(f"unknown integration_id: {integration_id}")

    manifest = build_adapter_manifest(
        record,
        extra_metadata={"requested_by": requested_by, "package_operation": "bundle"},
    )
    manifest_summary = summarize_adapter_manifest(manifest)

    keyset = initialize_policy_signing_keys()
    bundle = PolicyBundle(
        bundle_id=f"bundle-{record.slug}",
        version=record.version,
        created_at=manifest.generated_at,
        policies=[
            {
                "type": "adapter_manifest",
                "integration_id": record.integration_id,
                "slug": record.slug,
                "manifest": manifest.to_dict(),
            }
        ],
        metadata={
            "integration_id": record.integration_id,
            "slug": record.slug,
            "platform": record.platform,
            "requested_by": requested_by,
        },
    )
    signed_bundle = sign_policy_bundle(bundle, keyset)

    payload = {
        "command": "package",
        "integration_id": record.integration_id,
        "slug": record.slug,
        "platform": record.platform,
        "requested_by": requested_by,
        "manifest": manifest_summary,
        "bundle": {
            "bundle_id": signed_bundle.bundle.bundle_id,
            "version": signed_bundle.bundle.version,
            "key_id": signed_bundle.key_id,
            "algorithm": signed_bundle.algorithm,
            "signed_at": signed_bundle.signed_at,
            "export_json": export_signed_bundle(signed_bundle, format="json"),
            "export_compact": export_signed_bundle(signed_bundle, format="compact"),
        },
    }
    _emit(payload, pretty=not compact)
    return 0, payload


def handle_package_args(
    args: argparse.Namespace,
    *,
    registry: IntegrationRegistry | None = None,
) -> int:
    exit_code, _ = run_package_command(
        args.integration_id,
        requested_by=args.requested_by,
        registry=registry,
        compact=args.compact,
    )
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = build_package_parser()
    args = parser.parse_args(argv)
    return handle_package_args(args)


if __name__ == "__main__":
    raise SystemExit(main())