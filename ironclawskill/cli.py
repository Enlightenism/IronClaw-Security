from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Final, Literal

from .adapterclaude import adaptclauderequest, adaptclauderesponse
from .adapteropenclaw import adaptopenclawrequest, adaptopenclawresponse
from .billing import BillingResult, chargeunits, createbillinghook
from .config import IronClawSkillConfig, loadconfig
from .contracts import SkillResponseEnvelope
from .router import IronClawSkillRouter
from .runtime import runtimesnapshot

CliFormat = Literal["json", "pretty"]
CliProvider = Literal["openclaw", "claude"]
CliOperation = Literal["scan", "actionpolicy", "actiondecision", "execute"]

DEFAULT_INPUT_FILE: Final[str] = "-"
DEFAULT_OUTPUT_FORMAT: Final[CliFormat] = "pretty"


class IronClawSkillCliError(RuntimeError):
    """Raised when CLI invocation or payload handling fails."""


def buildparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ironclawskill",
        description="IronClaw skill CLI for request adaptation, routing, runtime inspection, and guarded local testing.",
    )
    parser.add_argument(
        "--config",
        dest="configpath",
        default=None,
        help="Optional path to an ironclawskill TOML config file.",
    )
    parser.add_argument(
        "--provider",
        choices=["openclaw", "claude"],
        default="openclaw",
        help="Request adapter/provider shape for input and output payloads.",
    )
    parser.add_argument(
        "--input-file",
        default=DEFAULT_INPUT_FILE,
        help="Path to JSON input payload. Use '-' to read from stdin.",
    )
    parser.add_argument(
        "--output-format",
        choices=["json", "pretty"],
        default=DEFAULT_OUTPUT_FORMAT,
        help="Output rendering style.",
    )
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help="Exit non-zero when routed response indicates failure.",
    )
    parser.add_argument(
        "--with-billing",
        action="store_true",
        help="Run billing hook before routing and include billing result in output.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    routeparser = subparsers.add_parser(
        "route",
        help="Adapt a provider payload into SkillRequest, route it, and adapt the response back.",
    )
    routeparser.add_argument(
        "--operation",
        choices=["scan", "actionpolicy", "actiondecision", "execute"],
        default=None,
        help="Optional asserted operation for request validation.",
    )

    adaptrequestparser = subparsers.add_parser(
        "adapt-request",
        help="Adapt provider-shaped JSON into canonical SkillRequest JSON.",
    )
    adaptrequestparser.add_argument(
        "--operation",
        choices=["scan", "actionpolicy", "actiondecision", "execute"],
        default=None,
        help="Optional asserted operation for request validation.",
    )

    adaptresponseparser = subparsers.add_parser(
        "adapt-response",
        help="Adapt canonical SkillResponseEnvelope JSON into provider-shaped JSON.",
    )
    adaptresponseparser.add_argument(
        "--operation",
        choices=["scan", "actionpolicy", "actiondecision", "execute"],
        default=None,
        help="Optional asserted operation for response validation.",
    )

    runtimeparser = subparsers.add_parser(
        "runtime",
        help="Print runtime connectivity and resolved config snapshot.",
    )
    runtimeparser.add_argument(
        "--as-text",
        action="store_true",
        help="Emit only the runtime JSON payload without CLI envelope metadata.",
    )

    return parser


def readjson(path: str) -> dict[str, Any]:
    if path == "-" or not path.strip():
        data = sys.stdin.read()
        if not data.strip():
            raise IronClawSkillCliError("No JSON input received on stdin.")
        return parsedictjson(data, source="stdin")

    file_path = Path(path).expanduser().resolve()
    if not file_path.exists() or not file_path.is_file():
        raise IronClawSkillCliError(f"Input file does not exist: {file_path}")
    return parsedictjson(file_path.read_text(encoding="utf-8"), source=str(file_path))


def parsedictjson(raw: str, *, source: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IronClawSkillCliError(f"Invalid JSON from {source}: {exc}") from exc
    if not isinstance(payload, dict):
        raise IronClawSkillCliError(f"Expected top-level JSON object from {source}.")
    return payload


def loadskillconfig(configpath: str | None) -> IronClawSkillConfig:
    return loadconfig(configpath=configpath) if configpath else loadconfig()


def adaptrequest(provider: CliProvider, payload: dict[str, Any]) -> Any:  # cross-package nominal boundary: ironclaw_skill vs ironclawskill
    if provider == "openclaw":
        return adaptopenclawrequest(payload)
    if provider == "claude":
        return adaptclauderequest(payload)
    raise IronClawSkillCliError(f"Unsupported provider: {provider}")


def adaptresponse(provider: CliProvider, response: SkillResponseEnvelope) -> dict[str, Any]:
    if provider == "openclaw":
        return adaptopenclawresponse(response)
    if provider == "claude":
        return adaptclauderesponse(response)
    raise IronClawSkillCliError(f"Unsupported provider: {provider}")


def assertrequestoperation(request: Any, expected: CliOperation | None) -> None:
    if expected is None:
        return
    actual = getattr(request, "operation", None) if not isinstance(request, dict) else request.get("operation")
    if actual != expected:
        raise IronClawSkillCliError(
            f"Request operation mismatch: expected {expected}, received {actual}.",
        )


def assertresponseoperation(response: SkillResponseEnvelope, expected: CliOperation | None) -> None:
    if expected is None:
        return
    actual = getattr(response, "operation", None)
    if actual != expected:
        raise IronClawSkillCliError(
            f"Response operation mismatch: expected {expected}, received {actual}.",
        )


def envelopeok(response: SkillResponseEnvelope) -> bool:
    return bool(getattr(response, "ok", False)) and not bool(getattr(response, "errorcode", None))


def modeljson(value: Any) -> Any:
    if hasattr(value, "model_dump") and callable(value.model_dump):
        return value.model_dump(mode="json")
    if hasattr(value, "todict") and callable(value.todict):
        return value.todict()
    return value


def renderpayload(payload: Any, *, outputformat: CliFormat) -> str:
    if outputformat == "json":
        return json.dumps(payload, ensure_ascii=False)
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False)


def billingoperationfromrequest(request: Any) -> CliOperation:
    operation = getattr(request, "operation", None) if not isinstance(request, dict) else request.get("operation")
    if operation in {"scan", "actionpolicy", "actiondecision", "execute"}:
        return operation  # type: ignore[return-value]
    raise IronClawSkillCliError(f"Unsupported billing operation: {operation}")


def commandroute(args: argparse.Namespace) -> dict[str, Any]:
    payload = readjson(args.input_file)
    request = adaptrequest(args.provider, payload)
    assertrequestoperation(request, args.operation)

    billing: BillingResult | None = None
    if args.with_billing:
        billing = chargeunits(
            operation=billingoperationfromrequest(request),
            hook=createbillinghook(),
            context=None if getattr(request, "context", None) is None else None,
            metadata={
                "source": "cli",
                "provider": args.provider,
                "command": "route",
            },
        )

    router = IronClawSkillRouter()
    response = router.route(request)
    result = adaptresponse(args.provider, response)

    output: dict[str, Any] = {
        "ok": envelopeok(response),
        "provider": args.provider,
        "command": "route",
        "request": modeljson(request),
        "response": result,
    }
    if billing is not None:
        output["billing"] = billing.todict()
    return output


def commandadaptrequest(args: argparse.Namespace) -> dict[str, Any]:
    payload = readjson(args.input_file)
    request = adaptrequest(args.provider, payload)
    assertrequestoperation(request, args.operation)
    return {
        "ok": True,
        "provider": args.provider,
        "command": "adapt-request",
        "request": modeljson(request),
    }


def commandadaptresponse(args: argparse.Namespace) -> dict[str, Any]:
    payload = readjson(args.input_file)
    try:
        response = SkillResponseEnvelope(**payload)
    except Exception as exc:
        raise IronClawSkillCliError(f"Canonical response payload validation failed: {exc}") from exc
    assertresponseoperation(response, args.operation)
    return {
        "ok": envelopeok(response),
        "provider": args.provider,
        "command": "adapt-response",
        "response": adaptresponse(args.provider, response),
    }


def commandruntime(args: argparse.Namespace) -> dict[str, Any]:
    config = loadskillconfig(args.configpath)
    snapshot = runtimesnapshot()
    payload = {
        "ok": True,
        "command": "runtime",
        "config": {
            "appname": config.appname,
            "environment": config.environment,
            "defaultprovider": config.defaultprovider,
            "failclosed": config.failclosed,
            "telemetryenabled": config.telemetryenabled,
            "debug": config.debug,
            "enabledproviders": list(config.enabledproviders),
            "paths": {
                "rootdir": str(config.paths.rootdir),
                "configfile": str(config.paths.configfile) if config.paths.configfile else None,
                "auditlogpath": str(config.paths.auditlogpath) if config.paths.auditlogpath else None,
                "rulesdir": str(config.paths.rulesdir) if config.paths.rulesdir else None,
                "quarantinedir": str(config.paths.quarantinedir) if config.paths.quarantinedir else None,
                "outputdir": str(config.paths.outputdir) if config.paths.outputdir else None,
            },
            "security": {
                "reviewonhighrisk": config.security.reviewonhighrisk,
                "blockonpolicyviolation": config.security.blockonpolicyviolation,
                "allownetwork": config.security.allownetwork,
                "allowtoolinvocation": config.security.allowtoolinvocation,
                "allowfilesystemwrite": config.security.allowfilesystemwrite,
                "enablesandbox": config.security.enablesandbox,
                "enableauditlogging": config.security.enableauditlogging,
                "enablepromptredaction": config.security.enablepromptredaction,
                "maxpayloadbytes": config.security.maxpayloadbytes,
                "maxoutputbytes": config.security.maxoutputbytes,
                "maxexecutionseconds": config.security.maxexecutionseconds,
            },
        },
        "runtime": snapshot,
    }
    if args.as_text:
        return snapshot
    return payload


def dispatch(args: argparse.Namespace) -> dict[str, Any]:
    if args.command == "route":
        return commandroute(args)
    if args.command == "adapt-request":
        return commandadaptrequest(args)
    if args.command == "adapt-response":
        return commandadaptresponse(args)
    if args.command == "runtime":
        return commandruntime(args)
    raise IronClawSkillCliError(f"Unsupported command: {args.command}")


def main(argv: list[str] | None = None) -> int:
    parser = buildparser()
    args = parser.parse_args(argv)

    try:
        output = dispatch(args)
        print(renderpayload(output, outputformat=args.output_format))
        if args.fail_on_error and not bool(output.get("ok", False)):
            return 1
        return 0
    except IronClawSkillCliError as exc:
        errorpayload = {
            "ok": False,
            "error": {
                "code": "skill-cli-error",
                "message": str(exc),
            },
        }
        print(renderpayload(errorpayload, outputformat=args.output_format), file=sys.stderr)
        return 1
    except Exception as exc:
        errorpayload = {
            "ok": False,
            "error": {
                "code": "skill-cli-unhandled-error",
                "message": str(exc),
            },
        }
        print(renderpayload(errorpayload, outputformat=args.output_format), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DEFAULT_INPUT_FILE",
    "DEFAULT_OUTPUT_FORMAT",
    "CliFormat",
    "CliOperation",
    "CliProvider",
    "IronClawSkillCliError",
    "adaptrequest",
    "adaptresponse",
    "buildparser",
    "commandadaptrequest",
    "commandadaptresponse",
    "commandroute",
    "commandruntime",
    "dispatch",
    "main",
    "modeljson",
    "parsedictjson",
    "readjson",
    "renderpayload",
]
