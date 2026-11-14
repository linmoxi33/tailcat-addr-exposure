"""CLI entry point for tailcat-addr-exposure."""

from __future__ import annotations

import argparse
import json
import sys

from .addr import AddrError, parse_address
from .scan import scan_paths, summarize, threshold_hit, SEVERITY_ORDER

SCHEMA = 1
VERSION = "1.0.0"


def _emit(payload: dict, as_json: bool) -> None:
    if as_json:
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")


def cmd_inspect(args) -> int:
    try:
        parsed = parse_address(args.address)
    except AddrError as exc:
        payload = {
            "schema": SCHEMA,
            "verdict": "invalid",
            "error": {"rule": exc.rule, "message": exc.message, "severity": exc.severity},
        }
        if args.json:
            _emit(payload, True)
        else:
            print("invalid: %s: %s" % (exc.rule, exc.message), file=sys.stderr)
        return 2

    risk = "bearer-secret" if parsed.has_psk else "publishable-no-psk"
    payload = {
        "schema": SCHEMA,
        "verdict": risk,
        "address": parsed.as_dict(),
        "risk": {
            "bearer_secret": parsed.has_psk,
            "contains_key_material": bool(parsed.has_psk),
            "note": (
                "anyone holding this address can attempt to connect; only safe to publish when the "
                "server also authenticates clients (serve --allow / --ssh-authorized-keys)"
                if parsed.has_psk
                else "no pre-shared key in this address; publishing is safe only with client authentication"
            ),
        },
    }
    if args.show_address:
        payload["address"]["raw"] = parsed.text
    if args.json:
        _emit(payload, True)
    else:
        print("fingerprint: %s" % parsed.fingerprint[:16])
        print("verdict:     %s" % risk)
        print("length:      %d chars" % parsed.length)
        print("server key:  %s... (32 bytes)" % parsed.server_key[:8].hex())
        print("disco key:   %s" % ("present" if parsed.has_disco else "absent"))
        print("pre-shared:  %s" % ("present (SECRET)" if parsed.has_psk else "absent"))
        print("region id:   %s" % (parsed.region_id if parsed.region_id is not None else "not set"))
        print("embedded derp regions: %d" % len(parsed.regions))
        if parsed.unknown_fields:
            print("unknown fields: %s" % ", ".join(sorted(parsed.unknown_fields)))
        print("note:        %s" % payload["risk"]["note"])
    return 1 if parsed.has_psk else 0


def cmd_scan(args) -> int:
    try:
        findings, stats = scan_paths(args.paths, show_address=args.show_address)
    except FileNotFoundError as exc:
        print("error: no such path: %s" % exc, file=sys.stderr)
        return 2
    summary = summarize(findings)
    worst = "none"
    for sev in ("error", "warning", "info"):
        if summary.get(sev):
            worst = sev
            break
    payload = {
        "schema": SCHEMA,
        "tool_version": VERSION,
        "scanned": {
            "paths": args.paths,
            "files": stats["files"],
            "bytes": stats["bytes"],
            "addresses": len({f.fingerprint for f in findings if f.fingerprint}),
        },
        "summary": summary,
        "worst_severity": worst,
        "findings": [f.as_dict(show_address=args.show_address) for f in findings],
    }
    if args.json:
        _emit(payload, True)
    else:
        for f in findings:
            location = "%s:%s:%s" % (f.file, f.line, f.column) if f.file else "<input>"
            print(
                "%s: %s %s [%s] len=%s psk=%s fp=%s"
                % (
                    location,
                    f.severity.upper(),
                    f.rule,
                    f.context,
                    f.length,
                    "yes" if f.has_psk else ("no" if f.has_psk is False else "?"),
                    (f.fingerprint or "-")[:12],
                )
            )
            print("    %s" % f.message)
            if args.show_address and f.address:
                print("    address: %s" % f.address)
        print(
            "scanned %d files, %d bytes; %d error(s), %d warning(s), %d info"
            % (stats["files"], stats["bytes"], summary["error"], summary["warning"], summary["info"])
        )
    return 1 if threshold_hit(findings, args.fail_on) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tailcat-addr-exposure",
        description="Offline auditor for tailcat addresses: is this tc... string a bearer secret?",
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    inspect_p = sub.add_parser("inspect", help="decode one address without printing key material")
    inspect_p.add_argument("address")
    inspect_p.add_argument("--json", action="store_true")
    inspect_p.add_argument("--show-address", action="store_true", help="echo the raw address (it may be a secret)")
    inspect_p.set_defaults(func=cmd_inspect)

    scan_p = sub.add_parser("scan", help="scan files or directories for tc... addresses")
    scan_p.add_argument("paths", nargs="+")
    scan_p.add_argument("--json", action="store_true")
    scan_p.add_argument("--show-address", action="store_true", help="include raw addresses in the report")
    scan_p.add_argument(
        "--fail-on",
        choices=["error", "warning", "info", "none"],
        default="error",
        help="lowest severity that makes the command exit 1 (default: error)",
    )
    scan_p.set_defaults(func=cmd_scan)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
