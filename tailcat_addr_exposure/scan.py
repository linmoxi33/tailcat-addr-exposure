"""Filesystem scanner: find tailcat addresses and classify their exposure."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .addr import ADDR_RE, AddrError, parse_address

DEFAULT_EXCLUDED_DIRS = {".git", "node_modules", "__pycache__", ".venv", "vendor", ".mypy_cache"}
MAX_FILE_BYTES = 2 * 1024 * 1024

TXT_HINT = re.compile(r"(tailcat\s*=|IN\s+TXT|\bTXT\s+[\"'])", re.IGNORECASE)
SEVERITY_ORDER = {"info": 0, "warning": 1, "error": 2}


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    file: str | None = None
    line: int | None = None
    column: int | None = None
    context: str = "file"
    fingerprint: str | None = None
    length: int | None = None
    has_psk: bool | None = None
    region_id: int | None = None
    address: str | None = None  # populated only when --show-address is set

    def as_dict(self, show_address: bool = False) -> dict:
        out = {
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "context": self.context,
            "fingerprint": self.fingerprint,
            "length": self.length,
            "has_psk": self.has_psk,
            "region_id": self.region_id,
        }
        if show_address:
            out["address"] = self.address
        return out


def classify_context(path: str, line: str) -> str:
    if TXT_HINT.search(line):
        return "dns_txt"
    lowered = path.lower()
    if "/.github/workflows/" in lowered or lowered.endswith((".yml", ".yaml")):
        return "ci_config"
    if os.path.basename(lowered) in (".bash_history", ".zsh_history", ".python_history"):
        return "shell_history"
    if lowered.endswith((".log", ".jsonl")):
        return "log"
    if lowered.endswith((".md", ".rst", ".txt", ".mdx")):
        return "doc"
    return "file"


def findings_for_token(token: str, path: str, line_no: int, column: int, line: str) -> list:
    context = classify_context(path, line)
    base = {"file": path, "line": line_no, "column": column, "context": context, "address": token}
    try:
        parsed = parse_address(token)
    except AddrError as exc:
        return [Finding(rule=exc.rule, severity=exc.severity, message=exc.message, **base)]

    out: list = []
    detail = {
        "fingerprint": parsed.fingerprint,
        "length": parsed.length,
        "has_psk": parsed.has_psk,
        "region_id": parsed.region_id,
    }
    if parsed.has_psk and parsed.zero_psk:
        out.append(
            Finding(
                rule="PSK_ZERO_FIELD",
                severity="warning",
                message="address carries an all-zero pre-shared key; tailcat omits the field instead",
                **base,
                **detail,
            )
        )
    if parsed.has_psk:
        if context in ("dns_txt", "ci_config"):
            out.append(
                Finding(
                    rule="BEARER_SECRET_PUBLISHED",
                    severity="error",
                    message=(
                        "address carries a pre-shared key and appears in a publishable context; "
                        "anyone who reads it can attempt to connect, and whether the server "
                        "authenticates clients (--allow / --ssh-authorized-keys) cannot be "
                        "verified from the address"
                    ),
                    **base,
                    **detail,
                )
            )
        else:
            out.append(
                Finding(
                    rule="BEARER_SECRET",
                    severity="error",
                    message="address carries a pre-shared key and must be treated as a password; rotate it if this file can be published",
                    **base,
                    **detail,
                )
            )
    else:
        out.append(
            Finding(
                rule="NO_PSK_ADDRESS",
                severity="info",
                message="address has no pre-shared key (--psk=false or pre-v0.6.0); publishing it is safe only when the server authenticates clients",
                **base,
                **detail,
            )
        )
    if parsed.unknown_fields:
        out.append(
            Finding(
                rule="UNKNOWN_FIELDS",
                severity="warning",
                message="unknown CBOR fields present (newer tailcat?): %s" % ", ".join(sorted(parsed.unknown_fields)),
                **base,
                **detail,
            )
        )
    if parsed.regions:
        out.append(
            Finding(
                rule="EMBEDDED_DERP",
                severity="info",
                message="address embeds %d DERP region(s) with %d node(s) total; fingerprint pins the relay set"
                % (len(parsed.regions), sum(r["node_count"] for r in parsed.regions)),
                **base,
                **detail,
            )
        )
    return out


def iter_files(root: str, excluded_dirs=DEFAULT_EXCLUDED_DIRS):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in excluded_dirs and not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            yield full


def scan_file(path: str, show_address: bool = False):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return [], 0
        with open(path, "rb") as fh:
            blob = fh.read()
    except OSError:
        return [], 0
    if b"\x00" in blob[:4096]:
        return [], 0
    text = blob.decode("utf-8", "replace")
    findings: list = []
    seen_in_file = set()
    for line_no, line in enumerate(text.splitlines(), 1):
        for match in ADDR_RE.finditer(line):
            token = match.group(0)
            try:
                fp = parse_address(token).fingerprint
            except AddrError:
                fp = token
            # Deduplicate repeats on the same line only: the same address in a
            # DNS TXT record and in prose has a different exposure meaning.
            if (fp, line_no) in seen_in_file:
                continue
            seen_in_file.add((fp, line_no))
            findings.extend(findings_for_token(token, path, line_no, match.start() + 1, line))
    return findings, len(blob)


def scan_paths(paths, show_address: bool = False):
    findings: list = []
    files = 0
    total_bytes = 0
    for root in paths:
        if not os.path.exists(root):
            raise FileNotFoundError(root)
        for path in iter_files(root):
            files += 1
            found, size = scan_file(path, show_address=show_address)
            total_bytes += size
            findings.extend(found)
    findings.sort(key=lambda f: (f.file or "", f.line or 0, f.column or 0, f.rule))
    return findings, {"files": files, "bytes": total_bytes}


def summarize(findings) -> dict:
    summary = {"error": 0, "warning": 0, "info": 0}
    for f in findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1
    return summary


def threshold_hit(findings, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    floor = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER[f.severity] >= floor for f in findings)
