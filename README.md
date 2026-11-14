# tailcat-addr-exposure

A `tc...` tailcat address is usually a **bearer capability**: it embeds a 32-byte WireGuard pre-shared key, and upstream's own docs say to treat it like a password. Nothing today tells you whether a `tc...` string you are about to paste into a DNS TXT record, a CI log, or a public README is a secret-bearing address or a harmless `--psk=false` one. This tool answers that offline, never prints the key, and emits a shareable fingerprint instead.

Upstream: https://github.com/tailscale/tailcat

## What the upstream is, and what it is missing

tailcat is Tailscale's netcat-over-the-data-plane tool. A server prints a short address of the form `tc` + base64url(CBOR). The CBOR map (`wire.go` → `wireConnInfo`) carries the server's WireGuard public key (`p`), an optional path-discovery key (`k`), **an optional pre-shared key (`q`)**, and DERP region info (`i` or `r`).

Upstream is explicit that the default address is a secret:

- README: *"The default address is a secret bearer capability because it contains the pre-shared key. Share it only with clients that should be able to connect. Publishing it, in a public DNS TXT record or anywhere else, gives that capability to the whole internet…"* — https://github.com/tailscale/tailcat/blob/main/README.md#L718-L721
- Source comment on `PresharedKey`: *"When non-zero, treat the entire tailcat address as a secret because it contains this key."* — https://github.com/tailscale/tailcat/blob/main/tailcat.go#L204-L208
- The docs vs. blog post contradiction is an **open issue**: https://github.com/tailscale/tailcat/issues/105
- The PSK-in-address / DNS-TXT publication hazard is an **open issue**: https://github.com/tailscale/tailcat/issues/133

The only upstream affordance is `tailcat parse <addr>`, which dumps the wire struct as JSON — including the pre-shared key, because `PresharedKey.MarshalText` renders it as `psk:<hex>` (https://github.com/tailscale/tailcat/blob/main/tailcat.go#L246-L252, dispatch at https://github.com/tailscale/tailcat/blob/main/cmd/tailcat/tailcat.go#L1196-L1199). There is no scanner, no classification, and no redacted output. Generic secret scanners have no rule for the `tc` prefix, so a leaked tailcat address walks straight past them.

## What this tool does / does not do

It does:

- parse an address **offline** (small strict CBOR reader, stdlib only), validating prefix, raw-base64url encoding, CBOR shape, key lengths, duplicate keys, trailing bytes, and the presence of DERP info;
- classify `has_psk` / no-PSK and flag PSK-bearing addresses found in **publishable contexts** (DNS `TXT`/`tailcat=` records, CI/YAML) with a distinct `BEARER_SECRET_PUBLISHED` rule;
- scan files and directories, report `file:line:col` plus a **stable SHA-256 fingerprint**, and never emit the address or the key unless you explicitly pass `--show-address`;
- expose `--json` with a fixed schema and meaningful exit codes.

It does not:

- connect to anything or test whether a server's `--allow` list protects a published address (that is not knowable from the address);
- rotate keys, decrypt traffic, or validate WireGuard keys cryptographically;
- scan git history (only the working tree you point it at).

## Install

No dependencies, Python 3.9+:

```sh
git clone git@github-<you>:<you>/tailcat-addr-exposure.git
cd tailcat-addr-exposure
./bin/tailcat-addr-exposure --version
```

## Usage

```sh
# one address: verdict + metadata, exit 1 when it carries a PSK
./bin/tailcat-addr-exposure inspect 'tc...'

# a tree: every tc... token, classified by context
./bin/tailcat-addr-exposure scan examples/in
./bin/tailcat-addr-exposure scan examples/in --json
./bin/tailcat-addr-exposure scan . --fail-on warning
```

Text output (real run over this repo's `examples/in`):

```
examples/in/leaked_notes.md:5:5: ERROR BEARER_SECRET [doc] len=249 psk=yes fp=a6dadbecab6a
examples/in/leaked_notes.md:9:41: ERROR BEARER_SECRET_PUBLISHED [dns_txt] len=249 psk=yes fp=a6dadbecab6a
examples/in/clean/README.md:6:5: INFO NO_PSK_ADDRESS [doc] len=104 psk=no fp=04e06b33273e
scanned 2 files, 1173 bytes; 2 error(s), 0 warning(s), 4 info
```

`--json` (truncated; full files live in `examples/out/`):

```json
{
  "schema": 1,
  "scanned": {"paths": ["examples/in"], "files": 2, "bytes": 1173, "addresses": 2},
  "summary": {"error": 2, "warning": 0, "info": 4},
  "worst_severity": "error",
  "findings": [
    {"rule": "BEARER_SECRET_PUBLISHED", "severity": "error", "context": "dns_txt",
     "file": "examples/in/leaked_notes.md", "line": 9, "column": 41,
     "fingerprint": "a6dadbecab6a...", "length": 249, "has_psk": true, "region_id": null}
  ]
}
```

### Exit codes

| code | meaning |
| --- | --- |
| `0` | nothing at or above `--fail-on` (default `error`); for `inspect`, the address has no PSK |
| `1` | a finding at or above `--fail-on`; for `inspect`, the address carries a PSK |
| `2` | usage or input error (unreadable path, undecodable address) |

`--fail-on error|warning|info|none` moves the threshold. `--show-address` is opt-in because it puts a secret back into your terminal scrollback and CI log.

### Rules

| rule | severity | meaning |
| --- | --- | --- |
| `BEARER_SECRET` | error | valid address carrying `q` (pre-shared key) |
| `BEARER_SECRET_PUBLISHED` | error | the same, in a DNS TXT / `tailcat=` / CI-YAML context |
| `NO_PSK_ADDRESS` | info | valid address without `q`; publishable only with client auth |
| `EMBEDDED_DERP` | info | `r` present: relay set is pinned inside the address |
| `PSK_ZERO_FIELD` | warning | `q` is 32 zero bytes (upstream omits the field instead) |
| `UNKNOWN_FIELDS` | warning | CBOR keys outside `p/k/q/r/i` |
| `ADDR_NO_DERP` | warning | no `i`/`r`: upstream omits a zero region id, so the client picks a relay |
| `ADDR_*` | error/warning | malformed base64, CBOR, key length, trailing bytes, missing prefix |

## 与同类项目的差异

Searched before building (`gh search repos "tailcat address"`, `gh search repos "secret scanner"`, `gh search code "tc" prefix tailcat`): no tailcat-specific tool exists. Generic scanners (gitleaks, trufflehog, deepfence/SecretScanner ≥3k★) find *entropy* or known provider patterns; none parse the tailcat CBOR envelope, so they cannot distinguish a PSK-bearing `tc...` (a live credential) from a `--psk=false` one (safe to publish), and none can explain *why* a match matters. This tool is format-aware and redacts by construction.

## 本轮创新

**B 档**：第一次把 tailcat 地址当作一个可判定的**凭证载体**来做离线取证——按 `wire.go` 的 `q` 字段判定 bearer secret，区分「发布到 DNS TXT 的 PSK 地址」与「无 PSK 可公开地址」，并用指纹替代原文以便报告可安全分享；上游只有会回显 PSK 的 `tailcat parse`，通用密钥扫描器对这一格式零覆盖。

## Limitations

- `examples/in/*` addresses are **synthesized** deterministically from the documented wire layout (`tests/fixtures.py`), not harvested from a live server; no real secret is in this repo.
- Context detection is heuristic: a `TXT` string near an address marks it publishable; it does not resolve DNS.
- The tool cannot tell whether a published PSK address is *actually* protected by `serve --allow`; it reports the risk, not a verdict on the server.
- Very large files are skipped above 2 MB, and git history is not walked.