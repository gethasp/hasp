#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() {
  printf 'telemetry release gate: %s\n' "$*" >&2
  exit 1
}

run_live_endpoint_gate() {
  python3 <<'PY'
import json
import subprocess
import socket
import ssl
import sys
import urllib.parse

def go_run(args):
    try:
        return subprocess.check_output(
            ["go", "run", "./cmd/telemetry-release-payload", *args],
            cwd="apps/server",
            stderr=subprocess.PIPE,
            timeout=60,
        ).strip()
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", "replace").strip()
        raise SystemExit(f"build release payload failed: {detail}") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"build release payload failed: {exc}") from exc

endpoint = go_run(["--endpoint"]).decode("utf-8")
parsed = urllib.parse.urlparse(endpoint)
if parsed.scheme != "https" or parsed.hostname != "telemetry.gethasp.com" or parsed.path != "/v1/cli/ping" or parsed.query:
    raise SystemExit("trusted endpoint constant changed")

def resolve_public_addresses(hostname):
    try:
        infos = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except OSError:
        infos = []
    addresses = [(family, sockaddr) for family, _type, _proto, _canon, sockaddr in infos]
    if addresses:
        return addresses

    resolved = []
    for record_type in ("A", "AAAA"):
        try:
            output = subprocess.check_output(
                ["dig", "+short", hostname, record_type],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        for line in output.splitlines():
            value = line.strip()
            if not value or not any(ch.isdigit() for ch in value):
                continue
            try:
                family = socket.AF_INET6 if ":" in value else socket.AF_INET
                sockaddr = (value, 443, 0, 0) if family == socket.AF_INET6 else (value, 443)
                socket.inet_pton(family, value)
            except OSError:
                continue
            resolved.append((family, sockaddr))
    return resolved


addresses = resolve_public_addresses(parsed.hostname)
if not addresses:
    raise SystemExit(f"DNS lookup returned no addresses for {parsed.hostname}")

body = go_run([])
try:
    json.loads(body.decode("utf-8"))
except json.JSONDecodeError as exc:
    raise SystemExit(f"release payload is not JSON: {exc}") from exc

context = ssl.create_default_context()
request = (
    f"POST {parsed.path} HTTP/1.1\r\n"
    f"Host: {parsed.hostname}\r\n"
    "Content-Type: application/json\r\n"
    "User-Agent: hasp-release-telemetry-gate\r\n"
    f"Content-Length: {len(body)}\r\n"
    "Connection: close\r\n"
    "\r\n"
).encode("ascii") + body

last_error = None
for family, sockaddr in addresses:
    raw = None
    tls = None
    try:
        raw = socket.socket(family, socket.SOCK_STREAM)
        raw.settimeout(10)
        raw.connect(sockaddr)
        tls = context.wrap_socket(raw, server_hostname=parsed.hostname)
        raw = None
        tls.sendall(request)
        response = b""
        while True:
            chunk = tls.recv(1024)
            if not chunk:
                break
            response += chunk
            if len(response) > 65536:
                raise RuntimeError("response too large")
        header, sep, response_body = response.partition(b"\r\n\r\n")
        if not sep:
            raise RuntimeError("missing HTTP response body")
        headers = header.decode("iso-8859-1", "replace").split("\r\n")
        status_line = headers[0]
        parts = status_line.split()
        if len(parts) < 2 or not parts[1].isdigit():
            raise RuntimeError(f"invalid HTTP status line: {status_line!r}")
        status = int(parts[1])
        if status != 202:
            raise RuntimeError(f"live endpoint returned HTTP {status}")
        response_headers = {}
        for line in headers[1:]:
            name, colon, value = line.partition(":")
            if colon:
                response_headers[name.strip().lower()] = value.strip().lower()
        if "application/json" not in response_headers.get("content-type", ""):
            raise RuntimeError("live endpoint returned non-JSON content")
        try:
            response_payload = json.loads(response_body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"live endpoint returned invalid JSON: {exc}") from exc
        if response_payload != {"ok": True}:
            raise RuntimeError(f"live endpoint returned unexpected body: {response_payload!r}")
        break
    except Exception as exc:
        last_error = exc
    finally:
        if tls is not None:
            tls.close()
        if raw is not None:
            raw.close()
else:
    raise SystemExit(f"live endpoint check failed: {last_error}")
PY
}

telemetry_doc="public/docs/telemetry.md"
if [[ ! -f "$telemetry_doc" && -f "docs/telemetry.md" ]]; then
  telemetry_doc="docs/telemetry.md"
fi
[[ -f "$telemetry_doc" ]] || fail "missing telemetry docs"

grep -q 'HASP_TELEMETRY_DISABLED' "$telemetry_doc" || fail "telemetry docs must document the env kill switch"
grep -q 'telemetry.gethasp.com/v1/cli/ping' "$telemetry_doc" || fail "telemetry docs must document the first-party endpoint"
grep -q 'HASP_TELEMETRY_ENDPOINT' scripts/build.sh || fail "build script must make the endpoint explicit"
grep -q 'telemetry.gethasp.com/v1/cli/ping' scripts/build.sh || fail "build script must pin the production endpoint"

telemetry_worker_src="apps/${HASP_PRIVATE_TELEMETRY_APP_NAME:-telemetry}/src"
third_party_scan_paths=(apps/server/internal/telemetry apps/server/internal/app/telemetry_command.go)
if [[ -d "$telemetry_worker_src" ]]; then
  third_party_scan_paths+=("$telemetry_worker_src")
fi

if rg -n 'posthog|umami|segment\.com|api-js\.mixpanel|plausible' \
  "${third_party_scan_paths[@]}" \
  >/tmp/hasp-telemetry-third-party.$$ 2>/dev/null; then
  cat /tmp/hasp-telemetry-third-party.$$ >&2
  rm -f /tmp/hasp-telemetry-third-party.$$
  fail "CLI/service telemetry code must not reference direct third-party analytics endpoints"
fi
rm -f /tmp/hasp-telemetry-third-party.$$

for forbidden in '"path"' '"repo"' '"alias"' '"ref"' '"argv"' '"env"' '"stdout"' '"stderr"' '"hostname"' '"username"'; do
  if rg -n -g '!**/*_test.go' "$forbidden" apps/server/internal/telemetry >/tmp/hasp-telemetry-forbidden.$$ 2>/dev/null; then
    cat /tmp/hasp-telemetry-forbidden.$$ >&2
    rm -f /tmp/hasp-telemetry-forbidden.$$
    fail "telemetry payload code contains forbidden key token $forbidden"
  fi
done
rm -f /tmp/hasp-telemetry-forbidden.$$

if [[ "${HASP_TELEMETRY_LIVE_GATE:-0}" == "1" ]]; then
  run_live_endpoint_gate || fail "live endpoint check failed"
fi

printf 'telemetry release gate: ok\n'
