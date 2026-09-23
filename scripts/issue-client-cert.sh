#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 || ! "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "usage: $0 SYSTEM_ID" >&2
  exit 2
fi
system_id=$1
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ca_dir=${ALFAGEN_MTLS_DIR:-"$repo_root/secrets/mtls"}
output="$ca_dir/clients/$system_id"
[[ -f "$ca_dir/ca.crt" && -f "$ca_dir/ca.key" ]] || { echo "CA not found in $ca_dir; run generate-mtls.sh first" >&2; exit 2; }
if [[ -e "$output/tls.crt" || -e "$output/tls.key" ]]; then
  echo "Refusing to replace existing certificate for $system_id" >&2
  exit 2
fi
mkdir -p "$output"
work=$(mktemp -d)
trap 'find "$work" -depth -delete 2>/dev/null || true' EXIT
openssl req -newkey rsa:2048 -sha256 -nodes -subj "/CN=${system_id}" \
  -keyout "$work/tls.key" -out "$work/client.csr" >/dev/null 2>&1
printf '%s\n' 'keyUsage=critical,digitalSignature' 'extendedKeyUsage=clientAuth' >"$work/client.ext"
openssl x509 -req -sha256 -days 365 -in "$work/client.csr" \
  -CA "$ca_dir/ca.crt" -CAkey "$ca_dir/ca.key" -CAcreateserial \
  -extfile "$work/client.ext" -out "$work/tls.crt" >/dev/null 2>&1
install -m 0600 "$work/tls.key" "$output/tls.key"
install -m 0644 "$work/tls.crt" "$output/tls.crt"
install -m 0644 "$ca_dir/ca.crt" "$output/ca.crt"
echo "Issued mTLS client certificate for $system_id in $output"
