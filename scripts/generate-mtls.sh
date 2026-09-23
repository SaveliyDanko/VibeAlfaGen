#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output=${ALFAGEN_MTLS_DIR:-"$repo_root/secrets/mtls"}
mkdir -p "$output"

publish_client_ca() {
  mkdir -p "$output/public"
  install -m 0644 "$output/ca.crt" "$output/public/ca.crt"
  install -m 0644 "$output/ca.crl" "$output/public/ca.crl"
}

required=(ca.crt ca.key ca.crl server.crt server.key client.crt client.key)
existing=0
for file in "${required[@]}"; do
  [[ -e "$output/$file" ]] && existing=$((existing + 1))
done
if [[ "$existing" -eq "${#required[@]}" ]]; then
  publish_client_ca
  echo "Using existing mTLS material in $output"
  exit 0
fi
if [[ "$existing" -eq 6 && ! -e "$output/ca.crl" ]]; then
  work=$(mktemp -d)
  trap 'find "$work" -depth -delete 2>/dev/null || true' EXIT
  : >"$work/index.txt"
  printf '1000\n' >"$work/serial"
  printf '1000\n' >"$work/crlnumber"
  cat >"$work/openssl.cnf" <<EOF
[ca]
default_ca=default
[default]
database=$work/index.txt
new_certs_dir=$work
certificate=$output/ca.crt
private_key=$output/ca.key
serial=$work/serial
crlnumber=$work/crlnumber
default_md=sha256
default_crl_days=7
EOF
  openssl ca -gencrl -config "$work/openssl.cnf" -out "$work/ca.crl" >/dev/null 2>&1
  install -m 0644 "$work/ca.crl" "$output/ca.crl"
  publish_client_ca
  echo "Added an empty CRL to existing mTLS material in $output"
  exit 0
fi
if [[ "$existing" -ne 0 ]]; then
  echo "Refusing to replace incomplete mTLS material in $output" >&2
  echo "Keep the CA stable, or move the directory explicitly before rotation." >&2
  exit 2
fi

work=$(mktemp -d)
trap 'find "$work" -depth -delete 2>/dev/null || true' EXIT
client_cn=${ALFAGEN_CLIENT_CN:-benchmark}
[[ "$client_cn" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { echo "Invalid client system ID" >&2; exit 2; }
server_sans='DNS:nginx,DNS:localhost,IP:127.0.0.1'
if [[ -n "${ALFAGEN_SERVER_IP:-}" ]]; then
  server_sans+=",IP:${ALFAGEN_SERVER_IP}"
fi
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -subj '/CN=AlfaGen client CA' -keyout "$work/ca.key" -out "$work/ca.crt" >/dev/null 2>&1
: >"$work/index.txt"
printf '1000\n' >"$work/serial"
printf '1000\n' >"$work/crlnumber"
cat >"$work/openssl.cnf" <<EOF
[ca]
default_ca=default
[default]
database=$work/index.txt
new_certs_dir=$work
certificate=$work/ca.crt
private_key=$work/ca.key
serial=$work/serial
crlnumber=$work/crlnumber
default_md=sha256
default_crl_days=7
EOF
openssl ca -gencrl -config "$work/openssl.cnf" -out "$work/ca.crl" >/dev/null 2>&1
openssl req -newkey rsa:2048 -sha256 -nodes -subj '/CN=nginx' \
  -keyout "$work/server.key" -out "$work/server.csr" >/dev/null 2>&1
printf '%s\n' \
  "subjectAltName=${server_sans}" \
  'keyUsage=critical,digitalSignature,keyEncipherment' \
  'extendedKeyUsage=serverAuth' >"$work/server.ext"
openssl x509 -req -sha256 -days 365 -in "$work/server.csr" \
  -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial \
  -extfile "$work/server.ext" -out "$work/server.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -sha256 -nodes -subj "/CN=${client_cn}" \
  -keyout "$work/client.key" -out "$work/client.csr" >/dev/null 2>&1
printf '%s\n' 'keyUsage=critical,digitalSignature' 'extendedKeyUsage=clientAuth' >"$work/client.ext"
openssl x509 -req -sha256 -days 365 -in "$work/client.csr" \
  -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial \
  -extfile "$work/client.ext" -out "$work/client.crt" >/dev/null 2>&1

install -m 0600 "$work/ca.key" "$output/ca.key"
install -m 0644 "$work/ca.crt" "$output/ca.crt"
install -m 0644 "$work/ca.crl" "$output/ca.crl"
install -m 0600 "$work/server.key" "$output/server.key"
install -m 0644 "$work/server.crt" "$output/server.crt"
install -m 0600 "$work/client.key" "$output/client.key"
install -m 0644 "$work/client.crt" "$output/client.crt"
publish_client_ca
echo "Created mTLS CA, server certificate and ${client_cn} client certificate in $output"
