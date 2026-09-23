#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
state_dir="$repo_root/secrets/admin"
action=${1:-up}

case "$action" in
  up|down|logs) ;;
  *) echo "usage: $0 up|down|logs" >&2; exit 2 ;;
esac

if [[ "$action" == "up" ]]; then
  mkdir -p "$state_dir/config" "$state_dir/api-keys" "$state_dir/reports" "$state_dir/audit"
  # Migrate the previous layout once, preserving existing operator settings.
  for file in backend.yaml mock-client.json; do
    if [[ ! -e "$state_dir/config/$file" && -f "$state_dir/$file" ]]; then
      cp -p "$state_dir/$file" "$state_dir/config/$file"
    fi
  done
  if [[ ! -f "$state_dir/config/backend.yaml" ]]; then
    cp "$repo_root/config.compose.yaml" "$state_dir/config/backend.yaml"
  fi
  if [[ ! -f "$state_dir/config/mock-client.json" ]]; then
    printf '%s\n' '{"version":"admin-initial-v1","enabled":false,"mode":"process","scenario":"mixed","target_url":"https://nginx:8443/process","seed":1,"rate_per_second":100,"duration":"30s","concurrency":512,"max_in_flight":512,"request_timeout":"10s","payload_profile":"small","operation_weights":{"mask_only":20,"round_trip":40,"stable_retry":20,"expected_conflict":20},"system_id":"benchmark","api_key_env":"MOCK_CLIENT_API_KEY"}' >"$state_dir/config/mock-client.json"
  fi
  if [[ ! -f "$state_dir/admin-token" ]]; then
    openssl rand -base64 36 >"$state_dir/admin-token"
  fi
  if [[ ! -f "$state_dir/grafana-password" ]]; then
    (umask 077; openssl rand -hex 32 >"$state_dir/grafana-password")
  fi
  chmod 0700 "$state_dir" "$state_dir/config" "$state_dir/api-keys" "$state_dir/reports" "$state_dir/audit"
  chmod 0600 "$state_dir/config/backend.yaml" "$state_dir/config/mock-client.json" "$state_dir/admin-token"
  chmod 0640 "$state_dir/grafana-password"
  ALFAGEN_MTLS_DIR=${ALFAGEN_MTLS_DIR:-"$repo_root/secrets/mtls"} "$repo_root/scripts/generate-mtls.sh"
fi

export ALFAGEN_ADMIN_UID=${ALFAGEN_ADMIN_UID:-$(id -u)}
export ALFAGEN_ADMIN_GID=${ALFAGEN_ADMIN_GID:-$(id -g)}
compose=(docker compose -f "$repo_root/docker-compose.yml" -f "$repo_root/docker-compose.admin.yml")

case "$action" in
  up)
    "${compose[@]}" up -d --build --wait
    echo "Admin UI: http://$("${compose[@]}" port admin 8090)"
    echo "Admin token: $state_dir/admin-token"
    echo "Grafana: http://$("${compose[@]}" port grafana 3000)"
    echo "Grafana password (user admin): $state_dir/grafana-password"
    echo "Prometheus: http://$("${compose[@]}" port prometheus 9090)"
    ;;
  down) "${compose[@]}" down ;;
  logs) "${compose[@]}" logs -f admin mock-client ;;
esac
