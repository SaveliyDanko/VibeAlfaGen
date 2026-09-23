#!/bin/sh
# The CA directory is mounted, so rename becomes visible. Reload only after
# validating the new config; keep retrying a failed reload instead of losing it.
set -eu
previous=$(cksum /etc/nginx/client-ca/ca.crl)
nginx -t
nginx -g 'daemon off;' &
master=$!
trap 'kill -QUIT "$master" 2>/dev/null || true; wait "$master"' TERM INT
while kill -0 "$master" 2>/dev/null; do
  sleep 2 &
  wait $! || true
  current=$(cksum /etc/nginx/client-ca/ca.crl)
  if [ "$current" != "$previous" ] && nginx -t && nginx -s reload; then
    previous=$current
  fi
done
wait "$master"
