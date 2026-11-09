#!/bin/sh
set -eu
case "$1" in
  go)
    export POSTERN_TEST_GO_CLIENT=1
    exec "$POSTERN_GO_CLIENT" -test.run=^TestClientTransportChild$
    ;;
  curl)
    exec curl --silent --show-error --fail --proxy-cacert "$SSL_CERT_FILE" --cacert "$SSL_CERT_FILE" "$POSTERN_TEST_TARGET"
    ;;
  node)
    export NODE_USE_ENV_PROXY=1
    exec node -e 'fetch(process.env.POSTERN_TEST_TARGET).then(r => {if (!r.ok) process.exit(3); return r.text()}).then(t => {if (t !== "ok") process.exit(4)}).catch(() => process.exit(5))'
    ;;
  requests)
    exec python3 -c 'import os,requests; r=requests.get(os.environ["POSTERN_TEST_TARGET"],timeout=8); r.raise_for_status(); assert r.text=="ok"'
    ;;
  httpx)
    exec python3 -c 'import os,httpx; r=httpx.get(os.environ["POSTERN_TEST_TARGET"],timeout=8); r.raise_for_status(); assert r.text=="ok"'
    ;;
  urllib)
    exec python3 -c 'import os,urllib.request; assert urllib.request.urlopen(os.environ["POSTERN_TEST_TARGET"],timeout=8).read()==b"ok"'
    ;;
  client-one)
    export ANTHROPIC_API_KEY="$POSTERN_TEST_API_KEY"
    export ANTHROPIC_BASE_URL="$POSTERN_TEST_TARGET"
    export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
    exec "$POSTERN_CLIENT_TOOLS/claude" --bare --no-session-persistence -p transport-check
    ;;
  client-two)
    export OPENAI_API_KEY="$POSTERN_TEST_API_KEY"
    export CODEX_API_KEY="$POSTERN_TEST_API_KEY"
    exec "$POSTERN_CLIENT_TOOLS/codex" --no-daemon exec --ephemeral --skip-git-repo-check --ignore-user-config \
      -c "openai_base_url=\"$POSTERN_TEST_TARGET/v1\"" -m transport-check transport-check
    ;;
  *) exit 2 ;;
esac
