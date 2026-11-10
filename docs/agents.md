# Agent enrollment and launch

Start from `postern config init`, install the proxy CA, and enable required client
authentication explicitly with `proxy.client_auth: required`, then restart the
server. Generated and existing configs otherwise keep authentication off; existing
bootstrap workflows remain available. Enroll only into a writable, protected configuration. The launcher
requires its recipient before mutation, keeps the key in memory, commits only the
verifier and waits up to five seconds for the running server to accept the new
key before starting the selected program without a shell. A failed confirmation
leaves the verifier committed and does not launch the recipient or restore a
rotated key. Inspect safe reload diagnostics and re-enroll after correcting the
server or trust configuration:

```sh
postern agent add worker --ca /trusted/postern-ca.pem --exec PROGRAM ARGUMENTS
postern agent rotate worker --ca /trusted/postern-ca.pem --exec PROGRAM ARGUMENTS
postern agent list
postern agent remove worker
```

`--exec` consumes all remaining arguments verbatim. All launcher flags go before
it. `--config PATH` selects the live configuration; `--proxy URL` selects an
endpoint without userinfo. TLS configs derive their default URL from the first
configured listener hostname. `--ca PATH` supplies a public CA bundle to
`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS` and `REQUESTS_CA_BUNDLE` in the child only.
Without it the recipient must already trust both hops through its own settings
or system store. curl also needs its explicit `--proxy-cacert PATH` option for
the proxy hop. The recipient's argument list may include public trust settings,
but must never include proxy keys.

The child receives authenticated HTTP(S) proxy URLs and `NODE_USE_ENV_PROXY=1`.
Existing proxy/bypass
environment settings are replaced in that child; parent settings are unchanged.
This is a credential-aware launcher, not the connect/disconnect configuration
manager. Applications can ignore environment proxy settings; use egress
containment and verify the selected client's real request path.

For a remote client, run issuance on its trusted launcher host:

```sh
postern agent add worker --enrollment-out ./worker-enrollment.yaml \
  --proxy https://proxy.example.test:1701 --ca /trusted/postern-ca.pem \
  --exec PROGRAM ARGUMENTS
```

The artifact contains only the name and verifier and has owner-only permissions.
An operator installs its `agents` entry through the existing protected config
workflow. The client receives 407 until that snapshot applies. `--enrollment-out`
and live `--config` mutation are mutually exclusive; existing artifacts are never
overwritten. A read-only live config is an error, never a reason to print a key.

Keys cannot be recovered/exported. Process loss requires re-enrollment/rotation.
Launch failure leaves enrollment committed and never rolls a rotation back.
Removing/rotating a live identity tears down busy sessions as well as idle ones.
Old configuration backups can re-enable old keys; handle them as protected state.

## Compatibility evidence

The real listener, authentication path and MITM were rechecked on Linux with
these clients. Each reached a local TLS mock upstream with its named proxy
identity, without forwarding proxy authentication. These are transport checks;
the CLI model endpoints returned a deliberate refusal and made no model-service
calls. They do not certify every configuration or client release.

| Client | Version | Proxy hop | Public CA setting |
| --- | --- | --- | --- |
| curl | 8.14.1 | TLS | `--proxy-cacert` and destination `--cacert` |
| Go net/http | 1.27.3 | TLS | `SSL_CERT_FILE`, explicit proxy URL selection |
| Node fetch | 24.21.0 | TLS | `NODE_EXTRA_CA_CERTS`, `NODE_USE_ENV_PROXY=1` |
| Claude Code | 2.1.319 | TLS | `NODE_EXTRA_CA_CERTS` |
| Codex CLI | 0.167.0 | TLS | `SSL_CERT_FILE` |
| requests / urllib3 | 2.34.0 / 2.8.0 | TLS | `REQUESTS_CA_BUNDLE` |
| httpx | 0.28.1 | TLS | `SSL_CERT_FILE` |
| Python urllib | 3.13.5 | protected plaintext | `SSL_CERT_FILE` for destination |

urllib's HTTPS proxy route did not protect CONNECT credentials in the preliminary
spike, so it uses loopback or an explicitly externally protected plaintext path.
Never interpret `HTTPS_PROXY` or destination TLS alone as proxy-hop protection.
For opaque passthrough, a client still needs normal destination roots; provide
a public bundle containing the Postern CA and the roots the recipient needs.

The opt-in `TestClientsAgainstProxyImplementation` uses testdata/client-check.sh.
Inside `make shell`, set `POSTERN_CLIENT_CHECK=1`, point `POSTERN_CLIENT_TOOLS`
at the directory containing the two CLI executables, make requests/httpx available
to Python, and run the runtime package test with that name. Tests generate keys
in memory, discard client diagnostics and write only a public CA certificate.
CLI fixtures use nonpersistent sessions and a local mock endpoint. Codex's
[noninteractive mode](https://learn.chatgpt.com/docs/non-interactive-mode) and
[endpoint override](https://learn.chatgpt.com/docs/config-file/config-advanced)
settings were checked against official documentation and the installed CLI.

Live enrollment uses an authenticated, origin-form `OPTIONS
/.well-known/postern/client-auth` probe on the proxy listener. It returns 204 only
after authentication and lifecycle admission, without invoking policy, credential
resolution or upstream dialing. Redirects are never followed. Remote artifact
issuance deliberately skips this wait because operator installation happens later.
