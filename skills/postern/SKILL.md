---
name: postern
description: Configure and use postern, the credential-brokering HTTPS forward proxy. Use when setting postern up for an agent, routing agent traffic through it, trusting its local CA, adding or validating broker rules in ~/.postern/config.yaml, wiring a credstore (1Password, Bitwarden, OAuth2), adding approval prompts, or debugging 502s, TLS trust failures, and requests that bypass the proxy.
---

# Postern

Postern is a local HTTPS forward proxy that injects credentials for allowlisted hosts.
The agent sends no credential or a placeholder; postern matches the destination host against a rule, resolves the rule's secret reference from the configured vault or provider, injects the result, and forwards the request.
The agent never holds the real secret.

This skill covers a complete setup: install, CA trust, credential source, rules, starting the proxy, wiring the calling agent, and verifying the result.
`references/config.md` has the full rule and credstore grammar; `references/troubleshooting.md` covers failures.

- Binary: `postern` on `PATH`, or `./dist/postern` from a source build.
- Config: `~/.postern/config.yaml`. CA: `~/.postern/ca.pem`. Default listener: `127.0.0.1:1701`.
- Supported: Linux and macOS, amd64 and arm64.

## Rules for the setup

- Never read, print, copy, or store a credential, a token file, or `ca.key`.
  Config holds references such as `op://Vault/Item/field`, never values.
- Never pass a token on a command line; it lands in the process table.
- Never run `postern` itself with `sudo`.
  Only the system trust-store steps and the polkit policy install are elevated, and the user runs those.
- Never write to `~/.postern` or change file permissions when the directory is not writable by you.
  Hand those steps to the user in one block and wait.
- Do not weaken security to make a request work.
  No `on_no_match: passthrough` switch, no `scrub_responses: false`, no wildcard rule on a shared or multi-tenant suffix, no dropping an `approval` block.
- Do not add a rule for a host you picked yourself.
  Confirm with the user that this credential should be brokered to that host.
- Keep the agent and postern under separate uids where possible.
  Code running as postern's uid can read its memory and drive its approval dialogs.

## 1. Collect what only the user knows

Ask in one batch, and only for what the current state does not already answer:

- APIs to broker: one host per API, and how each authenticates (header name and prefix, or a placeholder token the client already sends).
- Credential provider: 1Password service account, Bitwarden machine account, or an OAuth2 client.
- Secret reference for each host.
- How postern should stay running: this session only, a systemd unit, a macOS LaunchAgent, or Docker Compose.
- Whether the agent process can be restarted after setup, because its environment must change.

Setup cannot finish without a provider and one secret reference per brokered host, or four for an OAuth 1.0a rule.
Postern cannot broker credentials without a vault or IdP: with neither configured, stop and say so.
Do not guess vault, item, or field names.

## 2. Check current state

```sh
command -v postern && postern --version
id -un
pgrep -af 'postern server'
ls -l ~/.postern/config.yaml ~/.postern/ca.pem 2>/dev/null
test -w ~/.postern && echo writable || echo not-writable
```

If `~/.postern` does not exist, the later commands create it.
If it is not writable, or the agent runs under a different uid than postern, hand the write and permission steps to the user and wait.
Confirm the platform is Linux or macOS before installing anything.

## 3. Install the binary

Skip this step when `postern --version` works.

```sh
curl -fsSL https://raw.githubusercontent.com/mmartinez/postern/main/install.sh | sh
```

The default target is `/usr/local/bin`, which needs sudo, so give the user that command to run.
Without sudo:

```sh
curl -fsSL https://raw.githubusercontent.com/mmartinez/postern/main/install.sh | POSTERN_INSTALL_DIR="$HOME/.local/bin" sh
```

Pin a release with `POSTERN_VERSION=<tag>`, for example `POSTERN_VERSION=v0.11.0`.
Afterwards confirm `command -v postern` and add the install directory to `PATH` if needed.
A source checkout builds with `make build` and writes `dist/postern`.

## 4. Install the CA

```sh
postern ca install
```

- Generates `~/.postern/ca.pem` and `ca.key` (0600) when absent, and reuses an existing CA.
- macOS: also trusts it in the login keychain and may show an authorization prompt.
- Linux: does not trust it system-wide.
  Clients that honor `SSL_CERT_FILE` are covered by `postern bootstrap`.
  GUI or system-store-only clients need the distribution steps in `docs/security.md`, run by the user with sudo.
- An agent under a different uid needs a readable copy of the certificate only: copy `ca.pem` (never `ca.key`) to a 0644 path it can read, and point `SSL_CERT_FILE` or `NODE_EXTRA_CA_CERTS` at that copy.
- After the CA is regenerated, re-export the variables; `postern ca uninstall --purge` deletes the files.

## 5. Choose and install the credential source

Use exactly one form: `token:` for a single legacy 1Password store, or `credstores:` for multiple vendors or Bitwarden and OAuth2.
The full grammar is in `references/config.md`.

| Provider | Config | Token | Secret reference |
|---|---|---|---|
| 1Password | `provider: 1password` | service-account token | `op://Vault/Item/field` |
| Bitwarden | `provider: bitwarden` | machine access token | `bw://<secret-uuid>` |
| OAuth2 | `provider: oauth2` plus `settings` | client secret in `token:`; refresh seed in `refresh_token:` for the refresh grant | `oauth2://<credstore-name>` |

- Single 1Password store: the user runs `postern token set --stdin` in their own terminal, or `postern token set --from-env OP_SERVICE_ACCOUNT_TOKEN` when that variable already exists; never print the value.
  Then verify with `postern token status` and `postern token test`.
- Headless or container: set `token.source: file` with a 0600 file readable by the uid that runs postern, or `source: env` with a variable in postern's process environment.
  `auto` tries file, then env, then the keychain.
- Bitwarden needs the `bws` CLI on postern's `PATH`, or `settings.bws_path`; postern does not bundle it.
- OAuth2 requires a registered client and `settings.token_url`, `settings.client_id`, and `settings.grant_type`.

If the token is absent and the user has not supplied one, stop and ask them to install it.
A config that cannot boot is not a finished setup.

## 6. Write the config and rules

If no config exists, run `postern config init`.
It refuses to overwrite without `--force`, and `--force` needs explicit user approval after copying the old file.
If a config already exists, read it first and append rules; never replace existing rules, credstores, or proxy settings without the user's approval.

Read `references/config.md` before editing, then start from a minimal working config:

```yaml
credstores:
  - name: vault
    provider: 1password
    token:
      source: file
      file: /run/secrets/op_token

proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m

rules:
  - template: anthropic
    secret_ref: op://Agents/Anthropic/api_key
```

For every host to broker:

1. Confirm the auth shape (header name and template, or placeholder sentinel).
2. Confirm the secret reference with the user.
3. Append the rule, preferring a built-in template when one fits: `anthropic`, `openai`, `github`, `stripe`, `googleapis`.
4. Run `postern config validate` and fix every error.
5. Run `postern rules list` and check order and fields.

Hot reload applies rule changes to a running server.
Listener, cache, `admin_listen`, token, `on_no_match`, `scrub_responses`, and `max_body_bytes` changes need a restart.
When the user passes `--config PATH`, pass it to every command, including `bootstrap` and `server`.

## 7. Start the proxy

```sh
postern server --log-level info
```

Run it in the foreground first.
Logs are needed to verify injection, and `--daemon` detaches while discarding stdout and stderr, so a daemonized process has no log output at all.

For a lasting setup use systemd, a macOS LaunchAgent, or Docker Compose; the postern repository README has unit and compose examples.
macOS approval requires the login session, meaning a LaunchAgent and not a LaunchDaemon.
Linux approval requires the polkit action plus an authentication agent in the desktop session:

```sh
postern approval policy | sudo tee /usr/share/polkit-1/actions/dev.postern.policy
```

The user runs that as their own user, and only the `sudo tee` half is elevated.
Check `pgrep -af 'postern server'` before starting a second process; only one can bind the listener.

## 8. Wire the agent that will call the APIs

`postern bootstrap` prints exports; it does not change a running process:

```sh
eval "$(postern bootstrap --shell bash)"   # zsh: same; fish: postern bootstrap --shell fish | source
```

- The variables must exist before the agent process starts: shell profile, service unit, container environment, or the client's own proxy setting.
  A running process does not pick them up, so restate this in the final report if the agent cannot be restarted.
- `HTTPS_PROXY` points at `proxy.listen`; `SSL_CERT_FILE` points at `ca.pem`.
  If the server runs with an `--addr` that differs from `proxy.listen`, align the config; bootstrap reads the config.
- Node also needs `NODE_USE_ENV_PROXY=1` (Node 22.21.0+ or 24.5.0+) and `NODE_EXTRA_CA_CERTS="$HOME/.postern/ca.pem"`.
- Clients that set their own proxy agent or `ca` option ignore these variables; configure the client instead.
- If the agent runs in a container or another network namespace, loopback will not reach postern.
  Use the Docker Compose example from the postern repository, or an address both sides can reach, and confirm with the user first: the listener grants access to every brokered rule.
- SDKs that refuse to start without a key accept any dummy value.
  A `type: header` rule overwrites whatever the agent sent; a `placeholder` rule requires the exact configured sentinel.

## 9. Verify end to end

Setup is complete only when a real request, sent through the same wiring the agent will use, returns the endpoint's expected successful authenticated response and the server logs the injection for that same request.
Either signal alone is insufficient: a process check or admin healthcheck proves neither reachability through the proxy nor a working credential, and a successful response without the log line may have bypassed postern.

1. `postern config validate` is clean.
2. `postern rules list` shows each rule in the intended order.
3. Pre-check only: confirm the process exists with `pgrep -af 'postern server'`, and with `proxy.admin_listen` set, `postern server healthcheck --addr 127.0.0.1:1702`.
4. Send one real request the user agrees to, using the environment or client configuration the agent will actually use.
   Pick an endpoint that returns its success response only with a valid credential, usually a list or read call.
   A 401 or 403 means the credential or the wiring is still wrong; it is not acceptance.
   Record both:
   - the endpoint's expected successful status (usually 2xx), and
   - a `broker injected host=<host>` line for that request in the server log.
   If the response succeeds but no injection line appears, the call bypassed postern and nothing is brokered.
5. To test a rule in isolation, copy the config and run a second server on another port with `--config`; never break the live config.
6. If the user declines the live call, report the setup as unverified, with the exact request still to run.
7. Report what changed: files touched, rules added, commands the user ran, and how to undo (remove the rules, `postern ca uninstall --purge`, `postern token rm`).

If any step fails, read `references/troubleshooting.md` before changing the config.
