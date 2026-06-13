# Environment injection — `postern exec`

`postern exec` resolves secrets from your vault and exports them as environment
variables into a command it launches:

```sh
postern exec -- node server.js
```

It is the companion to the proxy. The proxy brokers credentials at the network
layer so an agent never holds them; `postern exec` is the fallback for the
things the proxy **cannot** intercept — a database driver, `git` over SSH, a CLI
that reads its credential from `$ENV`.

## The trade-off — read this first

The proxy's whole point is that the agent never sees the credential. **Environment
injection gives the secret to the launched process.** Once a value is an
environment variable, the process holds it for its lifetime — a strictly weaker
posture than brokering.

So the rule of thumb is:

> If the thing speaks HTTPS, route it through `postern server`. Use `postern
> exec` only for protocols and tools the proxy can't reach.

For a workload that does both (most do), run **both**: the proxy for the HTTPS
APIs, and `postern exec` for the residue (the DB URL, SSH-based git, env-reading
CLIs).

## Declaring secrets: the `env:` block

Add an `env:` block to your config. Each value is a `secret_ref` — the same
`op://…` / `bw://…` reference the rules use — and each key is the
environment-variable name the resolved value is exported under:

```yaml
credstores:
  - name: vault
    provider: 1password               # or: bitwarden
    token:
      source: env
      env_var: OP_SERVICE_ACCOUNT_TOKEN

proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m

env:
  DATABASE_URL: op://Infra/droplet-db/url
  STRIPE_SECRET_KEY: op://Infra/stripe/secret_key
```

`postern config validate` checks the block with line numbers: every key must be
a valid environment-variable name, every value a routable `<scheme>://<rest>`
reference whose scheme a configured credstore resolves.

Then launch your command after `--`:

```sh
postern exec -- node server.js
postern exec --config /etc/postern/config.yaml -- ./run-migrations.sh
```

`postern` resolves each `env:` entry, adds it to the environment (a config entry
overrides an inherited variable of the same name), and **replaces itself** with
the command via `exec(2)`. The command becomes the same process — signals, the
PID, and the exit status all flow straight to it, which is the right shape under
a process manager and the devcontainer CLI.

## Inline scanning: `--scan`

With `--scan`, postern also resolves **inherited** environment variables whose
value is itself a secret reference, replacing each in place:

```sh
DATABASE_URL=op://Infra/droplet-db/url postern exec --scan -- node server.js
```

Only values whose scheme has a configured credstore are touched; everything else
(`https://…` URLs, plain connection strings) passes through unchanged. A config
`env:` entry of the same name always wins over a scanned value. `--scan` works
with or without an `env:` block.

## What it guarantees

- **Fails closed.** If any secret fails to resolve, the command is **never
  launched** — a partially-resolved environment is worse than not running. This
  mirrors the proxy's fail-closed `502`.
- **Rejects non-cacheable refs.** A short-lived reference (e.g. an OTP) can't
  survive an exec-and-replace, so it's rejected up front. Use the proxy for those.
- **Never logs secret values.** Resolved values appear in logs only as a masked
  `first4…last4` fingerprint, never in the clear.
- **Child-only.** The resolved values go to the launched process. Postern does
  not export them to your shell, and never writes them to disk.

## Deployment recipes

No cluster required — these are single-host patterns (a droplet, a VM, a laptop).

### systemd service

Deliver the vault token with systemd's credential store, and resolve the
workload's secrets fresh on every start:

```ini
[Service]
ExecStart=/usr/local/bin/postern exec --config /etc/postern/config.yaml -- /usr/local/bin/myapp
LoadCredential=op_token:/etc/postern/op_token
```

Set `token.source: file` and `token.file:
/run/credentials/myapp.service/op_token` in the config. The service's main PID
becomes `myapp`, so `systemctl status`, restarts, and signals all behave
normally — and no plaintext `.env` file ever sits on disk.

### Docker Compose

Bake the postern binary into the image and make it the entrypoint:

```yaml
services:
  app:
    image: myapp
    entrypoint: ["postern", "exec", "--", "myapp"]
    volumes:
      - ./config.yaml:/etc/postern/config.yaml:ro
    secrets:
      - op_token        # the vault token, the only secret on disk (0600)
```

### Dev container over SSH

On the remote host, wrap the devcontainer CLI:

```sh
postern exec -- devcontainer up --workspace-folder .
```

postern resolves the `env:` block into the devcontainer CLI's environment; the
CLI forwards those into the container through its normal env-forwarding, e.g. in
`devcontainer.json`:

```json
{
  "remoteEnv": { "DATABASE_URL": "${localEnv:DATABASE_URL}" }
}
```

For the strongest posture, also run `postern server` inside the container and
point `HTTPS_PROXY` at it, so HTTPS APIs stay brokered and `exec` only carries
the non-HTTP residue.

## Limitations

- `postern exec` replaces the process with `exec(2)`, so it is supported on Linux
  and macOS only. On other platforms, use a process manager to inject the
  environment instead.
- It does **not** broker the SSH protocol itself. It can place a credential a
  tool reads from `$ENV`, but it cannot keep an SSH **private key** out of the
  container — that would be a separate SSH-agent / certificate-signing feature.
