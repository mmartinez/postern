# Security Policy

Postern brokers live credentials, so we take security reports seriously. This
policy covers how to report a vulnerability in postern itself. For how postern
defends the credentials it brokers (fail-closed semantics, logging redaction,
threat model, key handling), see [docs/security.md](docs/security.md).

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report it privately through GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability):
open the repository's **Security** tab and choose **Report a vulnerability**.
That opens a private advisory visible only to you and the maintainers.

Please include:

- The affected version or commit (`postern --version`).
- A description of the issue and its impact.
- Steps to reproduce, or a proof of concept, if you have one.
- Any suggested remediation.

Because postern handles secrets, **never include a real credential** in a
report. Redact tokens to a `first4…last4` form, the way postern masks them in
its own output.

## What to expect

- **Acknowledgement** within 5 business days.
- An initial assessment (severity, affected versions) once the report is
  triaged.
- Coordinated disclosure: we agree a timeline with you, fix the issue in a
  private advisory, and credit you in the published advisory unless you prefer
  to remain anonymous.

## Supported versions

Postern is pre-1.0 and ships from a single release line. Security fixes land on
the latest released version; please upgrade and confirm the issue still
reproduces before reporting.

| Version | Supported |
| --- | --- |
| Latest release | ✅ |
| Older releases | ❌ |

## Scope

In scope: the postern proxy, broker, credential providers, CLI, and the release
artifacts (binaries, container image) we publish.

Out of scope — these are documented design limits, see the
[threat model](docs/security.md#threat-model): a compromised postern process
holding live credentials in memory, a stolen CA private key, and egress control
beyond what `on_no_match` provides. Third-party credential vendors and the
external CLIs postern shells out to have their own disclosure channels.
