# Security Policy

Woland Guard is a defensive monitoring MVP for servers the operator owns or has explicit
permission to monitor. It is not hardened for multi-tenant or adversarial-input production use
without additional review — see [Ограничения MVP](README.md#ограничения-mvp) and
[docs/threat-model.md](docs/threat-model.md) before relying on it.

## Supported versions

The project has no tagged releases yet; only the `main`/`master` branch is maintained. Security
fixes land there.

## Reporting a vulnerability

Do not open a public GitHub issue for a suspected vulnerability. Use GitHub's private
vulnerability reporting (**Security → Report a vulnerability** on the repository) once the
project is hosted on GitHub. Include:

- affected component (`apps/agent`, `apps/control-plane`, `packages/contracts`, `scripts/demo_e2e`);
- reproduction steps or a minimal PoC;
- observed vs. expected behaviour;
- whether the issue requires authenticated access (agent API key, operator API key/session) or
  is reachable from an unauthenticated endpoint.

Please do not include real credentials, real server hostnames/IPs, or real log data in a report —
use synthetic values, consistent with how this repository itself is required to stay free of
real secrets and personal data.

## Scope

In scope:

- the Linux agent (`apps/agent`);
- the control plane API, detection engine, outbox worker and Dashboard
  (`apps/control-plane`);
- the shared event contract (`packages/contracts`);
- the Docker Compose deployment definitions (`compose.yaml`, `deploy/`);
- the 8B demo/verification tooling (`scripts/demo_e2e`), to the extent a flaw there could mask a
  real defect in the components above.

Out of scope:

- vulnerabilities that require the reporter to already control an agent's private key, an
  operator's credentials, or the PostgreSQL superuser — the threat model treats those as already
  compromised;
- findings against third-party dependencies without a demonstrated, project-specific impact
  (report those upstream; `dependency-audit` in CI already tracks known CVEs against the locked
  dependency set);
- the demo/synthetic data generators when used exactly as documented (they intentionally emit
  attack-shaped synthetic traffic against a loopback-only target).

## Known, already-documented limitations

The project tracks its own security-relevant limitations explicitly rather than hiding them:

- README's [Ограничения MVP](README.md#ограничения-mvp) section;
- [docs/threat-model.md](docs/threat-model.md);
- each `docs/adr/*.md` entry ends with an "Ограничения"/"Последствия" section describing what a
  given stage does *not* guarantee.

If your report matches an already-documented limitation, it is still useful to report — it helps
confirm real-world impact — but it will likely be triaged as a known gap rather than a new
finding.

## Disclosure

There is no bug bounty. Reporters will be credited in the fix's changelog entry unless they ask
to remain anonymous. Please allow a reasonable time to investigate and ship a fix before any
public disclosure.
