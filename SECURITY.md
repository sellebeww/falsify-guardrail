# Security policy

## Reporting a vulnerability

Report vulnerabilities in Falsify itself privately through
[GitHub security advisories](https://github.com/sellebeww/falsify-guardrail/security/advisories/new).
Please do not open a public issue. Include the Falsify commit, tool versions (`make versions`),
and a minimal reproduction. Only the latest commit on `main` is supported.

In scope:

- a contract under test, or a candidate source, reading host secrets or files, or escaping
  the disposable project in a way the [threat model](docs/threat-model.md) says is prevented,
- secrets or untrusted control characters reaching an artifact, report, SARIF file or job
  summary,
- a candidate passing the guardrail although a supplied exploit succeeds against it, or
  although the harness cannot fire,
- injection through action inputs or task metadata.

Out of scope:

- exploits the supplied harness does not encode. An `UNCONFIRMED` result is never a safety
  claim,
- malicious task harnesses. Harnesses are trusted executable code; review them like code,
- network access from tests. Run untrusted sources on runners without network access.

## Using Falsify safely

- Treat generated and candidate contracts as untrusted. Tool subprocesses receive an
  allowlisted environment, but run campaigns on isolated runners anyway.
- Pin this action to a full commit SHA, and protect task harnesses from unreviewed changes.
- Validate a harness with `falsify validate-task` whenever it changes.
- Keep model credentials in environment variables named by `api_key_env`, never in
  configuration files or transcripts.
