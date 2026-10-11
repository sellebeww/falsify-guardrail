# Threat model & scope

## What Falsify is
A **defensive evaluation tool**. It measures whether an LLM's smart-contract repair actually
removes a vulnerability, using automated exploits as the oracle. It is used as a CLI/CI
guardrail and as a proof-of-concept benchmark.

## Where exploits run
Bundled tasks and explicitly supplied local contracts run inside a **local Foundry EVM**
(`forge test`) in a disposable directory. Bundled harnesses do not target live contracts.
External harnesses are caller-controlled executable tests: use isolated runners and do not
assume a temporary directory is a sandbox or prevents a malicious harness from using network
or filesystem capabilities provided by the underlying tools. See
[untrusted contract code](#untrusted-contract-code).

## Untrusted contract code

Generated contracts and candidate sources are untrusted. Foundry exposes cheatcodes to every
contract in a test run, not only to the test harness. A contract can call the cheatcode
address itself.

### Secret exfiltration through the environment (mitigated)

A contract could call `vm.envString("SOME_TOKEN")` and revert with the value. Foundry
reports the revert text as the test failure reason. Falsify stored that text in the exploit
result, so the secret reached the JSON artifact that CI uploads. In live benchmark mode, the
model API key was in that environment.

Two independent layers now close this path:

1. **Environment allowlist.** Every forge, Slither and Echidna subprocess receives only
   `PATH`, a disposable per-process `HOME`, and `SOLC_VERSION`
   ([`toolpaths.subprocess_env`](../falsify/toolpaths.py)). Host secrets, model API keys and
   `FOUNDRY_*` configuration (for example `FOUNDRY_FFI=true`) are not inherited. The
   disposable `HOME` also hides host dotfiles and global tool configuration. Generated
   `foundry.toml` files set `ffi = false` and `fs_permissions = []` explicitly.
2. **Output sanitization.** Revert reasons, notes and Echidna output are sanitized before
   they are written to an artifact or printed ([`redact.py`](../falsify/redact.py)). The
   sanitizer redacts host environment values (raw or hex-encoded) and common credential
   formats, strips control characters and bidirectional overrides, and caps length. The
   oracle decides from test status, never from revert text, so sanitization cannot change
   a verdict.

The second layer is best effort. It cannot recognize a secret the contract has transformed,
for example reversed or base64-encoded. The allowlist is the primary control.
`tests/test_integration_secrets.py` runs an exfiltrating contract through `falsify check`
and asserts that the sentinel value appears in neither the artifact nor console output.

### Remaining exposure

- **Network.** Fork cheatcodes such as `vm.createSelectFork(url)` can make outbound requests.
  With the allowlist, a contract has no host secret to send, but it can still signal that
  it ran. Use a runner or container without network access for untrusted sources.
- **Non-secret host details.** `PATH` is passed through and may reveal the host username
  and directory layout.
- **Caller-controlled harnesses.** Tests and exploits supplied with a task run with the same
  capabilities. Review harness changes like code.

### Test-environment detection (open risk)

A contract can detect that it is running under the oracle and behave differently there.
Examples are `block.chainid == 31337` (Foundry's default chain ID), checking for code at the
cheatcode address, or relying on default test values such as `block.timestamp`. Such a
contract could block the supplied exploit during evaluation and remain exploitable on a
real chain. An exploit that fails under these conditions is reported as `UNCONFIRMED`,
consistent with UNCONFIRMED never meaning SECURE. Falsify does not currently detect this
pattern. Review accepted repairs for environment-dependent branches.

## Anti-circularity (why the results mean something)
- The functional tests, invariants, and PoC exploits are **task-owned** and live in the
  benchmark; the model under test never sees them (enforced structurally — see
  [`repair/feedback.py`](../falsify/repair/feedback.py) and its allowlist test).
- The exploit oracle is authored independently of the solution and encodes the *attack*, not
  the defense.
- Repair feedback is minimal by construction: vuln class + Slither text + an "exploit
  confirmed" boolean + failing functional-test names. Never the PoC source or invariants —
  leaking those would train-to-the-test.

## Trust boundaries
- A `CONFIRMED` result means the supplied exploit test passed; its assertions must faithfully
  encode exploitation. A malicious or incorrect harness can invalidate that conclusion.
- An `UNCONFIRMED` result is **not** a safety claim — it means the deterministic PoC library
  did not (yet) demonstrate exploitability. See [limitations.md](limitations.md).
