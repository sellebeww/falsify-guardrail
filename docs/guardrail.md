# External repository guardrail

The public entry point is `falsify check`, also used by root `action.yml`. It reads an existing
source and never repairs it. The caller supplies a trusted task directory:

```text
security/vault/
  task.json
  spec.md
  tests/Functional.t.sol
  exploits/Reentrancy.t.sol
  support/Ledger.sol             # optional fixed imports
```

Minimal `task.json`:

```json
{
  "id": "my-vault",
  "category": "reentrancy",
  "contract_name": "Vault",
  "solc_pragma": "^0.8.24",
  "spec_file": "spec.md"
}
```

`roles` is only required for fixture benchmarks, not `check`. Tests import the entry source as
`../src/Vault.sol`. An exploit test must **pass when exploitation succeeds** and fail when the
attack fails. Functional tests use ordinary pass-on-correct-behavior assertions. Empty or
unbuildable suites block. Candidate source must keep the harness-compatible interface;
changing it to make the exploit fail compilation is never an accepted repair.

`--source-root` replaces task support sources with the `.sol` files under the provided root,
excluding the entry. Relative paths are preserved and traversal/collisions rejected. Put the
entry directly under that directory. Dependency packages and remappings are not resolved.

The composite Action installs the toolchain on the caller's runner and invokes the same CLI.
Inputs are passed as environment variables and quoted shell arguments. It needs no API key
and no repository-write permission. The caller checks out its own repository, chooses the
trusted task, pins the Falsify commit, and uploads the JSON artifact using `if: always()`.
The action does not modify or publish candidate sources. Use an isolated Ubuntu runner for
untrusted pull requests and protect the task harness from unreviewed changes.

The action can be referenced from other repositories once the commit containing it is
published. The local CI workflow exercises both a passing fixed contract and a blocked
vulnerable contract through the action itself. A local CLI pass is not evidence of a hosted
GitHub Actions run; see the validation record for what was actually executed.

Reference: [GitHub composite actions](https://docs.github.com/en/actions/tutorials/create-actions/create-a-composite-action).
