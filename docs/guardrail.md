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

### Controls: proving the exploit can fire

A failing exploit only means something if the exploit could have succeeded. A harness with a
broken `setUp`, a stale interface or a wrong assertion would report every candidate as "not
exploited". Declare controls, sources whose outcome is known, to rule that out:

```json
"controls": {
  "exploitable": ["controls/Vault_vulnerable.sol"],
  "safe": ["controls/Vault_fixed.sol"]
}
```

Paths are relative to the task directory. `falsify validate-task --task DIR` requires:

- every exploit succeeds on at least one exploitable control,
- no exploit succeeds on a safe control,
- the functional suite passes on every control.

Without a `controls` block, fixture roles are used: `initial` and `bad_fix` are exploitable,
`good_fix` is safe. A task whose initial contract is safe must declare `controls`
explicitly. Run validation whenever the harness changes; CI runs it for every bundled task.

`falsify check` runs the exploits on the exploitable controls before it evaluates the
candidate. If any exploit fails to fire there, the result is `TOOL_ERROR` and the gate
blocks: a dead harness can no longer pass every candidate. A task without an exploitable
control still runs, and the artifact notes that liveness is unverified.

### Strict mode

By default `ORACLE_GAP` passes with a caveat: a detector flagged something that no supplied
exploit confirmed. `falsify check --strict` blocks in two more cases:

- detector findings remain unconfirmed (`ORACLE_GAP`),
- the task declares no exploitable control, so exploit liveness is unverified.

The verdict is unchanged; `gate_pass` becomes false and a `strict:` note explains why.
Use strict mode when unexplained detector findings should be reviewed by a person before
merging.

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
