# Validation record

Local verification on 2026-09-29, macOS, Python 3.11.9, Foundry 1.8.3,
Slither 0.11.6, Echidna 2.3.3, and solc 0.8.20/0.8.24.

## Executed

- Full Python suite: **69 passed** (49 unit/HTTP tests and 20 real-toolchain integration
  tests). Includes unit regressions, real loopback HTTP serialization, repeated
  two-model mock campaigns, real Foundry/Slither loops, all reference functional suites,
  line/function coverage, external-source CLI gate checks, and all eight Echidna campaigns.
- `falsify bench --out results/benchmark-expanded.json`: 24 fixture runs, eight tasks,
  three scripted strategies. `proper_fixer` and `eventually_fixer` repaired all seven
  vulnerable tasks; `detector_gamer` repaired none and was blocked on all seven.
- Observed states: 22 distinct task/source pairs. Slither flagged six exploited states and
  one unconfirmed state; it did not flag eight exploited states and seven unconfirmed states.
  These counts describe supplied harness outcomes, not statistical performance or safety.
- Echidna: initial vulnerable references falsified in all seven vulnerable tasks; corresponding
  fixes held for 5,000 tests with seed 1337. The guarded reference also held. These are bounded
  property campaigns, not proofs.
- `ruff check falsify tests`, `git diff --check`, shell syntax check, and YAML parsing for
  `action.yml` and the CI workflow.
- Wheel build; both Apache-2.0 and MIT license texts are included in package metadata.
  Installed the wheel into a separate virtualenv and ran `falsify check` from outside the
  checkout using the existing toolchain: fixed reference passed with 8/9 lines and 2/3
  functions covered. Without Slither/solc on PATH, the smoke run correctly blocked.
- GitHub CLI scope removal completed and verified: `delete_repo` is absent.

JSON run artifacts are generated under ignored `results/`; they are local evidence and are
not bundled into the source commit. Re-run the commands to reproduce case observations.

## Not executed / not claimed

- **Real external model inference:** no chosen endpoint/model credentials or live-call budget
  were supplied. HTTP tests use a loopback mock. They validate the network adapter and campaign
  wiring, not provider compatibility, model quality or a live multi-model comparison.
- **Hosted GitHub Actions:** the composite action and positive/negative CI job are implemented,
  with local CLI and installation checks. A hosted run requires publishing the commit. No
  hosted success is claimed from YAML validation.
- **Docker runtime:** Docker is unavailable locally. Its build definition was updated to copy
  the license and install both compiler pins; the existing hosted Docker job remains the check.
- **Research validity:** eight hand-curated cases do not justify statistical significance,
  general model rankings, exhaustive vulnerability coverage, or production-readiness claims.
