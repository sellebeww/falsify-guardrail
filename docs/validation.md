# Validation record

Local verification on 2026-10-11, macOS, Python 3.11.9, Foundry 1.8.3,
Slither 0.11.6, Echidna 2.3.3, and solc 0.8.20/0.8.24.

## Executed

- Full Python suite: **133 passed** (102 unit tests and 31 real-toolchain integration
  tests). Includes the earlier regressions plus:
  - an exfiltrating contract (`vm.envString` reverting with a sentinel) run through
    `falsify check`; the sentinel appears in neither the artifact nor console output,
  - harness validation of every bundled task, and a deliberately dead exploit that is
    reported invalid and makes `falsify check` block instead of passing,
  - SARIF and Markdown outputs, strict mode, record/replay transcripts (including parallel
    replay), opt-in retries against a loopback server, and parallel benchmark ordering.
- The integration suite passed both with `VIRTUAL_ENV` set and unset, which covers the two
  locations solc-select uses for compiler artifacts.
- With the old environment-copying behavior restored in memory only, the output sanitizer
  alone still replaced the sentinel with `[redacted:FALSIFY_TEST_SECRET]`.
- `falsify validate-task --all`: all eight tasks valid. Every exploit succeeded on its
  exploitable controls and on none of the safe controls, and functional suites passed on
  every control.
- `falsify bench`: 24 fixture runs. `proper_fixer` and `eventually_fixer` repaired all seven
  vulnerable tasks; `detector_gamer` repaired none and was blocked on all seven. Confusion
  over 22 distinct states: TP 6, FP 1, FN 8, TN 7. `--jobs 8` produced identical confusion,
  per-run and per-strategy results in 21 s instead of 54 s.
- `falsify check --strict` on every task's safe reference: the seven fixes passed; the
  guarded vault (`ORACLE_GAP`) was blocked, as specified.
- Echidna: initial vulnerable references falsified in all seven vulnerable tasks; fixes and
  the guarded reference held for 5,000 tests with seed 1337. These are bounded campaigns,
  not proofs.
- `make demo`: the assembly repair is rejected as a detector-silenced false fix in iteration
  1 and the checks-effects-interactions repair is accepted in iteration 2.
- `ruff check falsify tests`; YAML parsing and `bash -n` of both action steps; solc
  derivation from task pragmas (0.8.24 and 0.8.20).

JSON run artifacts are generated under ignored `results/`; they are local evidence and are
not bundled into the source commit. Re-run the commands to reproduce case observations.

## Not executed / not claimed

- **Real external model inference:** no chosen endpoint/model credentials or live-call budget
  were supplied. HTTP, retry and transcript tests use a loopback mock. They validate the
  adapter and campaign wiring, not provider compatibility, model quality or a live
  multi-model comparison.
- **Hosted GitHub Actions:** the changed composite action and CI jobs were validated locally
  (YAML, shell syntax, the CLI paths they call). No hosted run is claimed until the commits
  are published.
- **Docker runtime:** Docker is unavailable locally; the hosted Docker job remains the check.
- **Linux tool environment:** the minimal subprocess environment was verified on macOS.
  CI on Ubuntu exercises it once the commits are published.
- **Research validity:** eight hand-curated cases do not justify statistical significance,
  general model rankings, exhaustive vulnerability coverage, or production-readiness claims.
