# Changelog

## Unreleased

### Security

- Tool subprocesses (forge, Slither, Echidna) receive an allowlisted environment: `PATH`, a
  disposable per-process `HOME` and `SOLC_VERSION`. Previously a contract under test could
  read any host variable, including model API keys, through Foundry cheatcodes, and the
  value reached the JSON artifact through its revert reason. `FOUNDRY_*` configuration from
  the host no longer applies.
- Generated `foundry.toml` files set `ffi = false` and `fs_permissions = []` explicitly.
- Revert reasons, notes and Echidna output are sanitized before they are persisted or shown:
  host secret values (raw or hex), common credential formats, control characters and
  bidirectional overrides are removed, and length is capped.

### Added

- Harness controls and `falsify validate-task`: every exploit must succeed on a
  known-exploitable control, none on a known-safe control, and the functional suite must
  pass on all controls. All bundled tasks validate; the guarded reentrancy task gains an
  unguarded control.
- `falsify check` runs exploits on exploitable controls first and blocks with `TOOL_ERROR`
  when the harness cannot fire. `--strict` also blocks `ORACLE_GAP` and tasks without an
  exploitable control.
- `falsify check --sarif` (SARIF 2.1.0) and `--summary` (Markdown, e.g. for
  `$GITHUB_STEP_SUMMARY`), and `falsify --version`.
- Action inputs `strict`, `sarif` and `job-summary`; the compiler version is derived from the
  task's `solc_pragma` unless `solc-version` overrides it.
- Live campaigns: `--record` and `--replay` JSONL transcripts for offline, credential-free
  re-evaluation; opt-in retries (`max_retries`) for rate limits and transient errors.
- `falsify bench --jobs N` runs independent combinations in parallel with results in serial
  order (54 s to 21 s for the fixture benchmark on an 8-core machine).

### Changed

- The Action pins `setup-python` and `foundry-toolchain` to commit SHAs; CI pins
  `foundry-toolchain`.
- Foundry fuzz and invariant tests in a harness use a fixed seed (`0x1337`).
- solc artifacts are located the same way for forge, Slither and Echidna, removing a mismatch
  between `~/.solc-select` and `$VIRTUAL_ENV/.solc-select`.
- Comments and docstrings no longer cite sections of an unpublished planning document.
