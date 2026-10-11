# Benchmark protocol

`falsify bench` defaults to fixtures. `--models FILE` selects real HTTP generation for every
configured model on every discovered task. `--jobs N` runs independent task/model/repetition
combinations in parallel; runs are reported in the same order as a serial campaign, and
replays stay exact because transcripts are keyed by task and repetition. Mind provider rate
limits when parallelizing live requests. `--repetitions N` creates fresh generators for
independent runs; `--max-iterations N` bounds repair calls. Maximum requests are
`tasks × models × repetitions × (1 + max_iterations) × (1 + max_retries)`; early stopping
can reduce this.
`max_tokens` bounds requested output tokens, not monetary cost. Provider billing includes
input and may include other tokens; determine a budget before running remote endpoints.

Use the schema in `examples/models.json`. Each entry has a unique reporting `name`, provider
`model` ID, full `endpoint`, optional `api_key_env`, `max_tokens`, `temperature`, `timeout`
seconds, and optional `max_retries` (default 0) with `retry_backoff` seconds. Local vLLM and compatible chat-completions servers can be used without changing the
loop. Remote endpoints require HTTPS; HTTP is allowed on loopback. Redirects are rejected.
Configuration contains credential variable names only. No credentials or HTTP error bodies
are included in reports. HTTP errors, missing credentials and truncated output do not become
successful Solidity generations. Retries are off unless a model sets `max_retries` (at
most 10). Only HTTP 408/429/5xx responses, connection failures and timeouts are retried,
with exponential backoff that honors `Retry-After` (capped at 60 seconds). Client errors
and truncated output are never retried. Each model call records its number of attempts.

## Recording and replaying a campaign

`--record transcript.jsonl` appends every model exchange of a live `bench` or `run` to a
JSON Lines transcript. `--replay transcript.jsonl` re-runs the campaign from it with no
network access and no credentials, for example after a change to the oracle, a task harness
or the scoring. Entries are keyed by model name, task, repetition and the exact prompts. Repair prompts embed
the previous response, so a replay follows the recorded conversation. Responses for an
identical prompt are consumed in recording order, so each repetition replays its own
responses. If a prompt has no remaining recorded response, because the specification or
loop changed, that run becomes a blocked `TOOL_ERROR` instead of an empty generation.
Replayed calls are marked `"replayed": true` and keep the recorded usage. Transcripts hold
prompts and responses, never credentials; keep them with the published results.

The model receives the same task specification and version constraints. Fixed supporting
interfaces must be described in `spec.md`; the model repairs only the entry source. Task-owned
support files are restored for each candidate. Functional, exploit and property files are
never sent to the endpoint. Repair feedback includes only test names and minimal findings.

Artifacts identify fixture/live mode, model configurations, repetition, tool versions, source
hashes and complete source bundles, model-call usage metadata, findings, per-attempt outcomes,
functional coverage and gas. Each completed run is
checkpointed; a process interruption may lose the current run. Provider errors are recorded
as blocked tool errors; the benchmark exits nonzero when these occur. Exact model inference
is not reproducible merely because temperature is zero. Preserve the endpoint deployment and
provider revision separately for any publishable experiment.

The confusion summary deduplicates `(task_id, source_hash)` and excludes unevaluated states.
It measures detector/exploit agreement for supplied harnesses, not universal ground truth.
The legacy `fp` and `tn` labels indicate no supplied exploit succeeded. Report denominators,
failed runs and every model, not only accepted fixes. Distinguish initial-generation quality
from conditional repair success. Fixture Pareto calculations are omitted for live mode,
where generated initial contracts differ across models.

Before a research claim: expand task provenance and pattern diversity, preregister sampling
and hypotheses, hold out private tasks, budget repeated model runs, manually adjudicate
unconfirmed findings, and use an appropriate uncertainty analysis. None of that is implied
by the bundled eight-task demonstration.

Transport reference: [vLLM compatible server documentation](https://docs.vllm.ai/en/latest/serving/openai_compatible_server/).
