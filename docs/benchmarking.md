# Benchmark protocol

`falsify bench` defaults to fixtures. `--models FILE` selects real HTTP generation for every
configured model on every discovered task. `--repetitions N` creates fresh generators for
independent runs; `--max-iterations N` bounds repair calls. Maximum requests are
`tasks × models × repetitions × (1 + max_iterations)`; early stopping can reduce this.
`max_tokens` bounds requested output tokens, not monetary cost. Provider billing includes
input and may include other tokens; determine a budget before running remote endpoints.

Use the schema in `examples/models.json`. Each entry has a unique reporting `name`, provider
`model` ID, full `endpoint`, optional `api_key_env`, `max_tokens`, `temperature`, and `timeout`
seconds. Local vLLM and compatible chat-completions servers can be used without changing the
loop. Remote endpoints require HTTPS; HTTP is allowed on loopback. Redirects are rejected.
Configuration contains credential variable names only. No credentials or HTTP error bodies
are included in reports. HTTP errors, missing credentials and truncated output do not become
successful Solidity generations. No automatic retries consume unbounded extra calls.

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
