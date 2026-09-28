"""Human-readable run report (plan §9). The JSON artifact remains the source of truth."""

from __future__ import annotations

from falsify.types import EvalRecord, FindingStatus, Severity

_CAVEAT = "UNCONFIRMED != SECURE — the oracle's PoC library is partial (docs/limitations.md)."


def render_record(record: EvalRecord) -> str:
    max_severity = max(
        (f.severity for f in record.findings), key=lambda s: s.rank, default=Severity.INFO
    ).value
    confirmed = sum(1 for f in record.findings if f.status is FindingStatus.CONFIRMED)
    unconf = sum(1 for f in record.findings if f.status is FindingStatus.UNCONFIRMED)
    oos = sum(1 for f in record.findings if f.status is FindingStatus.OUT_OF_SCOPE)

    lines = [
        f"Falsify — task {record.task_id} ({record.category.value})   model={record.model}",
        f"Verdict: {record.verdict.value.upper()}     Gate: {'PASS' if record.gate_pass else 'BLOCK'}",
        (
            f"Findings: {confirmed} confirmed, {unconf} unconfirmed, {oos} out-of-scope"
            f"   (max severity: {max_severity})"
        ),
        f"False fixes caught (detector-silenced, RQ1): {record.false_fixes}",
        f"Gas tax total of accepted repairs (RQ3): {record.gas_tax_total():+d}",
    ]
    gas_deltas = {k: v for k, v in record.gas_final.delta(record.gas_baseline).items() if v}
    if gas_deltas:
        lines.append(
            "  gas Δ by function: "
            + ", ".join(f"{sig} {v:+d}" for sig, v in sorted(gas_deltas.items()))
        )
    if record.repairs:
        lines.append("Repair iterations:")
        for a in record.repairs:
            fates = ", ".join(f"{fid.split(':')[1] if ':' in fid else fid}={fate.value}"
                              for fid, fate in a.fates.items()) or "-"
            reason = a.reason.value if a.reason else "-"
            lines.append(
                f"  #{a.iteration}  {a.outcome.value:<8}  {reason:<22}"
                f"  gasΔ={a.gas_delta_total:+d}  fates: {fates}"
            )
    if record.notes:
        lines.append("Notes:")
        lines += [f"  - {n}" for n in record.notes]
    lines.append(f"\n{_CAVEAT}")
    return "\n".join(lines)


def render_benchmark(result) -> str:
    """Render a BenchmarkResult (duck-typed to avoid an import cycle)."""
    c = result.confusion()
    n_states = c.tp + c.fp + c.fn + c.tn
    tasks = sorted({r.task_id for r in result.runs})
    strategies = sorted({r.strategy for r in result.runs})

    lines = [
        (
            f"Falsify benchmark — {len(result.runs)} runs "
            f"({len(tasks)} tasks × {len(strategies)} strategies)"
        ),
        "",
        (
            f"Ground truth (exploit oracle) vs a Slither-only gate, over {n_states} distinct "
            "contract states:"
        ),
        "",
        "                    exploitable      safe",
        f"  Slither flags        TP={c.tp:<3}        FP={c.fp:<3}   <- FP = RQ2 false positives",
        f"  Slither clean        FN={c.fn:<3}        TN={c.tn:<3}   <- FN = RQ1 false fixes",
        "",
        f"  A Slither-only gate would APPROVE {c.fn} still-exploitable contract(s) (RQ1),",
        f"  and BLOCK {c.fp} provably-safe contract(s) (RQ2). Falsify's oracle gets both right.",
        "",
        "Per strategy (model):",
    ]
    for strat, s in sorted(result.per_strategy().items()):
        lines.append(
            f"  {strat:<18} runs={s['runs']}  real-fixes={s['success']}  "
            f"blocked={s['blocked']}  false-fixes-caught={s['false_fixes']}"
        )

    lines.append("")
    lines.append("Pareto frontier (security vs gas) per category:")
    for cat, points in sorted(result.pareto_by_category().items()):
        pretty = ", ".join(f"{p.label}(sec={p.security:.2f}, gas={p.gas:+.0f})" for p in points)
        lines.append(f"  {cat}: {pretty}")

    lines.append(f"\n{_CAVEAT}")
    return "\n".join(lines)
