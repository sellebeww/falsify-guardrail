"""Unit tests for the scoring modules (pure, fast)."""

from __future__ import annotations

from falsify.scoring.pareto import ParetoPoint, frontier


def test_pareto_frontier_drops_dominated_points():
    pts = [
        ParetoPoint("A", security=1.0, gas=100),   # best security, cheap
        ParetoPoint("B", security=1.0, gas=200),   # dominated by A (same sec, more gas)
        ParetoPoint("C", security=0.5, gas=50),    # cheaper but less secure -> non-dominated
        ParetoPoint("D", security=0.4, gas=60),    # dominated by C
    ]
    labels = {p.label for p in frontier(pts)}
    assert labels == {"A", "C"}


def test_pareto_single_point_is_its_own_frontier():
    p = ParetoPoint("only", security=1.0, gas=42)
    assert frontier([p]) == [p]
