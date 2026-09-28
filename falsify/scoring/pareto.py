"""Pareto frontier: security (confirmed) vs gas efficiency (plan §7 scoring).

Valid only when models are compared on an identical task set. MVP has one model, so
this mainly supports v0.2 benchmark mode; it is kept generic and tested in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ParetoPoint:
    label: str
    security: float  # higher is better (e.g. fraction of confirmed exploits neutralized)
    gas: float       # lower is better (e.g. gas tax)


def frontier(points: list[ParetoPoint]) -> list[ParetoPoint]:
    """Return the non-dominated points (maximize security, minimize gas).

    A point is dominated if another is at least as good on both axes and strictly
    better on one.
    """

    def dominated(p: ParetoPoint) -> bool:
        for q in points:
            if q is p:
                continue
            if q.security >= p.security and q.gas <= p.gas and (
                q.security > p.security or q.gas < p.gas
            ):
                return True
        return False

    nd = [p for p in points if not dominated(p)]
    return sorted(nd, key=lambda p: (p.gas, -p.security))
