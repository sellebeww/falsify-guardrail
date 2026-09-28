"""Loop configuration (plan §3 stopping conditions)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LoopConfig:
    max_iterations: int = 5          # N: hard iteration budget
    stagnation_patience: int = 2     # k: reject iters with no reduction in confirmed set -> stop
    compile_fail_streak: int = 3     # m: consecutive non-compiling repairs -> abort
