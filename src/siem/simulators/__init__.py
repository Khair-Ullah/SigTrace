"""Synthetic log traffic generation for demos, training and tests (Phase 9)."""
from siem.simulators.generator import (
    DEFAULT_ATTACKER,
    DEFAULT_VICTIM,
    SCENARIOS,
    LogSimulator,
    SimulatedLog,
    generate_many,
)

__all__ = [
    "LogSimulator",
    "SimulatedLog",
    "generate_many",
    "SCENARIOS",
    "DEFAULT_ATTACKER",
    "DEFAULT_VICTIM",
]
