"""Test helpers shared across suites."""
import time


def wait_for(predicate, timeout: float = 5.0, interval: float = 0.05) -> bool:
    """Poll predicate until it returns True or timeout elapses."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False
