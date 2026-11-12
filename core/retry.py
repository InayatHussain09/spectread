"""
SpectreAD :: core/retry.py
Retry, backoff, transport fallback.

Author : Inayat Hussain
"""

from __future__ import annotations

import functools
import random
import time

from core import ui


def retry(times: int = 3, backoff: float = 1.5, quiet: bool = False):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **k):
            delay, last = 0.5, None
            for attempt in range(1, times + 1):
                try:
                    return fn(*a, **k)
                except Exception as exc:
                    last = exc
                    if attempt == times:
                        break
                    if not quiet:
                        ui.warn(f"{fn.__name__} {attempt}/{times}: {exc}")
                    time.sleep(delay + random.uniform(0, 0.3))
                    delay *= backoff
            raise last
        return wrapper
    return deco


def with_fallback(*transports):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **k):
            last = None
            for t in transports:
                try:
                    return fn(t, *a, **k)
                except Exception as exc:
                    last = exc
                    ui.info(f"{t} failed, trying next")
            raise last
        return wrapper
    return deco
