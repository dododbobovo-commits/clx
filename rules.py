# rules.py
"""
rules.py — свод правил для Collatz-блокчейна.

Здесь хранятся:
- уровни "подозрительности" орбит по количеству шагов,
- жёсткий лимит шагов,
- базовые параметры,
- функции-классификаторы.
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum, auto


class SuspicionLevel(Enum):
    """Уровень "подозрительности" орбиты по количеству шагов."""
    NORMAL = auto()             # Нормальное число
    LOW_SUSPICIOUS = auto()     # Немного подозрительное
    MEDIUM_SUSPICIOUS = auto()  # Средне подозрительное
    HIGH_SUSPICIOUS = auto()    # Сильно подозрительное
    EXTREME_SUSPICIOUS = auto() # Суперподозрительное


class BlockStatus(Enum):
    """
    Статус блока:
    - COMPLETED: орбита дошла до 1
    - SUSPECTED_INFINITE: очень длинная, но дошла до 1 (подозрительно)
    - FORCED_STOP: обрубили по лимиту шагов
    """
    COMPLETED = auto()
    SUSPECTED_INFINITE = auto()
    FORCED_STOP = auto()


@dataclass
class OrbitRules:
    """
    Пороговые значения для количества шагов.
    Ты можешь потом спокойно их подправить — всё в одном месте.
    """
    normal_max_steps: int = 100_000
    low_suspicious_max: int = 1_000_000
    medium_suspicious_max: int = 10_000_000
    high_suspicious_max: int = 100_000_000

    # Жёсткий технический лимит шагов — защита от зависания
    hard_step_limit: int = 1_000_000_000

    # Порог, после которого орбита становится кандидатом
    # на "подозрение в бесконечности"
    suspected_infinite_threshold: int = 100_000_000

    # Порог "интересности" орбиты (например, для повышенной награды)
    interesting_threshold: int = 1_000_000


def classify_suspicion(steps: int, rules: OrbitRules | None = None) -> SuspicionLevel:
    """По количеству шагов определяем уровень подозрительности."""
    if rules is None:
        rules = OrbitRules()

    if steps <= rules.normal_max_steps:
        return SuspicionLevel.NORMAL
    if steps <= rules.low_suspicious_max:
        return SuspicionLevel.LOW_SUSPICIOUS
    if steps <= rules.medium_suspicious_max:
        return SuspicionLevel.MEDIUM_SUSPICIOUS
    if steps <= rules.high_suspicious_max:
        return SuspicionLevel.HIGH_SUSPICIOUS
    return SuspicionLevel.EXTREME_SUSPICIOUS


def decide_block_status(
    steps: int,
    reached_one: bool,
    rules: OrbitRules | None = None
) -> BlockStatus:
    """
    Определяет статус блока:
    - если не дошли до 1 → FORCED_STOP
    - если дошли, но очень длинная орбита → SUSPECTED_INFINITE
    - иначе → COMPLETED
    """
    if rules is None:
        rules = OrbitRules()

    if not reached_one:
        return BlockStatus.FORCED_STOP

    if steps >= rules.suspected_infinite_threshold:
        return BlockStatus.SUSPECTED_INFINITE

    return BlockStatus.COMPLETED


def is_interesting_orbit(steps: int, rules: OrbitRules | None = None) -> bool:
    """Достаточно ли длинная орбита, чтобы считать её 'интересной'."""
    if rules is None:
        rules = OrbitRules()
    return steps >= rules.interesting_threshold
