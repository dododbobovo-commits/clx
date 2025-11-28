# segments.py
"""
segments.py — структуры данных сегментов Коллатца (задача и результат).

SegmentJob:
    - start_value: число, с которого начинается сегмент
    - max_steps: сколько шагов нужно выполнить
    - segment_id: уникальный идентификатор сегмента
    - expected_prev_hash: хэш предыдущего значения (защита от подделки)
    - job_index: номер сегмента в последовательности

SegmentResult:
    - segment_id: идентификатор сегмента
    - values: список полученных значений
    - steps_done: сколько шагов реально сделано
    - peak: максимум
    - reached_one: флаг
"""

import json
import hashlib
import secrets
from dataclasses import dataclass, asdict
from typing import List


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def random_id() -> str:
    return secrets.token_hex(16)


@dataclass
class SegmentJob:
    start_value: int
    max_steps: int
    job_index: int         # индекс сегмента в орбите
    expected_prev_hash: str   # хэш previous_value для проверки честности
    segment_id: str = None

    def __post_init__(self):
        if self.segment_id is None:
            self.segment_id = random_id()

    def to_dict(self):
        return asdict(self)

    def hash(self) -> str:
        """Хэш задания (включает start_value и max_steps)."""
        return sha256(json.dumps(self.to_dict(), sort_keys=True).encode())


@dataclass
class SegmentResult:
    segment_id: str
    values: List[int]
    steps_done: int
    peak: int
    reached_one: bool
    worker_id: str | None = None  # кто посчитал (IP или иной ID)

    def to_dict(self):
        return asdict(self)

    def hash(self) -> str:
        """Хэш результата (значения сегмента)."""
        return sha256(json.dumps(self.to_dict(), sort_keys=True).encode())

