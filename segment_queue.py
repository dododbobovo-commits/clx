# segment_queue.py
"""
segment_queue.py — очереди заданий и результатов для сегментов Коллатца.

Это общий буфер между:
- "координатором" (узел, который собирает орбиту)
- "воркерами" (узлы, которые считают сегменты)

Пока всё в памяти, без диска.
"""

import queue
from typing import Optional
from segments import SegmentJob, SegmentResult


class SegmentJobQueue:
    def __init__(self):
        self._q: "queue.Queue[SegmentJob]" = queue.Queue()

    def put(self, job: SegmentJob) -> None:
        self._q.put(job)

    def get(self, block: bool = False, timeout: Optional[float] = None) -> Optional[SegmentJob]:
        try:
            return self._q.get(block=block, timeout=timeout)
        except queue.Empty:
            return None

    def empty(self) -> bool:
        return self._q.empty()


class SegmentResultQueue:
    def __init__(self):
        self._q: "queue.Queue[SegmentResult]" = queue.Queue()

    def put(self, result: SegmentResult) -> None:
        self._q.put(result)

    def get(self, block: bool = False, timeout: Optional[float] = None) -> Optional[SegmentResult]:
        try:
            return self._q.get(block=block, timeout=timeout)
        except queue.Empty:
            return None

    def empty(self) -> bool:
        return self._q.empty()


# Глобальные очереди, которыми будет пользоваться и HTTP-сервер, и майнер.
job_queue = SegmentJobQueue()
result_queue = SegmentResultQueue()
