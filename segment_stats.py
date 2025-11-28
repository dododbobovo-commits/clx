# segment_stats.py
"""
Адаптация шага сегментов и таймауты для чекпоинтов.
"""

from dataclasses import dataclass


@dataclass
class SegmentStats:
    target_duration_sec: float = 0.5
    min_steps: int = 100
    max_steps: int = 50_000
    steps_per_segment: int = 1_000
    alpha: float = 0.3

    long_segment_sec: float = 30.0   # если сегмент длится дольше — публикуем чекпоинт
    long_block_sec: float = 600.0    # если блок не завершён за это время — публикуем чекпоинт

    def update(self, steps_done: int, duration_sec: float) -> None:
        if steps_done <= 0 or duration_sec <= 0:
            return

        if duration_sec > 10:
            self.steps_per_segment = max(self.min_steps, self.steps_per_segment // 2)
            return

        if 0.5 <= duration_sec <= 0.7:
            boosted = int(self.steps_per_segment * 1.5)
            self.steps_per_segment = min(self.max_steps, max(self.min_steps, boosted))
            return

        speed = steps_done / duration_sec
        desired_steps = speed * self.target_duration_sec
        new_steps = (1 - self.alpha) * self.steps_per_segment + self.alpha * desired_steps
        new_steps = max(self.min_steps, min(self.max_steps, int(new_steps)))
        self.steps_per_segment = new_steps

    def get_steps(self, remaining_global_limit: int) -> int:
        return max(self.min_steps, min(self.steps_per_segment, remaining_global_limit))


SEGMENT_STATS = SegmentStats()
