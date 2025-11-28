# collatz.py
from typing import List, Tuple

def collatz_step(n: int) -> int:
    """
    Выполняет ОДИН шаг преобразования Коллатца.
    Это фундамент для всей монеты — так добывается 'работа'.

    Для чётных чисел: возвращает n/2
    Для нечётных:      возвращает 3n + 1

    Никаких оптимизаций — пока базовый вариант.
    """
    if n <= 0:
        raise ValueError("n должно быть положительным")
    if n % 2 == 0:
        return n // 2
    else:
        return 3 * n + 1


def collatz_orbit(n: int, max_steps: int = 10_000_000) -> Tuple[List[int], int, int]:
    """
    Вычисляет ПОЛНУЮ орбиту числа n до падения в 1.
    Возвращает:
    - seq: путь всех значений
    - steps: количество шагов
    - peak: максимальное значение (важно для экономики токена)

    max_steps — защита от зависания, если число вдруг бесконечное (гипотетически).
    """
    if n <= 0:
        raise ValueError("n должно быть положительным")

    seq = [n]        # Список всех значений орбиты
    current = n
    peak = n         # Максимум по пути

    # Цикл шагов
    for _ in range(max_steps):
        if current == 1:
            break   # Орбита завершена
        
        current = collatz_step(current)
        seq.append(current)

        # Запоминаем пиковое значение
        if current > peak:
            peak = current

    else:
        # Если цикл НЕ завершён break'ом — значит достигли max_steps
        raise RuntimeError(f"Превышен лимит {max_steps} шагов для числа {n}")

    steps = len(seq) - 1
    return seq, steps, peak

def collatz_segment(start: int, max_steps: int) -> Tuple[List[int], int, int, bool]:
    """
    Считает ОДИН СЕГМЕНТ орбиты Коллатца, начиная с числа `start`.

    max_steps — максимум шагов в этом сегменте.

    Возвращает:
    - values: список новых значений (БЕЗ самого start).
      Например: start=7 → [22, 11, 34, ...]
    - steps_done: сколько шагов реально сделано (<= max_steps)
    - peak: максимальное значение, встреченное в этом сегменте
    - reached_one: True, если по пути дошли до 1
    """
    if start <= 0:
        raise ValueError("start должно быть положительным")

    current = start
    values: List[int] = []
    peak = start
    steps_done = 0

    for _ in range(max_steps):
        if current == 1:
            # Уже в 1, дальше шаги не делаем
            return values, steps_done, peak, True

        # Один шаг Коллатца
        if current % 2 == 0:
            current = current // 2
        else:
            current = 3 * current + 1

        values.append(current)
        steps_done += 1

        if current > peak:
            peak = current

        if current == 1:
            return values, steps_done, peak, True

    # Лимит шагов исчерпан, но 1 не достигнута
    return values, steps_done, peak, (current == 1)
