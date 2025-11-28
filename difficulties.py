from enum import Enum


class DifficultyTier(Enum):
    SUPER_EASY = "SUPER_EASY"
    EASY = "EASY"
    MEDIUM = "MEDIUM"
    HARD = "HARD"
    VERY_HARD = "VERY_HARD"
    EXTREME = "EXTREME"


# Пороги шагов для классификации сложности (включительно)
DIFFICULTY_THRESHOLDS = {
    DifficultyTier.SUPER_EASY: 100_000,
    DifficultyTier.EASY: 1_000_000,
    DifficultyTier.MEDIUM: 10_000_000,
    DifficultyTier.HARD: 100_000_000,
    DifficultyTier.VERY_HARD: 1_000_000_000,
    DifficultyTier.EXTREME: None,  # все, что выше VERY_HARD
}

# Множители наград по сложности
DIFFICULTY_MULTIPLIERS = {
    DifficultyTier.SUPER_EASY: 1.0,
    DifficultyTier.EASY: 2.0,
    DifficultyTier.MEDIUM: 4.0,
    DifficultyTier.HARD: 8.0,
    DifficultyTier.VERY_HARD: 16.0,
    DifficultyTier.EXTREME: 32.0,
}


def classify_difficulty(steps: int) -> DifficultyTier:
    """
    Определить сложность по количеству шагов.
    """
    for tier, threshold in DIFFICULTY_THRESHOLDS.items():
        if threshold is None:
            continue
        if steps <= threshold:
            return tier
    return DifficultyTier.EXTREME
