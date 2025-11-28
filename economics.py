import json
import math
import os
from dataclasses import dataclass, asdict
from typing import Dict

from difficulties import DifficultyTier, DIFFICULTY_MULTIPLIERS, classify_difficulty


ECONOMICS_PATH = "economics.json"
DEFAULT_DECAY = 0.005  # 0.5% снижение базовой награды на блок
CHECKPOINT_REWARD_RATIO = 0.01  # 1% от награды блока для tier
CHECKPOINT_REWARD_CAP = 0.7     # суммарные чекпоинты не больше 70% награды блока
EXTREME_RECORD_BONUS = 0.05     # +5% за новый рекорд в EXTREME


@dataclass
class EconomicsState:
    base_reward: float = 1.0
    decay: float = DEFAULT_DECAY
    record_steps: Dict[str, int] = None      # tier -> max steps
    last_reward_by_tier: Dict[str, float] = None  # tier -> last выплаченная награда блока

    def __post_init__(self):
        if self.record_steps is None:
            self.record_steps = {}
        if self.last_reward_by_tier is None:
            self.last_reward_by_tier = {}


def load_economics(path: str = ECONOMICS_PATH) -> EconomicsState:
    if not os.path.exists(path):
        return EconomicsState()
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return EconomicsState(
        base_reward=float(data.get("base_reward", 1.0)),
        decay=float(data.get("decay", DEFAULT_DECAY)),
        record_steps=data.get("record_steps", {}) or {},
        last_reward_by_tier=data.get("last_reward_by_tier", {}) or {},
    )


def save_economics(state: EconomicsState, path: str = ECONOMICS_PATH) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(asdict(state), f, ensure_ascii=False, indent=2)


def next_base_reward(state: EconomicsState) -> float:
    """
    Возвращает текущую базовую награду и двигает состояние с учётом decay.
    """
    reward = state.base_reward
    state.base_reward = max(0.0, state.base_reward * (1 - state.decay))
    return reward


def difficulty_multiplier(tier: DifficultyTier) -> float:
    return DIFFICULTY_MULTIPLIERS.get(tier, 1.0)


def block_reward_for_steps(state: EconomicsState, steps: int) -> tuple[float, DifficultyTier]:
    tier = classify_difficulty(steps)
    base = next_base_reward(state)
    reward = base * difficulty_multiplier(tier)
    state.last_reward_by_tier[tier.value] = reward
    return reward, tier


def checkpoint_reward(last_block_reward_for_tier: float) -> float:
    """
    Награда за чекпоинт = 1% от награды блока соответствующего tier.
    """
    return last_block_reward_for_tier * CHECKPOINT_REWARD_RATIO


def apply_extreme_record_bonus(reward: float, tier: DifficultyTier, steps: int, state: EconomicsState) -> float:
    if tier != DifficultyTier.EXTREME:
        return reward
    prev_record = state.record_steps.get(tier.value, 0)
    if steps > prev_record:
        state.record_steps[tier.value] = steps
        return reward * (1 + EXTREME_RECORD_BONUS)
    return reward


def cap_checkpoint_sum(total_checkpoint_reward: float, block_reward: float) -> float:
    """
    Ограничивает сумму выплат по чекпоинтам.
    """
    return min(total_checkpoint_reward, block_reward * CHECKPOINT_REWARD_CAP)


def last_reward_for_tier(state: EconomicsState, tier: DifficultyTier) -> float:
    """
    Последняя известная награда блока для данного tier (без сдвига base_reward).
    """
    return state.last_reward_by_tier.get(tier.value, state.base_reward * difficulty_multiplier(tier))
