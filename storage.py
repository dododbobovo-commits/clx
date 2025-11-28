import json
import os
from typing import Optional, List, Tuple

from block import Block
from checkpoint import Checkpoint
from economics import EconomicsState, load_economics, save_economics


DEFAULT_CHAIN_PATH = "chain.json"
DEFAULT_CHECKPOINT_PATH = "checkpoints.json"


def block_from_dict(data: dict) -> Block:
    return Block(**data)


def save_chain(blocks: List[Block], path: str = DEFAULT_CHAIN_PATH) -> None:
    data = [b.to_dict() for b in blocks]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"Цепочка сохранена в {path}. Блоков: {len(blocks)}")


def load_chain(path: str = DEFAULT_CHAIN_PATH) -> Optional[List[Block]]:
    if not os.path.exists(path):
        print(f"Файл {path} не найден — цепь создаётся заново.")
        return None

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    blocks = [block_from_dict(d) for d in data]
    print(f"Загружена цепь из {path}. Блоков: {len(blocks)}")
    return blocks


def save_checkpoints(cps: List[Checkpoint], path: str = DEFAULT_CHECKPOINT_PATH) -> None:
    data = [c.to_dict() for c in cps]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"Чекпоинты сохранены в {path}. Кол-во: {len(cps)}")


def load_checkpoints(path: str = DEFAULT_CHECKPOINT_PATH) -> List[Checkpoint]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    cps = [Checkpoint.from_dict(d) for d in data]
    print(f"Загружено чекпоинтов из {path}: {len(cps)}")
    return cps


def load_economics_state() -> EconomicsState:
    return load_economics()


def save_economics_state(state: EconomicsState) -> None:
    save_economics(state)
