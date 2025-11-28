"""
Конфигурация BFT-валидаторов и подписей.
Используем упрощённые подписи (hash(private+msg)), но строго требуем наличия приватных ключей для валидации.
"""

import json
import os
from dataclasses import dataclass, asdict
from typing import Dict, Set


@dataclass
class BFTConfig:
    validators: Set[str]
    private_keys: Dict[str, str]  # addr -> priv_hex
    quorum_ratio: float = 0.67

    def required(self) -> int:
        import math
        return max(1, math.ceil(len(self.validators) * self.quorum_ratio))


def load_bft_config() -> BFTConfig:
    addrs_env = os.environ.get("VALIDATOR_ADDRESSES", "")
    priv_map_env = os.environ.get("VALIDATOR_KEYMAP", "")

    validators = {a.strip() for a in addrs_env.split(",") if a.strip()}
    priv_map: Dict[str, str] = {}
    if priv_map_env:
        # формат: addr:priv,addr2:priv2
        parts = [p.strip() for p in priv_map_env.split(",") if p.strip()]
        for item in parts:
            if ":" in item:
                addr, priv = item.split(":", 1)
                priv_map[addr.strip()] = priv.strip()

    return BFTConfig(validators=validators, private_keys=priv_map)


def save_bft_config(cfg: BFTConfig, path: str = "bft_config.json") -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(asdict(cfg), f, ensure_ascii=False, indent=2)
