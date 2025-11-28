"""
Простейший детектор двойных подписей для блоков/голосов.
Сохраняет наблюдаемые подписи в памяти; при повторной подписи тем же валидатором с другим блок_hash/слотом фиксирует нарушение.
"""

from dataclasses import dataclass
from typing import Dict, Tuple, Optional
import json
import os


@dataclass
class DoubleSignEvidence:
    kind: str  # "BLOCK" или "VOTE"
    slot: int
    round: int
    signer: str
    first_hash: str
    second_hash: str


class SlashingDetector:
    def __init__(self):
        self.block_signatures: Dict[Tuple[int, str], str] = {}
        self.vote_signatures: Dict[Tuple[int, int, str], str] = {}
        self.evidence: list[DoubleSignEvidence] = []
        self.slashed: set[str] = set()

    def check_block_sig(self, slot: int, signer: str, block_hash: str) -> Optional[DoubleSignEvidence]:
        key = (slot, signer)
        existing = self.block_signatures.get(key)
        if existing and existing != block_hash:
            self.evidence.append(
                DoubleSignEvidence("BLOCK", slot, 0, signer, existing, block_hash)
            )
            self.slashed.add(signer)
            return self.evidence[-1]
        else:
            self.block_signatures[key] = block_hash
        return None

    def check_vote_sig(self, slot: int, rnd: int, signer: str, block_hash: str) -> Optional[DoubleSignEvidence]:
        key = (slot, rnd, signer)
        existing = self.vote_signatures.get(key)
        if existing and existing != block_hash:
            self.evidence.append(
                DoubleSignEvidence("VOTE", slot, rnd, signer, existing, block_hash)
            )
            self.slashed.add(signer)
            return self.evidence[-1]
        else:
            self.vote_signatures[key] = block_hash
        return None

    def get_evidence(self) -> list[DoubleSignEvidence]:
        return list(self.evidence)

    def is_slashed(self, signer: str) -> bool:
        return signer in self.slashed

    def reset(self):
        self.block_signatures.clear()
        self.vote_signatures.clear()
        self.evidence.clear()
        self.slashed.clear()


SLASHED_PATH = "slashed.json"


def save_slashed(addrs: set[str], path: str = SLASHED_PATH) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sorted(addrs), f, ensure_ascii=False, indent=2)


def load_slashed(path: str = SLASHED_PATH) -> set[str]:
    if not os.path.exists(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return set(data or [])
    except Exception:
        return set()
