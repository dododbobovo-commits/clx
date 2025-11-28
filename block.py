# block.py
import json
import hashlib
from dataclasses import dataclass, asdict, field
from typing import Optional, List


def sha256(data: bytes) -> str:
    """SHA-256 helper."""
    return hashlib.sha256(data).hexdigest()


@dataclass
class Block:
    """
    Блок CollatzCoin.

    Хэш считается по header_payload (без подписей валидаторов),
    чтобы подписи не влияли на prev_hash следующего блока.
    """

    index: int
    number: int
    steps_total: int
    peak_value: int
    orbit_hash: str
    prev_hash: Optional[str]
    timestamp: float
    nonce: int = 0
    merkle_root: Optional[str] = None

    suspicion_level: str = "NORMAL"
    status: str = "COMPLETED"

    miner_address: Optional[str] = None
    reward: int = 0

    transactions: list = None
    # сложность/чекпоинты
    difficulty: str = "UNKNOWN"
    checkpoint_refs: List[str] = field(default_factory=list)
    checkpoint_reward_paid: float = 0.0
    segment_hashes: List[str] = field(default_factory=list)
    segment_lengths: List[int] = field(default_factory=list)
    # Probabilistic verification fields
    segment_root: Optional[str] = None  # Merkle root over segment_hashes/chunks
    master_hash: Optional[str] = None   # Hash of full segment/steps
    proof_seed: Optional[str] = None    # Randomness for chunk selection
    chunk_proofs: List[dict] = field(default_factory=list)  # sampled chunks with paths

    validator_signatures: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def header_payload(self) -> dict:
        d = self.to_dict()
        d.pop("validator_signatures", None)
        # merkle_root остаётся в заголовке
        return d

    def hash(self) -> str:
        """Хэш по данным блока без подписей валидаторов."""
        encoded = json.dumps(self.header_payload(), sort_keys=True).encode("utf-8")
        return sha256(encoded)
