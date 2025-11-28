"""
Упрощённый каркас BFT: предложения и голоса (prevote/precommit).
Реальный протокол (таймеры, слоты, ротация) не реализован, только типы и проверки кворума.
Подписи простые: sha256(priv + msg).
"""

import math
import time
from dataclasses import dataclass, asdict, field
from typing import Dict, Optional

from block import Block
from crypto_utils import sign_ed25519, verify_ed25519, derive_address_from_public
from validator import ValidatorConfig


@dataclass
class ConsensusConfig:
    slot_duration: float = 6.0
    round_duration: float = 3.0
    quorum_ratio: float = 0.67
    timeout_base: float = 3.0   # базовый таймаут для раунда
    timeout_increment: float = 1.0  # инкремент для следующего раунда


@dataclass
class Proposal:
    slot: int
    round: int
    block: Block
    proposer: str
    signature: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["block"] = self.block.to_dict()
        return d


@dataclass
class Vote:
    slot: int
    round: int
    block_hash: str
    voter: str
    signature: str
    vote_type: str = "PRECOMMIT"  # PREVOTE / PRECOMMIT
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RoundState:
    slot: int
    round: int
    proposal: Optional[Proposal] = None
    prevotes: Dict[str, Vote] = field(default_factory=dict)
    precommits: Dict[str, Vote] = field(default_factory=dict)
    decided_block_hash: Optional[str] = None

    def has_quorum(self, votes: Dict[str, Vote], validators: ValidatorConfig, ratio: float) -> bool:
        active = validators.active_validators()
        if not active:
            return False
        required = max(1, math.ceil(len(active) * ratio))
        counted = sum(1 for v in votes if v in active)
        return counted >= required

    def prevote_quorum(self, validators: ValidatorConfig, ratio: float) -> bool:
        return self.has_quorum(self.prevotes, validators, ratio)

    def precommit_quorum(self, validators: ValidatorConfig, ratio: float) -> bool:
        return self.has_quorum(self.precommits, validators, ratio)


def _derive_sig(priv_hex: str, msg: str) -> str:
    return sign_ed25519(msg.encode(), priv_hex)


def sign_proposal(block: Block, priv_hex: str, slot: int, round: int) -> Proposal:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    pub_hex = priv.public_key().public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.PublicFormat.Raw,
    ).hex()
    proposer = derive_address_from_public(pub_hex)
    msg = f"proposal:{slot}:{round}:{block.hash()}"
    sig = _derive_sig(priv_hex, msg)
    return Proposal(slot=slot, round=round, block=block, proposer=proposer, signature=sig)


def sign_vote(block_hash: str, priv_hex: str, slot: int, round: int, vote_type: str = "PRECOMMIT") -> Vote:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    pub_hex = priv.public_key().public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.PublicFormat.Raw,
    ).hex()
    voter = derive_address_from_public(pub_hex)
    msg = f"vote:{vote_type}:{slot}:{round}:{block_hash}"
    sig = _derive_sig(priv_hex, msg)
    return Vote(slot=slot, round=round, block_hash=block_hash, voter=voter, signature=sig, vote_type=vote_type)


def verify_vote(vote: Vote, validators: ValidatorConfig) -> bool:
    if vote.voter not in validators.active_validators():
        return False
    msg = f"vote:{vote.vote_type}:{vote.slot}:{vote.round}:{vote.block_hash}"
    pub_hex = validators.public_keys.get(vote.voter)
    if not pub_hex:
        return False
    return verify_ed25519(vote.signature, msg.encode(), pub_hex)


def verify_proposal(prop: Proposal, validators: ValidatorConfig) -> bool:
    if prop.proposer not in validators.active_validators():
        return False
    msg = f"proposal:{prop.slot}:{prop.round}:{prop.block.hash()}"
    pub_hex = validators.public_keys.get(prop.proposer)
    if not pub_hex:
        return False
    return verify_ed25519(prop.signature, msg.encode(), pub_hex)


def checkpoint_quorum(cp, validators: ValidatorConfig, ratio: float = 0.67) -> bool:
    """
    Ensure checkpoint attestations reach the required fraction of validators.
    Accepts either dict or object attestations with a 'signer' field.
    """
    active = validators.active_validators()
    if not active:
        return False
    required = max(1, math.ceil(len(active) * ratio))
    signers = set()
    for att in getattr(cp, "attestations", []):
        signer = None
        if isinstance(att, dict):
            signer = att.get("signer")
        else:
            signer = getattr(att, "signer", None)
        if signer:
            signers.add(signer)
    return len(signers) >= required
