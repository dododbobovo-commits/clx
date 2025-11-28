import json
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple

from crypto_utils import sign_ed25519, verify_ed25519, derive_address_from_public
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


@dataclass
class CheckpointAttestation:
    signer: str
    signature: str
    pub: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Checkpoint:
    number: int
    steps_done_total: int
    last_value: int
    orbit_hash_so_far: str
    segment_range: Tuple[int, int]
    segment_hash: str
    miner_address: Optional[str] = None
    reward_paid: float = 0.0
    attestations: List[CheckpointAttestation] = None

    def __post_init__(self):
        if self.attestations is None:
            self.attestations = []

    def to_dict(self) -> dict:
        d = asdict(self)
        d["attestations"] = [a.to_dict() for a in self.attestations]
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Checkpoint":
        att = [CheckpointAttestation(**a) for a in data.get("attestations", [])]
        return cls(
            number=int(data["number"]),
            steps_done_total=int(data["steps_done_total"]),
            last_value=int(data["last_value"]),
            orbit_hash_so_far=str(data["orbit_hash_so_far"]),
            segment_range=tuple(data["segment_range"]),
            segment_hash=str(data["segment_hash"]),
            miner_address=data.get("miner_address"),
            reward_paid=float(data.get("reward_paid", 0.0)),
            attestations=att,
        )

    def hash(self) -> str:
        payload = self.to_dict()
        payload.pop("attestations", None)
        return sha256(json.dumps(payload, sort_keys=True).encode("utf-8"))


def sign_checkpoint(cp: Checkpoint, private_key_hex: str, signer_addr: Optional[str] = None) -> CheckpointAttestation:
    cp_hash = cp.hash()
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    pub_bytes = priv.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    pub_hex = pub_bytes.hex()
    if signer_addr is None:
        signer_addr = derive_address_from_public(pub_hex)
    sig = sign_ed25519(cp_hash.encode(), private_key_hex)
    return CheckpointAttestation(signer=signer_addr, signature=sig, pub=pub_hex)


def verify_checkpoint_attestation(att: CheckpointAttestation, cp_hash: str) -> bool:
    return verify_ed25519(att.signature, cp_hash.encode(), att.pub)
