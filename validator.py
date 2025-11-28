import math
import os
from dataclasses import dataclass
from typing import Dict, Optional, Set

from block import Block
from crypto_utils import sign_ed25519, verify_ed25519, derive_address_from_public, generate_ed25519_keypair


def signing_hash(block: Block) -> str:
    return block.hash()


def sign_block(block: Block, private_key_hex: str) -> dict:
    msg = signing_hash(block).encode()
    sig = sign_ed25519(msg, private_key_hex)
    # derive public key from private
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    pub_hex = priv.public_key().public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.PublicFormat.Raw,
    ).hex()
    signer = derive_address_from_public(pub_hex)
    return {"signer": signer, "sig": sig, "pub": pub_hex}


def verify_signature(sig_entry: dict, private_map: Dict[str, str], block: Block) -> bool:
    signer = sig_entry.get("signer")
    sig = sig_entry.get("sig")
    pub_hex = sig_entry.get("pub")
    if not signer or not sig or not pub_hex:
        return False
    msg = signing_hash(block).encode()
    return verify_ed25519(sig, msg, pub_hex)


def verify_checkpoint_signature(sig_entry: dict, private_map: Dict[str, str], cp_hash: str) -> bool:
    signer = sig_entry.get("signer")
    sig = sig_entry.get("sig")
    pub_hex = sig_entry.get("pub")
    if not signer or not sig or not pub_hex:
        return False
    return verify_ed25519(sig, cp_hash.encode(), pub_hex)


@dataclass
class ValidatorConfig:
    validator_addresses: Set[str]
    threshold_ratio: float = 0.67
    my_private_key: Optional[str] = None
    known_private_keys: Dict[str, str] = None
    public_keys: Dict[str, str] = None  # addr -> pub_hex
    slashed: Set[str] = None

    def __init__(
        self,
        validator_addresses: Optional[Set[str]] = None,
        threshold_ratio: float = 0.67,
        my_private_key: Optional[str] = None,
        known_private_keys: Optional[Dict[str, str]] = None,
    ):
        self.validator_addresses = validator_addresses or set()
        self.threshold_ratio = threshold_ratio
        self.my_private_key = my_private_key
        self.known_private_keys = known_private_keys or {}
        self.public_keys = {}
        self.slashed = set()

    def active_validators(self) -> Set[str]:
        return {v for v in self.validator_addresses if v not in self.slashed}

    def required_signatures(self) -> int:
        active = self.active_validators()
        if not active:
            return 0
        return max(1, math.ceil(len(active) * self.threshold_ratio))


def load_validators_from_env() -> ValidatorConfig:
    addrs_env = os.environ.get("VALIDATOR_ADDRESSES", "")
    my_priv = os.environ.get("VALIDATOR_PRIVATE")
    priv_map_env = os.environ.get("VALIDATOR_KEYMAP", "")
    pub_map_env = os.environ.get("VALIDATOR_PUBKEYS", "")

    addresses = {a.strip() for a in addrs_env.split(",") if a.strip()}

    priv_map: Dict[str, str] = {}
    pub_map: Dict[str, str] = {}
    if priv_map_env:
        parts = [p.strip() for p in priv_map_env.split(",") if p.strip()]
        for item in parts:
            if ":" in item:
                addr, priv = item.split(":", 1)
                priv_map[addr.strip()] = priv.strip()

    if pub_map_env:
        parts = [p.strip() for p in pub_map_env.split(",") if p.strip()]
        for item in parts:
            if ":" in item:
                addr, pub = item.split(":", 1)
                pub_map[addr.strip()] = pub.strip()

    cfg = ValidatorConfig(validator_addresses=addresses, my_private_key=my_priv, known_private_keys=priv_map)
    # автодополнение pub_key из priv_map, если отсутствует
    for addr in addresses:
        if addr in pub_map:
            cfg.public_keys[addr] = pub_map[addr]
        elif addr in priv_map:
            # derive public
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            priv_bytes = bytes.fromhex(priv_map[addr])
            pub_hex = Ed25519PrivateKey.from_private_bytes(priv_bytes).public_key().public_bytes(
                encoding=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.Encoding.Raw,
                format=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.PublicFormat.Raw,
            ).hex()
            cfg.public_keys[addr] = pub_hex
    return cfg


def verify_validator_signatures(block: Block, cfg: ValidatorConfig) -> bool:
    # если валидаторы не заданы — пропускаем проверку
    if not cfg.validator_addresses:
        return True

    sigs = block.validator_signatures or []
    if not sigs:
        return False

    seen = set()
    ok = 0
    active = cfg.active_validators()
    for s in sigs:
        signer = s.get("signer")
        sig_hex = s.get("sig")
        pub_hex = s.get("pub") or cfg.public_keys.get(signer)
        if signer in seen:
            continue
        if signer not in active:
            continue
        if not pub_hex or not sig_hex:
            continue
        if verify_ed25519(sig_hex, signing_hash(block).encode(), pub_hex):
            seen.add(signer)
            ok += 1
            if ok >= cfg.required_signatures():
                return True

    return False
