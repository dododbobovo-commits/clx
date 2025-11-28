import hashlib
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat


def generate_ed25519_keypair() -> Tuple[str, str]:
    """
    Возвращает (private_hex, public_hex).
    """
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv_bytes.hex(), pub_bytes.hex()


def sign_ed25519(message: bytes, private_hex: str) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    sig = priv.sign(message)
    return sig.hex()


def verify_ed25519(signature_hex: str, message: bytes, public_hex: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        pub.verify(bytes.fromhex(signature_hex), message)
        return True
    except Exception:
        return False


def derive_address_from_public(public_hex: str) -> str:
    """
    Адрес = sha256(public_key_bytes)[:40].
    """
    pub_bytes = bytes.fromhex(public_hex)
    return hashlib.sha256(pub_bytes).hexdigest()[:40]
