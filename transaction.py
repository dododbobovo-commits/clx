# transaction.py
import json
import hashlib
from dataclasses import dataclass, asdict
from typing import Optional

from crypto_utils import sign_ed25519, verify_ed25519


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Transaction:
    sender: str
    recipient: str
    amount: int
    signature: Optional[str] = None
    sender_pub: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def body(self) -> dict:
        return {"sender": self.sender, "recipient": self.recipient, "amount": self.amount}

    def body_json(self) -> str:
        return json.dumps(self.body(), sort_keys=True)

    def hash(self) -> str:
        return sha256(self.body_json().encode())

    def sign(self, private_key_hex: str, sender_pub_hex: str) -> None:
        self.sender_pub = sender_pub_hex
        self.signature = sign_ed25519(self.body_json().encode(), private_key_hex)

    def verify(self) -> bool:
        if not self.signature or not self.sender_pub:
            return False
        return verify_ed25519(self.signature, self.body_json().encode(), self.sender_pub)


def transaction_from_dict(data: dict) -> Transaction:
    return Transaction(
        sender=str(data.get("sender")),
        recipient=str(data.get("recipient")),
        amount=int(data.get("amount", 0)),
        signature=data.get("signature"),
        sender_pub=data.get("sender_pub"),
    )
