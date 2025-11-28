# wallet.py
"""
Примитивные кошельки: адрес = первые 40 hex символов от sha256(private_key_bytes).
Транзакции подписываются через Transaction.sign.
"""

import json
import os
from dataclasses import dataclass, asdict
from typing import List

from transaction import Transaction
from crypto_utils import generate_ed25519_keypair, derive_address_from_public, sign_ed25519

WALLETS_PATH = "wallets.json"


@dataclass
class Wallet:
    address: str
    private_key: str  # ed25519 private hex
    public_key: str   # ed25519 public hex


def generate_wallet() -> Wallet:
    priv_hex, pub_hex = generate_ed25519_keypair()
    address = derive_address_from_public(pub_hex)
    return Wallet(address=address, private_key=priv_hex, public_key=pub_hex)


def save_wallets(wallets: List[Wallet], path: str = WALLETS_PATH) -> None:
    data = [asdict(w) for w in wallets]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"Сохранено {len(wallets)} кошельков в {path}")


def load_wallets(path: str = WALLETS_PATH) -> List[Wallet]:
    if not os.path.exists(path):
        print(f"Файл {path} не найден — создайте кошелёк.")
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    wallets = [Wallet(**w) for w in data]
    print(f"Загружено {len(wallets)} кошельков из {path}")
    return wallets


def get_or_create_default_wallet(path: str = WALLETS_PATH) -> Wallet:
    wallets = load_wallets(path)
    if wallets:
        w = wallets[0]
        print(f"Кошелёк по умолчанию: {w.address}")
        return w

    print("Кошелёк не найден, создаём новый...")
    w = generate_wallet()
    save_wallets([w], path)
    print(f"Адрес: {w.address}\nПриватный ключ (hex): {w.private_key}\nПубличный ключ (hex): {w.public_key}")
    return w


def create_new_wallet(path: str = WALLETS_PATH) -> Wallet:
    wallets = load_wallets(path)
    w = generate_wallet()
    wallets.append(w)
    save_wallets(wallets, path)
    print(f"Новый кошелёк: {w.address}\nПриватный ключ (hex): {w.private_key}\nПубличный ключ (hex): {w.public_key}")
    return w


def create_transaction(sender_wallet: Wallet, recipient: str, amount: int) -> Transaction:
    tx = Transaction(sender=sender_wallet.address, recipient=recipient, amount=amount)
    tx.sign(sender_wallet.private_key, sender_wallet.public_key)
    return tx
