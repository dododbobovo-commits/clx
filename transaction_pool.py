# transaction_pool.py
"""
transaction_pool.py — локальный пул транзакций (mempool).

Пока это просто список неподтверждённых транзакций.
Позже заменим на p2p-пул, чтобы узлы делились транзакциями.
"""

from typing import List
from transaction import Transaction


class TransactionPool:
    def __init__(self):
        self.transactions: List[Transaction] = []

    def add(self, tx: Transaction):
        self.transactions.append(tx)

    def clear(self):
        self.transactions.clear()

    def get_all(self) -> List[Transaction]:
        return list(self.transactions)

    def remove_by_hashes(self, hashes: List[str]):
        if not hashes:
            return
        keep = []
        target = set(hashes)
        for tx in self.transactions:
            if tx.hash() not in target:
                keep.append(tx)
        self.transactions = keep


# глобальный mempool для узла
mempool = TransactionPool()
