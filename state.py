# state.py
"""
Учёт балансов: блоки и чекпоинты.
"""

from typing import Dict, List

from block import Block
from checkpoint import Checkpoint
from transaction import transaction_from_dict


def apply_block_to_balances(
    balances: Dict[str, int],
    block: Block,
    strict: bool = False,
) -> bool:
    if block.miner_address and block.reward:
        balances[block.miner_address] = balances.get(block.miner_address, 0) + block.reward

    tx_list = block.transactions or []
    for tx_dict in tx_list:
        tx = transaction_from_dict(tx_dict)

        if tx.amount <= 0 or not tx.sender or not tx.recipient:
            if strict:
                return False
            continue

        if strict and not tx.verify():
            return False

        sender = tx.sender
        recipient = tx.recipient
        amount = tx.amount

        current = balances.get(sender, 0)
        if current < amount:
            if strict:
                return False
            continue

        balances[sender] = current - amount
        balances[recipient] = balances.get(recipient, 0) + amount

    return True


def apply_checkpoint_reward(balances: Dict[str, int], checkpoint: Checkpoint) -> None:
    if checkpoint.miner_address and checkpoint.reward_paid > 0:
        balances[checkpoint.miner_address] = balances.get(checkpoint.miner_address, 0) + int(checkpoint.reward_paid)


def calculate_balances(blocks: List[Block], checkpoints: List[Checkpoint] = None) -> Dict[str, int]:
    balances: Dict[str, int] = {}
    checkpoints = checkpoints or []

    # сперва награды чекпоинтов (только подтверждённые в цепи — логика отбора вне этого файла)
    for cp in checkpoints:
        apply_checkpoint_reward(balances, cp)

    for b in blocks:
        apply_block_to_balances(balances, b, strict=False)

    return balances
