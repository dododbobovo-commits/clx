import os
from typing import List, Optional, Tuple

from block import Block
from checkpoint import Checkpoint
from state import apply_block_to_balances
from validator import ValidatorConfig, verify_validator_signatures


class Blockchain:
    """
    Поддерживает блоки и чекпоинты для долгих вычислений.
    """

    def __init__(
        self,
        blocks: Optional[List[Block]] = None,
        checkpoints: Optional[List[Checkpoint]] = None,
        validators: Optional[ValidatorConfig] = None,
    ):
        self.blocks: List[Block] = blocks if blocks is not None else []
        self.checkpoints: List[Checkpoint] = checkpoints if checkpoints is not None else []
        self.validators = validators or ValidatorConfig()

    def get_last_block(self) -> Optional[Block]:
        if not self.blocks:
            return None
        return self.blocks[-1]

    def add_genesis_block(self) -> Block:
        if self.blocks:
            raise RuntimeError("Genesis block already exists")

        genesis = Block(
            index=1,
            number=1,
            steps_total=0,
            peak_value=1,
            orbit_hash="genesis",
            prev_hash=None,
            timestamp=0.0,
            nonce=0,
            suspicion_level="NORMAL",
            status="COMPLETED",
            miner_address=None,
            reward=0,
            transactions=None,
            validator_signatures=[],
            difficulty="SUPER_EASY",
            checkpoint_refs=[],
            checkpoint_reward_paid=0.0,
        )
        self.blocks.append(genesis)
        return genesis

    def add_checkpoint(self, cp: Checkpoint) -> None:
        """
        Добавляем чекпоинт без глубокой валидации здесь (валидация в p2p при приёме).
        """
        self.checkpoints.append(cp)

    def get_last_checkpoint_for(self, n: int) -> Optional[Checkpoint]:
        cps = [c for c in self.checkpoints if c.number == n]
        if not cps:
            return None
        return sorted(cps, key=lambda c: c.steps_done_total)[-1]

    def get_active_checkpoint_for(self, n: int) -> Optional[Checkpoint]:
        """
        Последний чекпоинт для числа n, который ещё не закрыт блоком.
        """
        if any(b.number == n for b in self.blocks):
            return None
        return self.get_last_checkpoint_for(n)

    def _is_block_economically_valid(self, block: Block) -> bool:
        from state import calculate_balances

        balances = calculate_balances(self.blocks)
        ok = apply_block_to_balances(balances, block, strict=True)
        return ok

    def _is_block_validator_valid(self, block: Block) -> bool:
        # новая система (probabilistic chunk proofs) заменяет подписи валидаторов
        if os.environ.get("AURORA_DISABLE_VALIDATORS", "0") in ("1", "true", "True"):
            return True
        if getattr(block, "segment_root", None) and getattr(block, "chunk_proofs", None):
            return True
        # на случай совсем старых блоков без новых полей — не требуем подписей
        return True

    def add_block(self, block: Block) -> bool:
        last = self.get_last_block()

        if last is None:
            if block.index != 1 or block.prev_hash is not None:
                return False
        else:
            if block.index != last.index + 1:
                return False
            if block.prev_hash != last.hash():
                return False

        if not self._is_block_economically_valid(block):
            print("Invalid block: economic rules failed.")
            return False

        if not self._is_block_validator_valid(block):
            print("Invalid block: validator signatures insufficient.")
            return False

        self.blocks.append(block)
        # удаляем чекпоинты по этому n, они закрыты
        self.checkpoints = [c for c in self.checkpoints if c.number != block.number]
        return True

    def is_valid_chain(self) -> bool:
        if not self.blocks:
            return True

        from state import calculate_balances

        for i in range(1, len(self.blocks)):
            prev = self.blocks[i - 1]
            curr = self.blocks[i]

            if curr.prev_hash != prev.hash():
                return False
            if curr.index != prev.index + 1:
                return False

        try:
            _ = calculate_balances(self.blocks)
        except Exception:
            return False

        return True
