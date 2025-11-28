"""
Хранилище состояния консенсуса на узле (каркас).
Не управляет таймерами/слотами, только хранит предложения/голоса и фиксирует финализацию при кворуме precommit.
"""

import time
from dataclasses import dataclass, field
from typing import Optional, Dict

from consensus import Proposal, Vote, RoundState, ConsensusConfig
from validator import ValidatorConfig
from block import Block


@dataclass
class ConsensusState:
    cfg: ConsensusConfig
    validators: ValidatorConfig
    current_slot: int = 0
    current_round: int = 0
    rounds: Dict[int, RoundState] = field(default_factory=dict)  # slot -> RoundState
    finalized_blocks: Dict[int, Block] = field(default_factory=dict)  # slot -> Block
    round_start_time: float = 0.0

    def current_round_state(self) -> RoundState:
        return self.get_round_state(self.current_slot, self.current_round)

    def get_round_state(self, slot: int, round: int) -> RoundState:
        rs = self.rounds.get(slot)
        if rs is None or rs.round != round:
            rs = RoundState(slot=slot, round=round)
            self.rounds[slot] = rs
        return rs

    def update_round(self, slot: int, round: int):
        """
        Обновляет текущий слот/раунд, сбрасывая состояние раунда.
        """
        self.current_slot = slot
        self.current_round = round
        self.round_start_time = time.time()
        self.rounds[slot] = RoundState(slot=slot, round=round)

    def add_proposal(self, prop: Proposal):
        # игнорируем устаревшие предложения
        if prop.slot < self.current_slot or (prop.slot == self.current_slot and prop.round < self.current_round):
            return
        if prop.slot > self.current_slot or prop.round > self.current_round:
            self.update_round(prop.slot, prop.round)
        rs = self.get_round_state(prop.slot, prop.round)
        if rs.proposal is None:
            rs.proposal = prop

    def add_vote(self, vote: Vote):
        if vote.slot < self.current_slot or (vote.slot == self.current_slot and vote.round < self.current_round):
            return
        if vote.slot > self.current_slot or vote.round > self.current_round:
            self.update_round(vote.slot, vote.round)
        rs = self.get_round_state(vote.slot, vote.round)
        if vote.vote_type == "PREVOTE":
            rs.prevotes[vote.voter] = vote
        else:
            rs.precommits[vote.voter] = vote

    def can_finalize(self, slot: int, round: int) -> Optional[str]:
        rs = self.get_round_state(slot, round)
        if rs.precommit_quorum(self.validators, self.cfg.quorum_ratio):
            hashes = {v.block_hash for v in rs.precommits.values()}
            if len(hashes) == 1:
                h = hashes.pop()
                rs.decided_block_hash = h
                return h
        return None

    def record_finalized(self, slot: int, block: Block):
        self.finalized_blocks[slot] = block

    def start_round(self, slot: int, rnd: int):
        self.current_slot = slot
        self.current_round = rnd
        self.round_start_time = time.time()
        self.rounds[slot] = RoundState(slot=slot, round=rnd)

    def should_timeout(self) -> bool:
        elapsed = time.time() - self.round_start_time
        limit = self.cfg.timeout_base + self.cfg.timeout_increment * self.current_round
        return elapsed > limit

    def next_round(self):
        self.start_round(self.current_slot, self.current_round + 1)

    def next_slot(self):
        self.start_round(self.current_slot + 1, 0)
