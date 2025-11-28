import os
import time
import math
import logging

from chain import Blockchain
from miner import mine_block_for_number
from storage import (
    load_chain,
    save_chain,
    load_checkpoints,
    save_checkpoints,
    load_economics_state,
    save_economics_state,
)
from state import calculate_balances
from wallet import get_or_create_default_wallet
from transaction_pool import mempool
from validator_settings import load_validator_config
from economics import (
    block_reward_for_steps,
    apply_extreme_record_bonus,
    last_reward_for_tier,
    checkpoint_reward,
    cap_checkpoint_sum,
    EconomicsState,
)
from difficulties import classify_difficulty
from checkpoint import Checkpoint, sign_checkpoint
from consensus import sign_proposal, sign_vote, Proposal, Vote
from aurora_protocol import MsgType

SAVE_EVERY = 10
DEBUG = os.environ.get("DEBUG", "0") == "1"

# first-miner bonus config
INITIAL_FIRST_BONUS = 0.20  # +20%
TARGET_FIRST_BONUS = 0.01   # ~+1%
TARGET_FIRST_BONUS_HEIGHT = 10000
FIRST_MINER_LIMIT = 10000
FIRST_BONUS_LAMBDA = math.log(INITIAL_FIRST_BONUS / TARGET_FIRST_BONUS) / TARGET_FIRST_BONUS_HEIGHT

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("clx")


def print_balances(chain: Blockchain, miner_address: str):
    balances = calculate_balances(chain.blocks, chain.checkpoints)
    print("\nBalances:")
    if not balances:
        print("  (no balances yet)")
        return
    for addr, bal in balances.items():
        mark = " <= you" if addr == miner_address else ""
        print(f"  {addr}: {bal}{mark}")


def load_or_create_chain(validators) -> tuple[Blockchain, bool]:
    loaded_blocks = load_chain()
    cps = load_checkpoints()
    if not loaded_blocks:
        chain = Blockchain(validators=validators)
        genesis = chain.add_genesis_block()
        print("Genesis block:", genesis.to_dict())
        return chain, True
    chain = Blockchain(blocks=loaded_blocks, checkpoints=cps, validators=validators)
    print("Loaded local chain. Valid:", chain.is_valid_chain())
    return chain, False


def first_miner_multiplier(height: int) -> float:
    if height <= 0:
        return 1.0 + INITIAL_FIRST_BONUS
    bonus = INITIAL_FIRST_BONUS * math.exp(-FIRST_BONUS_LAMBDA * max(0, height))
    bonus = max(bonus, TARGET_FIRST_BONUS)
    return 1.0 + bonus


def is_first_miner_addr(miner_addr: str, chain: Blockchain) -> bool:
    seen = []
    seen_set = set()
    for blk in chain.blocks:
        addr = blk.miner_address
        if not addr or addr in seen_set:
            continue
        seen.append(addr)
        seen_set.add(addr)
        if len(seen) >= FIRST_MINER_LIMIT:
            break
    return miner_addr in seen_set and seen.index(miner_addr) < FIRST_MINER_LIMIT


def broadcast_block(aurora_node, block, orbit=None):
    if not aurora_node:
        return
    payload = {"block": block.to_dict()}
    if orbit is not None:
        payload["orbit"] = orbit
    aurora_node._broadcast(MsgType.BLOCK, payload)


def broadcast_proposal(aurora_node, prop):
    if aurora_node:
        aurora_node._broadcast(MsgType.PROPOSAL, {"proposal": prop.to_dict()})


def broadcast_vote(aurora_node, vote):
    if aurora_node:
        aurora_node._broadcast(MsgType.VOTE, {"vote": vote.to_dict()})


def main():
    host = os.environ.get("NODE_HOST", "0.0.0.0")
    port = int(os.environ.get("NODE_PORT", "8000"))
    bootstrap_peers = [p.strip() for p in os.environ.get("BOOTSTRAP_PEERS", "").split(",") if p.strip()]

    aurora_node = None
    AURORA_ENABLE = os.environ.get("AURORA_ENABLE", "1") in ("1", "true", "True")
    if AURORA_ENABLE:
        try:
            from aurora_transport import AuroraTransport
            from aurora_node import AuroraNode
            import urllib.parse as _urlparse
            aurora_port = int(os.environ.get("AURORA_PORT", "9000"))

            def _parse_bootstrap_peer(url: str):
                try:
                    u = _urlparse.urlparse(url)
                    if u.hostname and u.port:
                        return (u.hostname, u.port)
                except Exception:
                    pass
                if ":" in url:
                    host, p = url.rsplit(":", 1)
                    host = host.replace("http://", "").replace("https://", "")
                    try:
                        return (host, int(p))
                    except Exception:
                        return (host, aurora_port)
                return ("127.0.0.1", aurora_port)

            aurora_bootstrap = [_parse_bootstrap_peer(p) for p in bootstrap_peers]
            aurora_transport = AuroraTransport(udp_port=aurora_port)
            aurora_node = AuroraNode(aurora_transport, bootstrap_peers=aurora_bootstrap)
            aurora_node.start()
            print(f"[aurora] started UDP on {aurora_port}, peers={aurora_bootstrap if aurora_bootstrap else 'public STUN autodiscovery'}")
        except Exception as exc:
            print(f"[aurora] disabled: {exc}")
            aurora_node = None

    validators = load_validator_config()
    economics_state = load_economics_state()

    wallet = get_or_create_default_wallet()
    miner_address = wallet.address
    print(f"\nMining rewards will go to: {miner_address}\n")

    chain, created_new_chain = load_or_create_chain(validators)
    if aurora_node:
        aurora_node.chain = chain
        aurora_node.validators = validators

    if created_new_chain and len(chain.blocks) <= 1:
        economics_state = EconomicsState()
        save_economics_state(economics_state)

    print_balances(chain, miner_address)
    print("\nMining... stop with Ctrl+C\n")

    blocks_mined = 0

    def on_checkpoint(cp: Checkpoint):
        cp.miner_address = miner_address
        tier = classify_difficulty(cp.steps_done_total)
        last_reward = last_reward_for_tier(economics_state, tier)
        existing_total = sum(c.reward_paid for c in chain.checkpoints if c.number == cp.number)
        est_cap = cap_checkpoint_sum(existing_total + checkpoint_reward(last_reward), last_reward)
        cp_reward = max(0.0, est_cap - existing_total)
        cp.reward_paid = cp_reward
        if validators.my_private_key and miner_address in validators.validator_addresses:
            att = sign_checkpoint(cp, validators.my_private_key, signer_addr=miner_address)
            cp.attestations.append(att.to_dict())
        chain.add_checkpoint(cp)
        print(f"[checkpoint] n={cp.number} steps={cp.steps_done_total} reward={cp.reward_paid:.4f}")

    def submit_consensus(block):
        if not validators.my_private_key or not validators.validator_addresses:
            return
        slot = block.index
        # proposer selection simplified: first validator
        leader = validators.validator_addresses[0] if validators.validator_addresses else None
        if leader != wallet.address:
            return
        prop = sign_proposal(block, validators.my_private_key, slot=slot, round=0)
        broadcast_proposal(aurora_node, prop)
        for vt in ["PREVOTE", "PRECOMMIT"]:
            v = sign_vote(block.hash(), validators.my_private_key, slot=slot, round=0, vote_type=vt)
            broadcast_vote(aurora_node, v)
        print(f"[consensus] proposed block #{block.index} and voted PREVOTE/PRECOMMIT")

    try:
        while True:
            last_block = chain.get_last_block()
            next_n = (last_block.number + 1) if last_block else 1
            last_cp = chain.get_active_checkpoint_for(next_n)

            txs = [tx.to_dict() for tx in mempool.get_all()]

            block, orbit = mine_block_for_number(
                next_n,
                last_block,
                miner_address,
                transactions=txs,
                validators=validators,
                economics_state=economics_state,
                last_checkpoint=last_cp,
                checkpoint_callback=on_checkpoint,
            )

            reward, tier = block_reward_for_steps(economics_state, block.steps_total)
            reward = apply_extreme_record_bonus(reward, tier, block.steps_total, economics_state)
            total_cp_paid = sum(cp.reward_paid for cp in chain.checkpoints if cp.number == block.number)
            total_cp_paid = cap_checkpoint_sum(total_cp_paid, reward)
            block.reward = max(0.0, reward - total_cp_paid)
            if is_first_miner_addr(miner_address, chain):
                block.reward *= first_miner_multiplier(block.index)

            submit_consensus(block)
            added_locally = chain.add_block(block)

            blocks_mined += 1
            broadcast_block(aurora_node, block, orbit=orbit)
            mempool.clear()

            print(
                f"[block #{block.index}] n={next_n} steps={block.steps_total} "
                f"peak={block.peak_value} suspicion={block.suspicion_level} "
                f"status={block.status} difficulty={block.difficulty} "
                f"txs={len(block.transactions or [])} miner={block.miner_address} reward={block.reward:.4f}"
            )
            if added_locally:
                print(f"[local] appended block #{block.index} immediately")

            if blocks_mined % SAVE_EVERY == 0:
                print("\nSaving chain to disk ...")
                save_chain(chain.blocks)
                save_checkpoints(chain.checkpoints)
                save_economics_state(economics_state)
                print_balances(chain, miner_address)
                print()

            time.sleep(0.2)

    except KeyboardInterrupt:
        print("\nStopping miner...")
    finally:
        save_chain(chain.blocks)
        save_checkpoints(chain.checkpoints)
        save_economics_state(economics_state)
        print("\nChain valid:", chain.is_valid_chain())
        print("Blocks total:", len(chain.blocks))
        print_balances(chain, miner_address)


if __name__ == "__main__":
    main()
