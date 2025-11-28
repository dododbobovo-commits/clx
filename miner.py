import json
import time
from typing import Tuple, List, Optional, Callable

from collatz import collatz_segment, collatz_step
from block import Block, sha256
from rules import OrbitRules, classify_suspicion, decide_block_status, is_interesting_orbit
from transaction import Transaction
from segments import SegmentJob, SegmentResult, sha256
from segment_stats import SEGMENT_STATS
from validator import sign_block, ValidatorConfig
from difficulties import classify_difficulty
from checkpoint import Checkpoint
from economics import (
    block_reward_for_steps,
    apply_extreme_record_bonus,
    last_reward_for_tier,
    checkpoint_reward,
    cap_checkpoint_sum,
    EconomicsState,
)
from segment_queue import job_queue, result_queue

RULES = OrbitRules()


def make_segment_job(current_value: int, job_index: int, max_steps: int) -> SegmentJob:
    prev_hash = sha256(str(current_value).encode())
    return SegmentJob(
        start_value=current_value,
        max_steps=max_steps,
        job_index=job_index,
        expected_prev_hash=prev_hash,
    )


def execute_segment_job(job: SegmentJob) -> SegmentResult:
    values, steps_done, peak, reached_one = collatz_segment(job.start_value, job.max_steps)
    return SegmentResult(
        segment_id=job.segment_id,
        values=values,
        steps_done=steps_done,
        peak=peak,
        reached_one=reached_one,
    )


def combine_orbit_hash(prefix_hash: Optional[str], segment_values: List[int]) -> str:
    """
    Инкрементальный хэш орбиты: берём хэш сегмента, затем sha256(JSON {prev, segment_hash}).
    """
    segment_hash = sha256(json.dumps(segment_values).encode())
    if prefix_hash is None:
        return segment_hash
    payload = {"prev": prefix_hash, "segment": segment_hash}
    return sha256(json.dumps(payload, sort_keys=True).encode())


def compute_orbit_via_segments(
    n: int,
    start_value: Optional[int] = None,
    steps_done_total: int = 0,
    orbit_prefix_hash: Optional[str] = None,
    checkpoint_callback: Optional[Callable[[Checkpoint], None]] = None,
    forced_segment_lengths: Optional[List[int]] = None,
) -> Tuple[List[int], int, int, bool, str, List[str], List[int]]:
    """
    Вычисляет орбиту, поддерживает чекпоинты.
    Возвращает (новые_значения_орбиты, total_steps, peak, reached_one, финальный_инкрементальный_хэш).
    """
    orbit: List[int] = []
    current = start_value if start_value is not None else n
    total_steps = steps_done_total
    peak = current
    reached_one = False
    hard_limit = RULES.hard_step_limit
    job_index = 0

    TIMEOUT = 2.0
    block_start_time = time.time()

    rolling_hash = orbit_prefix_hash
    if orbit_prefix_hash is None:
        orbit.append(current)

    segment_hashes: List[str] = []
    segment_lengths: List[int] = []

    segment_values: List[list] = []

    while current != 1 and total_steps < hard_limit:
        remaining = hard_limit - total_steps
        if remaining <= 0:
            break

        if forced_segment_lengths and job_index < len(forced_segment_lengths):
            steps_for_segment = min(forced_segment_lengths[job_index], remaining)
            seg_start = time.time()
            job = make_segment_job(current, job_index, steps_for_segment)
            result = execute_segment_job(job)
            seg_duration = time.time() - seg_start
        else:
            steps_for_segment = SEGMENT_STATS.get_steps(remaining)
            job = make_segment_job(current, job_index, steps_for_segment)
            job_queue.put(job)

            start_wait = time.time()
            result = None

            while time.time() - start_wait < TIMEOUT:
                candidate = result_queue.get(block=False)
                if candidate and candidate.segment_id == job.segment_id:
                    result = candidate
                    break
                elif candidate:
                    result_queue.put(candidate)
                time.sleep(0.05)

            if result is None:
                seg_start = time.time()
                result = execute_segment_job(job)
                seg_duration = time.time() - seg_start
            else:
                seg_duration = time.time() - start_wait

        SEGMENT_STATS.update(result.steps_done, seg_duration)

        start_hash = sha256(str(job.start_value).encode())
        if start_hash != job.expected_prev_hash:
            print("!! Ошибка: start hash mismatch")
            break

        if result.values:
            expected_first_value = collatz_step(job.start_value)
            if result.values[0] != expected_first_value:
                print("!! Ошибка: сегмент не стыкуется")
                break

        if not result.values:
            break

        orbit.extend(result.values)
        total_steps += result.steps_done
        rolling_hash = combine_orbit_hash(rolling_hash, result.values)
        segment_hash = sha256(json.dumps(result.values).encode())
        segment_hashes.append(segment_hash)
        segment_lengths.append(result.steps_done)
        segment_values.append(result.values)

        if result.peak > peak:
            peak = result.peak

        current = result.values[-1]
        job_index += 1

        if result.reached_one or current == 1:
            reached_one = True
            break

        now = time.time()
        if seg_duration > SEGMENT_STATS.long_segment_sec or (now - block_start_time) > SEGMENT_STATS.long_block_sec:
            if checkpoint_callback:
                segment_hash = sha256(json.dumps(result.values).encode())
                cp = Checkpoint(
                    number=n,
                    steps_done_total=total_steps,
                    last_value=current,
                    orbit_hash_so_far=rolling_hash,
                    segment_range=(total_steps - result.steps_done, total_steps),
                    segment_hash=segment_hash,
                )
                checkpoint_callback(cp)

    if current == 1:
        reached_one = True

    return orbit, total_steps, peak, reached_one, rolling_hash, segment_hashes, segment_lengths, segment_values


def compute_orbit_hash(orbit: list[int]) -> str:
    data = json.dumps(orbit).encode("utf-8")
    return sha256(data)


def mine_block_for_number(
    n: int,
    prev_block: Optional[Block],
    miner_address: str,
    transactions: Optional[List[Transaction]] = None,
    validators: Optional[ValidatorConfig] = None,
    economics_state: Optional[EconomicsState] = None,
    last_checkpoint: Optional[Checkpoint] = None,
    checkpoint_callback: Optional[Callable[[Checkpoint], None]] = None,
) -> Tuple[Block, list[int]]:
    """
    Майнит орбиту n, может стартовать с чекпоинта и публиковать новые чекпоинты.
    Возвращает финальный блок и новые значения орбиты (если завершено).
    """
    start_value = last_checkpoint.last_value if last_checkpoint else None
    steps_done_total = last_checkpoint.steps_done_total if last_checkpoint else 0
    orbit_prefix_hash = last_checkpoint.orbit_hash_so_far if last_checkpoint else None

    orbit_new, steps, peak, reached_one, final_hash, segment_hashes, segment_lengths, segment_values = compute_orbit_via_segments(
        n,
        start_value=start_value,
        steps_done_total=steps_done_total,
        orbit_prefix_hash=orbit_prefix_hash,
        checkpoint_callback=checkpoint_callback,
    )

    orbit_hash = final_hash if orbit_prefix_hash is not None else compute_orbit_hash(orbit_new)

    prev_hash = prev_block.hash() if prev_block is not None else None
    index = 1 if prev_block is None else prev_block.index + 1

    suspicion = classify_suspicion(steps, RULES)
    status = decide_block_status(steps, reached_one, RULES)
    interesting = is_interesting_orbit(steps, RULES)
    difficulty = classify_difficulty(steps).value

    if interesting:
        print(f"-> Интересная орбита {n}: {steps} шагов")

    reward = 0.0
    tier = None
    if economics_state:
        reward, tier = block_reward_for_steps(economics_state, steps)
        reward = apply_extreme_record_bonus(reward, tier, steps, economics_state)

    tx_dicts = [tx.to_dict() for tx in (transactions or [])]

    try:
        from merkle import merkle_root
        merkle_val = merkle_root(segment_hashes)
    except Exception:
        merkle_val = None
    try:
        from merkle import merkle_path
        proof_chunks = []
        num_chunks = len(segment_hashes)
        if num_chunks > 0:
            proof_count = int(os.environ.get("AURORA_PROOF_CHUNKS", "4"))
            for i in range(proof_count):
                idx = int(sha256((proof_seed + str(i)).encode()), 16) % num_chunks
                path = merkle_path(segment_hashes, idx)
                proof_chunks.append(
                    {
                        "idx": idx,
                        "data": segment_values[idx],
                        "path": path,
                    }
                )
    except Exception:
        proof_chunks = []

    # probabilistic verification helpers
    master_hash = orbit_hash
    proof_seed = sha256(
        json.dumps(
            {
                "prev": prev_hash or "",
                "miner": miner_address or "",
                "segment_root": merkle_val or "",
                "number": n,
            },
            sort_keys=True,
        ).encode()
    )

    block = Block(
        index=index,
        number=n,
        steps_total=steps,
        peak_value=peak,
        orbit_hash=orbit_hash,
        prev_hash=prev_hash,
        timestamp=time.time(),
        nonce=0,
        merkle_root=merkle_val,
        suspicion_level=suspicion.name,
        status=status.name,
        miner_address=miner_address,
        reward=reward,
        transactions=tx_dicts,
        validator_signatures=[],
        difficulty=difficulty,
        checkpoint_refs=[],
        checkpoint_reward_paid=0.0,
        segment_hashes=segment_hashes,
        segment_lengths=segment_lengths,
        segment_root=merkle_val,
        master_hash=master_hash,
        proof_seed=proof_seed,
        chunk_proofs=proof_chunks,
    )

    if validators and validators.my_private_key:
        sig = sign_block(block, validators.my_private_key)
        block.validator_signatures.append(sig)

    return block, orbit_new
