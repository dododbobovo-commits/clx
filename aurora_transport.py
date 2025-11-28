"""
Aurora-Net transport skeleton: UDP listener/sender with CBOR framing, signatures, PoW, dedup cache.
Does not auto-start; instantiate AuroraTransport manually if needed.
"""

import socket
import threading
import time
import logging
import hashlib
import os
from typing import Optional, Tuple, Callable

from aurora_protocol import (
    MsgType,
    MAX_RELAY_SESSIONS,
    MAX_RELAY_RATE_BYTES_PER_MIN,
    MAX_MSG_SIZE,
    RATE_LIMIT_DEFAULTS,
    build_msg_common,
    attach_signature,
    decode_msg,
    encode_msg,
    make_node_id,
    POW_LEADING_ZERO_BITS,
    POW_LEADING_ZERO_BITS_OVERLOAD,
    validate_incoming,
    msg_id,
    hmac_hp,
    CAPABILITIES,
    PROTO_VERSION,
    DISCOVERY_WINDOW_SEC,
    DISCOVERY_LIMIT,
    HP_PROBE_COUNT,
    HP_PROBE_TIMEOUT,
)
from crypto_utils import generate_ed25519_keypair

logger = logging.getLogger("aurora-transport")


class DedupCache:
    def __init__(self, ttl: int = 60, max_size: int = 1024):
        self.ttl = ttl
        self.max_size = max_size
        self._store = {}

    def _prune(self):
        now = time.time()
        to_del = [k for k, ts in self._store.items() if now - ts > self.ttl]
        for k in to_del:
            self._store.pop(k, None)
        if len(self._store) > self.max_size:
            # drop oldest
            for k, _ in sorted(self._store.items(), key=lambda x: x[1])[: len(self._store) - self.max_size]:
                self._store.pop(k, None)

    def seen(self, msg_id: bytes) -> bool:
        self._prune()
        if msg_id in self._store:
            return True
        self._store[msg_id] = time.time()
        return False


def generate_pow(node_id_hex: str, bits: int = POW_LEADING_ZERO_BITS) -> str:
    target_prefix = "0" * (bits // 4)
    ts = int(time.time())
    while True:
        nonce = os.urandom(8)
        h = hashlib.sha256(bytes.fromhex(node_id_hex) + ts.to_bytes(8, "big") + nonce).hexdigest()
        if h.startswith(target_prefix):
            return nonce.hex()


class RateLimiter:
    def __init__(self):
        self._buckets = {}

    def allow(self, key: str, limit: int, window: int) -> bool:
        now = time.time()
        bucket = self._buckets.get(key, {"ts": now, "cnt": 0})
        if now - bucket["ts"] > window:
            bucket = {"ts": now, "cnt": 0}
        bucket["cnt"] += 1
        self._buckets[key] = bucket
        return bucket["cnt"] <= limit


class SoftBan:
    def __init__(self):
        self._bans = {}

    def ban(self, key: str, seconds: int = 60):
        self._bans[key] = time.time() + seconds

    def is_banned(self, key: str) -> bool:
        exp = self._bans.get(key)
        if not exp:
            return False
        if time.time() > exp:
            self._bans.pop(key, None)
            return False
        return True


class SlidingCounter:
    def __init__(self):
        self._bucket = {}

    def inc(self, key: str, window: int) -> int:
        now = time.time()
        ts, cnt = self._bucket.get(key, (now, 0))
        if now - ts > window:
            ts, cnt = now, 0
        cnt += 1
        self._bucket[key] = (ts, cnt)
        return cnt


class AuroraTransport:
    def __init__(self, priv_hex: Optional[str] = None, pub_hex: Optional[str] = None, udp_port: int = 9000):
        if priv_hex is None or pub_hex is None:
            priv_hex, pub_hex = generate_ed25519_keypair()
        self.priv_hex = priv_hex
        self.pub_hex = pub_hex
        self.node_id = make_node_id(pub_hex)
        self.udp_port = udp_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", udp_port))
        self.sock.setblocking(False)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._recv_loop, daemon=True)
        self.dedup = DedupCache()
        self.handlers = {}  # msg_type -> callable(msg, addr)
        self.on_hp = None  # callback(msg, addr) when HP established
        self.relay_sessions = {}  # peer_addr -> {"ts": timestamp, "bytes": int}
        self.rate = RateLimiter()
        self.soft_ban = SoftBan()
        self.hp_token_resolver: Optional[Callable[[bytes], Optional[bytes]]] = None  # callable(remote_node_id_bytes)->token
        self.pow_overload = False
        self.allowed_capabilities = set(CAPABILITIES)
        self.on_relay_data = None  # callable(payload: dict, addr)
        self.relay_enabled = True
        self.discovery_counter = SlidingCounter()
        logger.info(f"AuroraTransport bound on udp://0.0.0.0:{udp_port} node_id={self.node_id}")

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except Exception:
            pass

    def register_handler(self, msg_type: MsgType, handler):
        self.handlers[msg_type] = handler

    def _recv_loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except BlockingIOError:
                time.sleep(0.01)
                continue
            except Exception as exc:
                logger.debug(f"recv error: {exc}")
                time.sleep(0.05)
                continue
            if len(data) > MAX_MSG_SIZE:
                continue
            try:
                msg = decode_msg(data)
            except Exception as exc:
                logger.debug(f"decode failed from {addr}: {exc}")
                continue
            mid = msg_id(msg)
            if self.dedup.seen(mid):
                continue
            mtype_val = msg.get(2)
            mtype = MsgType(mtype_val) if mtype_val in [mt.value for mt in MsgType] else None
            nid = msg.get(3, b"") or b""
            key = nid.hex() if isinstance(nid, (bytes, bytearray)) else str(addr)
            if self.soft_ban.is_banned(key):
                continue
            # version check
            if msg.get(1) != PROTO_VERSION:
                self.soft_ban.ban(key, seconds=300)
                continue
            # capability check on announce/peer_list
            if mtype in {MsgType.ANNOUNCE, MsgType.PEER_LIST}:
                payload = msg.get(7, {}) or {}
                caps = payload.get("capabilities", [])
                if caps and isinstance(caps, list):
                    if not set(caps).intersection(self.allowed_capabilities) or "udp_hp" not in caps:
                        self.soft_ban.ban(key, seconds=300)
                        continue
        if mtype in {MsgType.ANNOUNCE, MsgType.DISCOVERY_REQUEST, MsgType.ROOM_CREATE, MsgType.ROOM_JOIN}:
            cnt = self.discovery_counter.inc(key, DISCOVERY_WINDOW_SEC)
            if cnt > DISCOVERY_LIMIT:
                self.pow_overload = True
                self.soft_ban.ban(key, seconds=60)
                continue
        require_pow = mtype in {
            MsgType.ANNOUNCE,
            MsgType.DISCOVERY_REQUEST,
            MsgType.ROOM_CREATE,
            MsgType.ROOM_JOIN,
            MsgType.PEER_LIST,
            MsgType.RELAY_OFFER,
            MsgType.RELAY_DATA,
            MsgType.RELAY_CLOSE,
            MsgType.FRAUD_PROOF,
            MsgType.REPUTATION_UPDATE,
        } if mtype else True
            ok, reason = validate_incoming(msg, require_pow=require_pow)
            if not ok:
                self.soft_ban.ban(key, seconds=60)
                logger.debug(f"drop msg from {addr} nid={key} reason={reason}")
                continue
            if mtype and mtype in RATE_LIMIT_DEFAULTS:
                limit, window = RATE_LIMIT_DEFAULTS[mtype]
                if not self.rate.allow(key, limit, window):
                    # escalate pow requirement on overload
                    self.pow_overload = True
                    self.soft_ban.ban(key, seconds=30)
                    continue
            handler = self.handlers.get(MsgType(mtype)) if mtype in [mt.value for mt in MsgType] else None
            if handler:
                try:
                    handler(msg, addr)
                except Exception as exc:
                    logger.debug(f"handler error {mtype} from {addr}: {exc}")

    def send_msg(self, addr: Tuple[str, int], msg_type: MsgType, payload: dict, pow_bits: int = POW_LEADING_ZERO_BITS):
        ts = int(time.time())
        bits = POW_LEADING_ZERO_BITS_OVERLOAD if self.pow_overload else pow_bits
        pow_nonce = generate_pow(self.node_id, bits=bits)
        # attach capabilities on announce/peer_list to help remote validate
        if msg_type in {MsgType.ANNOUNCE, MsgType.PEER_LIST}:
            payload = dict(payload)
            payload.setdefault("capabilities", list(self.allowed_capabilities))
        msg = build_msg_common(msg_type, self.node_id, self.pub_hex, payload, pow_nonce=pow_nonce, timestamp=ts)
        msg = attach_signature(msg, self.priv_hex)
        data = encode_msg(msg)
        if len(data) > MAX_MSG_SIZE:
            raise ValueError("message too large")
        self.sock.sendto(data, addr)



    def _on_hp_probe(self, msg: dict, addr):
        try:
            payload = msg.get(7, {}) or {}
            nonce = payload.get("nonce")
            mac = payload.get("mac", b"")
            remote_nid = msg.get(3, b"")
            token = self.hp_token_resolver(remote_nid) if self.hp_token_resolver else None
            if token:
                expected_mac = hmac_hp(token, nonce, remote_nid)
                if not mac or mac != expected_mac:
                    return
                ack_payload = {"nonce": nonce, "mac": hmac_hp(token, nonce, bytes.fromhex(self.node_id))}
            else:
                ack_payload = {"nonce": nonce}
            ack = build_msg_common(MsgType.HP_ACK, self.node_id, self.pub_hex, ack_payload)
            ack = attach_signature(ack, self.priv_hex)
            self.sock.sendto(encode_msg(ack), addr)
        except Exception as exc:
            logger.debug(f"hp_probe error from {addr}: {exc}")

    def _on_hp_ack(self, msg: dict, addr):
        try:
            payload = msg.get(7, {}) or {}
            if self.on_hp:
                remote_nid = msg.get(3, b"")
                mac = payload.get("mac", b"")
                nonce = payload.get("nonce", b"")
                token = self.hp_token_resolver(remote_nid) if self.hp_token_resolver else None
                if token:
                    expected_mac = hmac_hp(token, nonce, remote_nid)
                    if not mac or mac != expected_mac:
                        return
                self.on_hp(msg, addr)
        except Exception as exc:
            logger.debug(f"hp_ack error from {addr}: {exc}")

    def send_hp_probe(self, addr: tuple[str,int], nonce: bytes, shared_token: Optional[bytes] = None):
        payload = {"nonce": nonce}
        if shared_token:
            payload["mac"] = hmac_hp(shared_token, nonce, bytes.fromhex(self.node_id))
        msg = build_msg_common(MsgType.HP_PROBE, self.node_id, self.pub_hex, payload)
        msg = attach_signature(msg, self.priv_hex)
        data = encode_msg(msg)
        if len(data) > MAX_MSG_SIZE:
            raise ValueError("message too large")
        self.sock.sendto(data, addr)


    def _on_relay_data(self, msg: dict, addr):
        if not self.relay_enabled:
            return
        payload = msg.get(7, {}) or {}
        data = payload.get("data", b"")
        # drop if no relay session exists for sender
        if addr not in self.relay_sessions:
            return
        counter = self._relay_counter(addr, len(data))
        if counter > MAX_RELAY_RATE_BYTES_PER_MIN:
            return
        self.relay_sessions[addr]["bytes"] = counter
        if self.on_relay_data:
            try:
                self.on_relay_data(payload, addr)
            except Exception as exc:
                logger.debug(f"relay data handler error: {exc}")

    def _on_relay_close(self, msg: dict, addr):
        self.relay_sessions.pop(addr, None)

    def send_relay_data(self, addr: tuple[str,int], data: bytes):
        if not self.relay_enabled:
            raise ValueError("relay disabled")
        payload = {"data": data}
        msg = build_msg_common(MsgType.RELAY_DATA, self.node_id, self.pub_hex, payload)
        msg = attach_signature(msg, self.priv_hex)
        encoded = encode_msg(msg)
        if len(encoded) > MAX_MSG_SIZE:
            raise ValueError("relay data too large")
        counter = self._relay_counter(addr, len(data))
        if counter > MAX_RELAY_RATE_BYTES_PER_MIN:
            raise ValueError("relay rate limit exceeded")
        self.sock.sendto(encoded, addr)

    def close_relay(self, addr: tuple[str,int]):
        payload = {}
        msg = build_msg_common(MsgType.RELAY_CLOSE, self.node_id, self.pub_hex, payload)
        msg = attach_signature(msg, self.priv_hex)
        self.sock.sendto(encode_msg(msg), addr)

    def _relay_counter(self, addr: tuple[str, int], delta: int) -> int:
        now = time.time()
        entry = self.relay_sessions.get(addr, {"ts": now, "bytes": 0})
        if addr not in self.relay_sessions and len(self.relay_sessions) >= MAX_RELAY_SESSIONS:
            return MAX_RELAY_RATE_BYTES_PER_MIN + delta
        if now - entry["ts"] > 60:
            entry = {"ts": now, "bytes": 0}
        entry["bytes"] += delta
        self.relay_sessions[addr] = entry
        return entry["bytes"]
