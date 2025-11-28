"""
Aurora-Net P2P Protocol scaffolding (types/constants, no transport yet).
Defines message types, limits, signing/PoW/HMAC helpers. Target wire: CBOR.
"""

import enum
import time
import os
import hmac
import hashlib
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Tuple

from crypto_utils import sign_ed25519, verify_ed25519

PROTO_VERSION = 1
CAPABILITIES = [
    "udp_hp",
    "relay_v1",
    "pow16",
    "room_v1",
    "peerlist_v1",
]


class MsgType(enum.IntEnum):
    STUN_REQUEST = 1
    STUN_RESPONSE = 2
    ANNOUNCE = 3
    DISCOVERY_REQUEST = 4
    ROOM_CREATE = 5
    ROOM_JOIN = 6
    HP_START = 7
    HP_FAIL = 8
    RELAY_OFFER = 9
    PEER_LIST = 10
    HEARTBEAT = 11
    HP_PROBE = 12
    HP_ACK = 13
    RELAY_ACK = 14
    RELAY_DATA = 15
    RELAY_CLOSE = 26
    BLOCK = 16
    TX = 17
    PROPOSAL = 18
    VOTE = 19
    CHECKPOINT = 20
    CHAIN_REQUEST = 21
    CHAIN_RESPONSE = 22
    HEARTBEAT_SIGNED = 23
    MEMPOOL_REQUEST = 24
    MEMPOOL_RESPONSE = 25
    REQUEST_CHUNK = 27
    CHUNK_RESPONSE = 28
    FRAUD_PROOF = 29
    REPUTATION_UPDATE = 30

# Limits and defaults
MAX_MSG_SIZE = 2048  # bytes
MAX_PEERS_PER_LIST = 32
MAX_ENDPOINTS_PER_PEER = 2
MAX_PEERS_STORED = 1024
MAX_RELAY_SESSIONS = 16
MAX_RELAY_RATE_BYTES_PER_MIN = 5000000
POW_LEADING_ZERO_BITS = int(os.environ.get("AURORA_POW_BITS", "14"))
POW_LEADING_ZERO_BITS_OVERLOAD = POW_LEADING_ZERO_BITS + 4
DEDUP_CACHE_SIZE = 1024
DEDUP_TTL_SEC = 60
DISCOVERY_POW_BASE = POW_LEADING_ZERO_BITS
DISCOVERY_POW_OVERLOAD = POW_LEADING_ZERO_BITS_OVERLOAD
DISCOVERY_WINDOW_SEC = 60
DISCOVERY_LIMIT = 50
HP_PROBE_COUNT = 50
HP_PROBE_TIMEOUT = 3.0
RELAY_TTL_MIN = 60
RELAY_TTL_MAX = 300
HMAC_ALGO = hashlib.sha256
HMAC_SIZE = 16
NODE_ID_SIZE = 32
NONCE_SIZE = 16
HP_NONCE_SIZE = 8
SIGNATURE_SIZE = 64  # expected ed25519 signature length in bytes
TIMESTAMP_WINDOW = int(os.environ.get("AURORA_TS_WINDOW", "300"))
MAX_MSG_CACHE = 1024
MAX_HP_PROBES_PER_MIN = 100

# Rate limits (per node_id) – soft caps, ban if exceeded repeatedly
RATE_LIMIT_DEFAULTS = {
    MsgType.ANNOUNCE: (1, 20),  # 1 per 20s
    MsgType.ROOM_CREATE: (2, 60),
    MsgType.ROOM_JOIN: (5, 60),
    MsgType.PEER_LIST: (2, 60),
    MsgType.STUN_REQUEST: (1, 10),
}


def make_node_id(pubkey_hex: str) -> str:
    return hashlib.blake2b(bytes.fromhex(pubkey_hex), digest_size=32).hexdigest()


def pow_valid(node_id_hex: str, timestamp: int, pow_nonce: str, bits: int = POW_LEADING_ZERO_BITS) -> bool:
    data = bytes.fromhex(node_id_hex) + timestamp.to_bytes(8, "big") + bytes.fromhex(pow_nonce)
    h = hashlib.sha256(data).hexdigest()
    prefix = "0" * (bits // 4)
    return h.startswith(prefix)


def sign_payload(priv_hex: str, msg: bytes) -> str:
    return sign_ed25519(msg, priv_hex)


def verify_signature(sig_hex: str, msg: bytes, pub_hex: str) -> bool:
    return verify_ed25519(sig_hex, msg, pub_hex)


def hmac_hp(shared_token: bytes, nonce: bytes, node_id: bytes) -> bytes:
    return hmac.new(shared_token, nonce + node_id, HMAC_ALGO).digest()[:HMAC_SIZE]


def make_shared_hp_token(pub_a_hex: str, pub_b_hex: str, room_id: bytes) -> bytes:
    parts = [bytes.fromhex(pub_a_hex), bytes.fromhex(pub_b_hex)]
    parts.sort()
    return hashlib.sha256(parts[0] + parts[1] + room_id).digest()


@dataclass
class Endpoint:
    proto: str  # "udp" or "tcp"
    host: str
    port: int

    def to_uri(self) -> str:
        return f"{self.proto}://{self.host}:{self.port}"

    @staticmethod
    def from_uri(uri: str) -> "Endpoint":
        proto, rest = uri.split("://", 1)
        host, port_s = rest.rsplit(":", 1)
        return Endpoint(proto=proto, host=host, port=int(port_s))


@dataclass
class PeerInfo:
    node_id: str
    endpoints: List[str]
    last_seen: int
    role_flags: int = 0
    score_hint: int = 0


def current_ts() -> int:
    return int(time.time())


def _is_recent_ts(ts: int, window: int = TIMESTAMP_WINDOW) -> bool:
    try:
        now = current_ts()
        return abs(now - int(ts)) <= window
    except Exception:
        return False


def _validate_basic_frame(msg: Dict[str, Any], require_pow: bool = True) -> tuple[bool, str]:
    """Basic frame checks: version, type, node id size, pubkey size, ts window, pow (optional) and signature presence.

    Returns (ok, error_code)
    """
    try:
        ver = msg.get(1)
        if ver != PROTO_VERSION:
            return False, "bad_version"
        mtype = msg.get(2)
        if mtype not in [mt.value for mt in MsgType]:
            return False, "bad_type"
        nid = msg.get(3)
        pub = msg.get(4)
        ts = msg.get(5)
        nonce = msg.get(6)
        pow_nonce = msg.get(9, b"")

        if not (isinstance(nid, (bytes, bytearray)) and len(nid) == NODE_ID_SIZE):
            return False, "bad_node_id"
        if not (isinstance(pub, (bytes, bytearray)) and len(pub) in (32, 33)):
            return False, "bad_pub"
        if not isinstance(ts, int) or not _is_recent_ts(ts):
            return False, "bad_ts"
        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != NONCE_SIZE:
            return False, "bad_nonce"
        if require_pow:
            if not pow_nonce or not isinstance(pow_nonce, (bytes, bytearray)):
                return False, "pow_missing"
            if not pow_valid(nid.hex(), ts, pow_nonce.hex(), bits=POW_LEADING_ZERO_BITS):
                return False, "pow_invalid"
        # signature check is done outside using verify_msg_signature
    except Exception:
        return False, "exception"
    return True, ""


def build_msg_common(msg_type: MsgType, node_id: str, pubkey: str, payload: Dict[str, Any], pow_nonce: Optional[str] = None, timestamp: Optional[int] = None) -> Dict[str, Any]:
    return {
        1: PROTO_VERSION,
        2: int(msg_type),
        3: bytes.fromhex(node_id),
        4: bytes.fromhex(pubkey),
        5: timestamp if timestamp is not None else current_ts(),
        6: os.urandom(16),
        7: payload,
        9: bytes.fromhex(pow_nonce) if pow_nonce else b"",
    }

try:
    import cbor2
except ImportError:
    cbor2 = None


def encode_msg(msg: Dict[str, Any]) -> bytes:
    if not cbor2:
        raise RuntimeError("cbor2 not installed")
    return cbor2.dumps(msg)


def decode_msg(data: bytes) -> Dict[str, Any]:
    if not cbor2:
        raise RuntimeError("cbor2 not installed")
    return cbor2.loads(data)


def attach_signature(msg: Dict[str, Any], priv_hex: str) -> Dict[str, Any]:
    tmp = dict(msg)
    tmp.pop(8, None)
    encoded = encode_msg(tmp)
    sig = sign_payload(priv_hex, encoded)
    msg[8] = bytes.fromhex(sig)
    return msg


def verify_msg_signature(msg: Dict[str, Any]) -> bool:
    sig = msg.get(8)
    if not sig:
        return False
    tmp = dict(msg)
    tmp.pop(8, None)
    encoded = encode_msg(tmp)
    pub = tmp.get(4)
    if not pub:
        return False
    return verify_signature(sig.hex(), encoded, pub.hex())


def msg_id(msg: Dict[str, Any]) -> bytes:
    mtype = msg.get(2, b"")
    nonce = msg.get(6, b"")
    nid = msg.get(3, b"")
    return hashlib.sha256(bytes([mtype]) + nonce + nid).digest()


def validate_incoming(msg: Dict[str, Any], require_pow: bool = True) -> tuple[bool, str]:
    # run basic frame validation first
    ok, reason = _validate_basic_frame(msg, require_pow=require_pow)
    if not ok:
        return False, reason

    # signature verification - ensure signature exists and verifies
    if not verify_msg_signature(msg):
        return False, "bad_sig"

    # Per-message payload validation
    try:
        mtype_val = msg.get(2)
        mtype = MsgType(mtype_val)
        payload = msg.get(7, {}) or {}

        if mtype == MsgType.ANNOUNCE:
            # endpoints array, capabilities list, ttl
            if not isinstance(payload, dict):
                return False, "bad_payload"
            endpoints = payload.get("endpoints", [])
            if not isinstance(endpoints, list) or len(endpoints) == 0:
                return False, "bad_payload_endpoints"
            for ep in endpoints:
                if not isinstance(ep, str) or "://" not in ep:
                    return False, "bad_endpoint"
            caps = payload.get("capabilities", [])
            if caps and not isinstance(caps, list):
                return False, "bad_caps"

        elif mtype == MsgType.PEER_LIST:
            peers = payload.get("peers", [])
            if not isinstance(peers, list) or len(peers) > MAX_PEERS_PER_LIST:
                return False, "bad_peerlist"
            for p in peers:
                if not isinstance(p, dict):
                    return False, "bad_peer_entry"
                nid = p.get(1)
                if not (isinstance(nid, (bytes, bytearray)) and len(nid) == NODE_ID_SIZE):
                    return False, "bad_peer_node_id"

        elif mtype == MsgType.HP_PROBE:
            nonce = payload.get("nonce")
            mac = payload.get("mac", b"")
            if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != HP_NONCE_SIZE:
                return False, "bad_hp_nonce"
            if mac and not isinstance(mac, (bytes, bytearray)):
                return False, "bad_hp_mac"

        elif mtype == MsgType.ROOM_CREATE:
            participants = payload.get("participants", [])
            ttl = payload.get("ttl")
            if not isinstance(participants, list) or len(participants) > 8:
                return False, "bad_room_participants"
            if not isinstance(ttl, int) or ttl <= 0 or ttl > 120:
                return False, "bad_room_ttl"

        # additional types: RELAY_DATA size checks etc.
        if mtype == MsgType.RELAY_DATA:
            data = payload.get("data", b"")
            if not isinstance(data, (bytes, bytearray)):
                return False, "bad_relay_data"
            if len(data) > MAX_MSG_SIZE:
                return False, "relay_data_too_large"

    except Exception:
        return False, "exception"

    return True, ""
