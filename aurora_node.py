"""

Aurora-Net óçåë: îáúÿâëåíèÿ, peer_list, HP-âàëèäàöèÿ, êîìíàòû HP-êîîðäèíàöèè è çà÷àòîê relay (ó÷¸ò/ëèìèòû).

"""

import threading

import time

import logging

import os

import random

import socket

import json

from typing import Dict, Tuple, List



from aurora_protocol import (

    MsgType,

    PeerInfo,

    MAX_PEERS_PER_LIST,

    MAX_ENDPOINTS_PER_PEER,

    MAX_PEERS_STORED,

    MAX_RELAY_SESSIONS,

    MAX_RELAY_RATE_BYTES_PER_MIN,

    pow_valid,

    POW_LEADING_ZERO_BITS,

    POW_LEADING_ZERO_BITS_OVERLOAD,

    make_shared_hp_token,

    CAPABILITIES,

    PROTO_VERSION,

    HP_PROBE_COUNT,

    HP_PROBE_TIMEOUT,

)

from aurora_transport import AuroraTransport

from crypto_utils import generate_ed25519_keypair

from crypto_utils import sign_ed25519, verify_ed25519



logger = logging.getLogger("aurora-node")



ANNOUNCE_INTERVAL = 30

PEERLIST_INTERVAL = 40

ROOM_INTERVAL = 60

HP_INTERVAL = 30

HEARTBEAT_INTERVAL_MIN = 20

HEARTBEAT_INTERVAL_MAX = 40

PEER_TTL = 600

PEERLIST_TTL = 600

COORD_WHITELIST = set(os.environ.get("AURORA_COORD_WHITELIST", "").split(",")) if os.environ.get("AURORA_COORD_WHITELIST") else set()

PUBLIC_STUN_SERVERS = [

    "stun.l.google.com:19302",

    "stun1.l.google.com:19302",

    "stun2.l.google.com:19302",

    "stun3.l.google.com:19302",

    "stun4.l.google.com:19302",

]



class AuroraNode:

    def __init__(self, transport: AuroraTransport, bootstrap_peers: List[Tuple[str, int]] = None, on_new_peer=None):

        self.t = transport

        # Bootstrap: åñëè çàäàí ñïèñîê ÿâíî  èñïîëüçóåì åãî; èíà÷å áóäåì îïðåäåëÿòü ÷åðåç ïóáëè÷íûå STUN.

        self.known_peers_file = os.environ.get("AURORA_KNOWN_PEERS_FILE", "known_peers.json")

        self.bootstrap_peers = bootstrap_peers or self._load_known_peers()

        self.peers: Dict[str, PeerInfo] = {}

        self._stop = threading.Event()

        self._threads: List[threading.Thread] = []

        self.on_new_peer = on_new_peer

        self.pending_hp: Dict[str, str] = {}  # endpoint -> node_id

        self.validated_hosts: set[str] = set()

        self.active_relays: set[str] = set()

        self.announce_last: Dict[str, float] = {}

        self.peerlist_last: Dict[str, float] = {}

        self.peer_pubs: Dict[str, str] = {}  # node_id -> pubkey hex

        self.room_tokens: Dict[str, bytes] = {}  # node_id -> shared HP token

        self.recent_rooms: list[str] = []

        self.capabilities: Dict[str, List[str]] = {}

        self.pending_peers: Dict[str, float] = {}  # node_id -> ts when pending (waiting for probe)

        self.hp_attempts: Dict[str, Dict[str, float]] = {}  # nid -> {"ts": last_window_start, "cnt": int}

        self.negotiated_caps: Dict[str, List[str]] = {}

        self.validated_peers: set[str] = set()

        self.relay_requested: set[str] = set()

        self.peer_state: Dict[str, str] = {}  # nid -> HP/ONEWAY/RELAY/OK

        self.peer_state_ts: Dict[str, float] = {}  # nid -> last state ts

        self.one_way_attempts: Dict[str, int] = {}

        self.blocked_peers: set[str] = set()

        self.relay_endpoints: Dict[str, str] = {}  # nid -> relay endpoint

        self.relay_ts: Dict[str, float] = {}

        self.blocked_peers_ts: Dict[str, float] = {}

        self.last_seen: Dict[str, float] = {}

        self.chain_sync_done = False

        # êåø ÷àíêîâ (block_hash -> list of proofs with data/path)

        self.chunk_cache: Dict[str, list] = {}

        self.chunk_cache_order: list[str] = []

        # ðåïóòàöèÿ ìàéíåðîâ

        self.miner_rep: Dict[str, int] = {}

        self.banned_miners: set[str] = set()

        self.rep_threshold = int(os.environ.get("AURORA_REP_THRESHOLD", "-5"))

        self.rep_decay = float(os.environ.get("AURORA_REP_DECAY", "0.0"))
        self.rep_seen: set[str] = set()
        self.fraud_seen: set[str] = set()
        self.chunk_cache_limit = int(os.environ.get("AURORA_CHUNK_CACHE", "16"))
        self.proof_chunks_required = int(os.environ.get("AURORA_PROOF_CHUNKS", "4"))



        # NAT & relay tuning

        self.nat_info: Dict[str, dict] = {}  # nid -> {seen: (ip,port), nat_type: int}

        self.RELAY_SCORE_THRESHOLD = int(os.environ.get("AURORA_RELAY_SCORE_THRESHOLD", "10"))

        self.relay_sessions: Dict[str, dict] = {}

        # per-coordinator room creation timestamps (for rate limiting)

        self.coord_room_ts: Dict[str, list] = {}

        # tunables for hole-punching behavior (overridable in tests)

        self.HP_PROBE_TIMEOUT = float(os.environ.get("AURORA_HP_TIMEOUT", "3.0"))

        self.HP_PROBE_ATTEMPTS = int(os.environ.get("AURORA_HP_ATTEMPTS", "60"))

        self.public_stun = os.environ.get("AURORA_PUBLIC_STUN", "")

        if self.public_stun:

            # allow override via env; split and clean

            self.public_stun_list = [s.strip() for s in self.public_stun.split(",") if s.strip()]

        else:

            self.public_stun_list = PUBLIC_STUN_SERVERS

        # îáíàðóæåííûé ïóáëè÷íûé àäðåñ (host, port) äëÿ îáúÿâëåíèÿ

        self.public_binding: Tuple[str, int] | None = None

        self.white_peers: set[Tuple[str, int]] = set()

        # MQTT ñèãíàëèíã (äëÿ ñåðûõ óçëîâ)

        self.mqtt_enabled = os.environ.get("AURORA_MQTT_ENABLE", "1") in ("1", "true", "True")

        brokers_env = os.environ.get("AURORA_MQTT_BROKERS", "")

        if brokers_env:

            self.mqtt_brokers = [b.strip() for b in brokers_env.split(",") if b.strip()]

        else:

            # ïóáëè÷íûå áðîêåðû ïî óìîë÷àíèþ

            self.mqtt_brokers = ["test.mosquitto.org", "mqtt.eclipseprojects.io"]

        self.mqtt_prefix = os.environ.get("AURORA_MQTT_PREFIX", "aurora/signal")

        self.mqtt_presence_interval = float(os.environ.get("AURORA_MQTT_PRESENCE_SEC", "15"))

        self.mqtt_client = None

        self.mqtt_thread = None

        # seed relays (áåëûå óçëû/êîîðäèíàòîðû), èñïîëüçóåì ïðè sym-sym NAT

        seeds_env = os.environ.get("AURORA_SEED_RELAYS", "")

        self.seed_relays: List[Tuple[str, int]] = []

        if seeds_env:

            for item in seeds_env.split(","):

                item = item.strip()

                if not item:

                    continue

                try:

                    host, port = item.rsplit(":", 1)

                    self.seed_relays.append((host, int(port)))

                except Exception:

                    continue



        self.t.register_handler(MsgType.ANNOUNCE, self._on_announce)

        self.t.register_handler(MsgType.PEER_LIST, self._on_peer_list)

        self.t.register_handler(MsgType.STUN_REQUEST, self._on_stun_request)

        self.t.register_handler(MsgType.STUN_RESPONSE, self._on_stun_response)

        self.t.register_handler(MsgType.HP_PROBE, self._on_hp_probe)

        self.t.register_handler(MsgType.HP_ACK, self._on_hp_ack)

        self.t.register_handler(MsgType.HEARTBEAT, self._on_heartbeat)

        self.t.register_handler(MsgType.ROOM_CREATE, self._on_room_create)

        self.t.register_handler(MsgType.RELAY_OFFER, self._on_relay_offer)

        self.t.register_handler(MsgType.RELAY_ACK, self._on_relay_ack)

        self.t.register_handler(MsgType.BLOCK, self._on_block_msg)

        self.t.register_handler(MsgType.TX, self._on_tx_msg)

        self.t.register_handler(MsgType.PROPOSAL, self._on_proposal_msg)

        self.t.register_handler(MsgType.VOTE, self._on_vote_msg)

        self.t.register_handler(MsgType.CHECKPOINT, self._on_checkpoint_msg)

        self.t.register_handler(MsgType.CHAIN_REQUEST, self._on_chain_request)

        self.t.register_handler(MsgType.CHAIN_RESPONSE, self._on_chain_response)

        self.t.register_handler(MsgType.HEARTBEAT_SIGNED, self._on_heartbeat)

        self.t.register_handler(MsgType.MEMPOOL_REQUEST, self._on_mempool_request)

        self.t.register_handler(MsgType.MEMPOOL_RESPONSE, self._on_mempool_response)

        self.t.register_handler(MsgType.REQUEST_CHUNK, self._on_request_chunk)

        self.t.register_handler(MsgType.CHUNK_RESPONSE, self._on_chunk_response)

        self.t.register_handler(MsgType.FRAUD_PROOF, self._on_fraud_proof)

        self.t.register_handler(MsgType.REPUTATION_UPDATE, self._on_rep_update)

        self.t.register_handler(MsgType.RELAY_CLOSE, self._on_relay_close)

        # placeholders for chunk requests/ fraud proofs if needed

        self.t.on_hp = self._on_hp_success

        self.t.hp_token_resolver = lambda nid_bytes: self.room_tokens.get(nid_bytes.hex())

        self.t.on_relay_data = self._on_relay_data



    def _check_pow(self, msg: dict, overload: bool = False) -> bool:

        try:

            nid = msg.get(3, b"").hex()

            ts = msg.get(5, 0)

            pow_nonce = msg.get(9, b"").hex() if msg.get(9) else ""

            if not pow_nonce:

                return False

            if abs(time.time() - float(ts)) > 300:

                return False

            bits = POW_LEADING_ZERO_BITS_OVERLOAD if overload or getattr(self.t, "pow_overload", False) else POW_LEADING_ZERO_BITS

            return pow_valid(nid, int(ts), pow_nonce, bits)

        except Exception:

            return False



    def _remember_pub(self, msg: dict):

        try:

            nid = msg.get(3, b"")

            pub = msg.get(4, b"")

            if isinstance(nid, (bytes, bytearray)) and isinstance(pub, (bytes, bytearray)) and len(pub) in (32, 33):

                self.peer_pubs[nid.hex()] = pub.hex()

        except Exception:

            pass



    def _cap_compatible(self, nid: str) -> bool:

        caps = self.negotiated_caps.get(nid, [])

        return "udp_hp" in caps



    def _register_room_tokens(self, room_id_hex: str, participants: list):

        try:

            room_bytes = bytes.fromhex(room_id_hex)

        except Exception:

            return

        for p in participants:

            try:

                nid = p.get("node_id")

                pub = p.get("pubkey") or self.peer_pubs.get(nid)

                if not nid or not pub:

                    continue

                token = make_shared_hp_token(self.t.pub_hex, pub, room_bytes)

                self.room_tokens[nid] = token

            except Exception:

                continue



    def start(self):

        self.t.start()

        # åñëè bootstrap íå çàäàí, ïîïðîáóåì ÷åðåç ïóáëè÷íûé STUN îïðåäåëèòü ñâîé àäðåñ è îáúÿâèòüñÿ

        if not self.bootstrap_peers:

            self._discover_via_public_stun()

        self._threads = [

            threading.Thread(target=self._announce_loop, daemon=True),

            threading.Thread(target=self._peerlist_loop, daemon=True),

            threading.Thread(target=self._hp_loop, daemon=True),

            threading.Thread(target=self._room_loop, daemon=True),

            threading.Thread(target=self._heartbeat_loop, daemon=True),

        ]

        for th in self._threads:

            th.start()

        # MQTT ñèãíàëèíã âêëþ÷àåì, òîëüêî åñëè íåò ÿâíûõ ñèäîâ (èç ôàéëà/áåëûõ óçëîâ)

        if self.mqtt_enabled and not self.bootstrap_peers and not self.white_peers:

            self._start_mqtt_signaling()

        # initial bootstrap request via Aurora

        threading.Thread(target=self._request_chain_bootstrap, daemon=True).start()

        # initial bootstrap request

        self._request_chain_bootstrap()



    def stop(self):

        self._stop.set()

        self.t.stop()

        try:

            if self.mqtt_client:

                self.mqtt_client.loop_stop()

                self.mqtt_client.disconnect()

        except Exception:

            pass



    def _announce_loop(self):

        while not self._stop.is_set():

            try:

                roles = ["peer"]

                if self.public_binding:

                    roles.append("stun_candidate")

                pub_host = self._public_host()

                pub_port = self.public_binding[1] if self.public_binding else self.t.udp_port

                payload = {

                    "endpoints": [f"udp://{pub_host}:{pub_port}"],

                    "roles": roles,

                    "ttl": ANNOUNCE_INTERVAL + 10,

                    "capabilities": CAPABILITIES,

                }

                self._broadcast(MsgType.ANNOUNCE, payload)

            except Exception as exc:

                logger.debug(f"announce loop error: {exc}")

            self._stop.wait(ANNOUNCE_INTERVAL)



    def _peerlist_loop(self):

        while not self._stop.is_set():

            try:

                self._prune_pending()

                peers_payload = {"peers": []}

                for nid, info in list(self.peers.items())[:MAX_PEERS_PER_LIST]:

                    if nid in self.validated_peers:

                        role_flags = info.role_flags if isinstance(info.role_flags, int) else 0

                        score_hint = info.score_hint if isinstance(info.score_hint, int) else 0

                        peers_payload["peers"].append(

                            {

                                "node_id": nid,

                                "endpoints": info.endpoints[:2],

                                "last_seen": info.last_seen,

                                "role_flags": role_flags,

                                "score_hint": score_hint,

                                "capabilities": self.capabilities.get(nid, []),

                            }

                        )

                self._broadcast(MsgType.PEER_LIST, peers_payload)

            except Exception as exc:

                logger.debug(f"peerlist loop error: {exc}")

            self._stop.wait(PEERLIST_INTERVAL)



    def _room_loop(self):

        import os

        while not self._stop.is_set():

            try:

                peers_list = list(self.peers.values())

                if len(peers_list) >= 2:

                    participants = []

                    for info in peers_list[:4]:

                        participants.append({"node_id": info.node_id, "endpoints": info.endpoints[:2], "pubkey": self.peer_pubs.get(info.node_id)})

                    participants.append({"node_id": self.t.node_id, "endpoints": [f"udp://{self._public_host()}:{self.t.udp_port}"], "pubkey": self.t.pub_hex})

                    room_id = os.urandom(8).hex()

                    payload = {"room_id": room_id, "participants": participants, "ttl": 15, "roles": ["stun_candidate"]}

                    self._register_room_tokens(room_id, participants)

                    self._broadcast(MsgType.ROOM_CREATE, payload)

            except Exception:

                pass

            self._stop.wait(ROOM_INTERVAL)



    def _heartbeat_loop(self):

        while not self._stop.is_set():

            try:

                peers = list(self.validated_peers)

                if peers:

                    target = random.choice(peers)

                    info = self.peers.get(target)

                    if info and info.endpoints:

                        ep = info.endpoints[0]

                        # signed heartbeat payload

                        ts = int(time.time())

                        payload = {"ts": ts, "sender_pub": self.t.pub_hex}

                        import cbor2

                        encoded = cbor2.dumps(payload)

                        sig = sign_ed25519(encoded, self.t.priv_hex)

                        payload["sig"] = sig

                        if ep.startswith("udp://"):

                            host_port = ep.split("://", 1)[1]

                            host, port = host_port.split(":", 1)

                            self.t.send_msg((host, int(port)), MsgType.HEARTBEAT_SIGNED, payload)

                        elif self._relay_send(target, MsgType.HEARTBEAT, payload):

                            pass

            except Exception:

                pass

            self._stop.wait(random.randint(HEARTBEAT_INTERVAL_MIN, HEARTBEAT_INTERVAL_MAX))



    def _broadcast(self, mtype: MsgType, payload: dict):

        seed_peers = self.bootstrap_peers or list(self.white_peers)

        for host, port in seed_peers:

            try:

                self.t.send_msg((host, port), mtype, payload)

            except Exception as exc:

                logger.debug(f"broadcast to {(host, port)} failed: {exc}")

        for nid in list(self.validated_peers):

            info = self.peers.get(nid)

            if not info or not info.endpoints:

                continue

            if nid in self.blocked_peers:

                continue

            ep = info.endpoints[0]

            if ep.startswith("udp://"):

                try:

                    host_port = ep.split("://", 1)[1]

                    host, port = host_port.split(":", 1)

                    self.t.send_msg((host, int(port)), mtype, payload)

                except Exception:

                    continue

            elif self._relay_send(nid, mtype, payload):

                continue



    def _prune_pending(self):

        now = time.time()

        for nid, ts in list(self.pending_peers.items()):

            if now - ts > 120:

                self.pending_peers.pop(nid, None)

                self.validated_peers.discard(nid)

                self.peer_state.pop(nid, None)

                self.peer_state_ts.pop(nid, None)

                self.relay_endpoints.pop(nid, None)

                self.relay_ts.pop(nid, None)

        for nid, ts in list(self.blocked_peers_ts.items()):

            if now - ts > 600:

                self.blocked_peers.discard(nid)

                self.blocked_peers_ts.pop(nid, None)

        for ep, nid in list(self.pending_hp.items()):

            # drop pending HP if too old

            if now - self.pending_peers.get(nid, now) > 120:

                self.pending_hp.pop(ep, None)

        for nid, ts in list(self.last_seen.items()):

            if now - ts > PEER_TTL:

                self.peers.pop(nid, None)

                self.validated_peers.discard(nid)

                self.pending_peers.pop(nid, None)

                self.peer_state.pop(nid, None)

                self.peer_state_ts.pop(nid, None)

                self.relay_endpoints.pop(nid, None)

                self.relay_ts.pop(nid, None)

                self.last_seen.pop(nid, None)

        # escalate to relay if HP_ACK too long without success

        for nid, state in list(self.peer_state.items()):

            ts = self.peer_state_ts.get(nid, 0)

            if state in ("HP", "HP_ACK") and now - ts > 30:

                if nid not in self.relay_requested and self.bootstrap_peers:

                    coord = self.bootstrap_peers[0]

                    try:

                        self.request_relay(coord, between=[self.t.node_id, nid])

                        self.relay_requested.add(nid)

                        self.peer_state[nid] = "RELAY_PENDING"

                        self.peer_state_ts[nid] = now

                    except Exception:

                        continue

            if state == "HP" and now - ts > 10:

                attempts = self.one_way_attempts.get(nid, 0)

                if attempts < 2:

                    self.one_way_attempts[nid] = attempts + 1

                    self.peer_state[nid] = "ONEWAY"

                    self.peer_state_ts[nid] = now

                    info = self.peers.get(nid)

                    if info and info.endpoints:

                        ep = info.endpoints[0]

                        if ep.startswith("udp://"):

                            try:

                                host_port = ep.split("://", 1)[1]

                                host, port = host_port.split(":", 1)

                                # one-way attempt: send probe without expecting return path change

                                self.t.send_hp_probe((host, int(port)), os.urandom(8), shared_token=self.room_tokens.get(nid))

                            except Exception:

                                pass

            if state == "RELAY_PENDING" and now - ts > 60:

                # relay info too stale

                self.relay_endpoints.pop(nid, None)

                self.relay_ts.pop(nid, None)



    def _on_announce(self, msg: dict, addr):

        try:

            from aurora_protocol import verify_msg_signature

            if not verify_msg_signature(msg):

                return

        except Exception:

            return

        if msg.get(1) != PROTO_VERSION:

            return

        # adaptive PoW check under overload

        if self.t.pow_overload and not self._check_pow(msg, overload=True):

            return

        self._remember_pub(msg)

        if self.t.pow_overload and not self._check_pow(msg, overload=True):

            return

        if not self._check_pow(msg):

            return

        payload = msg.get(7, {}) if isinstance(msg.get(7, {}), dict) else {}

        endpoints = payload.get("endpoints", [])

        caps = payload.get("capabilities", [])

        nid = msg.get(3, b"").hex()

        if nid in self.blocked_peers:

            return

        if caps and isinstance(caps, list):

            self.capabilities[nid] = [c for c in caps if isinstance(c, str)]

            common = [c for c in self.capabilities[nid] if c in CAPABILITIES]

            self.negotiated_caps[nid] = common

            if not self._cap_compatible(nid):

                self.blocked_peers.add(nid)

                self.blocked_peers_ts[nid] = time.time()

                return

        now = time.time()

        if nid in self.announce_last and now - self.announce_last.get(nid, 0) < 5:

            return

        if nid and endpoints:

            self.announce_last[nid] = now

            is_new = nid not in self.peers

            if len(self.peers) >= MAX_PEERS_STORED and not is_new:

                return

            self.pending_peers[nid] = now

            self.peers[nid] = PeerInfo(node_id=nid, endpoints=endpoints, last_seen=int(now))

            self.last_seen[nid] = now

            self._maybe_register_white_peer(endpoints[0])

            logger.debug(f"announce from {nid} endpoints={endpoints} caps={self.negotiated_caps.get(nid)} addr={addr}")

            validated = addr[0] in self.validated_hosts

            if validated:

                self._notify_peer(nid, endpoints, validated=True)

            if endpoints and not validated:

                ep = endpoints[0]

                self.pending_hp[ep] = nid

                if ep.startswith("udp://"):

                    try:

                        host_port = ep.split("://", 1)[1]

                        host, port = host_port.split(":", 1)

                        # probe-lite: single UDP ping to confirm reachability

                        try:

                            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                            sock.settimeout(0.2)

                            sock.sendto(b"probe", (host, int(port)))

                            sock.close()

                        except Exception:

                            pass

                        self.hp_initiate((host, int(port)), nid)

                    except Exception:

                        pass

            if is_new and validated:

                self._notify_peer(nid, endpoints, validated=True)



    def _on_peer_list(self, msg: dict, addr):

        try:

            from aurora_protocol import verify_msg_signature

            if not verify_msg_signature(msg):

                return

        except Exception:

            return

        if msg.get(1) != PROTO_VERSION:

            return

        self._remember_pub(msg)

        if not self._check_pow(msg):

            return

        payload = msg.get(7, {}) or {}

        plist = payload.get("peers", [])

        now = time.time()

        sender = msg.get(3, b"").hex()

        if sender in self.peerlist_last and now - self.peerlist_last.get(sender, 0) < 10:

            return

        self.peerlist_last[sender] = now

        for p in plist[:MAX_PEERS_PER_LIST]:

            try:

                nid = p.get("node_id")

                eps = p.get("endpoints", [])[:MAX_ENDPOINTS_PER_PEER]

                caps = p.get("capabilities", [])

                role_flags = p.get("role_flags", 0)

                score_hint = p.get("score_hint", 0)

                if not nid or not isinstance(nid, str) or len(nid) != 64:

                    continue

                eps_valid = [ep for ep in eps if isinstance(ep, str) and "://" in ep][:MAX_ENDPOINTS_PER_PEER]

                if not eps_valid:

                    continue

                if len(self.peers) >= MAX_PEERS_STORED and nid not in self.peers:

                    continue

                if nid in self.blocked_peers:

                    continue

                if caps and isinstance(caps, list):

                    self.capabilities[nid] = [c for c in caps if isinstance(c, str)]

                    common = [c for c in self.capabilities[nid] if c in CAPABILITIES]

                    self.negotiated_caps[nid] = common

                    if not self._cap_compatible(nid):

                        self.blocked_peers.add(nid)

                        self.blocked_peers_ts[nid] = time.time()

                        continue

                is_new = nid not in self.peers

                self.pending_peers[nid] = now

                info = PeerInfo(node_id=nid, endpoints=eps_valid, last_seen=now, role_flags=role_flags, score_hint=score_hint)

                self.peers[nid] = info

                self.last_seen[nid] = now

                self._maybe_register_white_peer(eps_valid[0])

                ep = eps_valid[0]

                self.pending_hp[ep] = nid

                if ep.startswith("udp://"):

                    try:

                        host_port = ep.split("://", 1)[1]

                        host, port = host_port.split(":", 1)

                        # probe-lite

                        try:

                            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                            sock.settimeout(0.2)

                            sock.sendto(b"probe", (host, int(port)))

                            sock.close()

                        except Exception:

                            pass

                        self.hp_initiate((host, int(port)), nid)

                    except Exception:

                        pass

                # notification deferred until validated

            except Exception:

                continue



    def _public_host(self):

        if self.public_binding:

            return self.public_binding[0]

        return self.bootstrap_peers[0][0] if self.bootstrap_peers else "127.0.0.1"



    # ---------------- Reputation helpers ----------------

    def _update_rep(self, miner: str, delta: int, broadcast: bool = True):
        rep = self.miner_rep.get(miner, 0)
        rep += delta
        if self.rep_decay and abs(rep) < 1000:
            rep = int(rep * (1.0 - self.rep_decay))
        self.miner_rep[miner] = rep
        if rep <= self.rep_threshold:
            self.banned_miners.add(miner)
        if broadcast and delta != 0:
            try:
                import hashlib, json
                ts = int(time.time())
                payload = {"miner": miner, "delta": delta, "ts": ts, "signer": self.t.pub_hex}
                h = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
                payload["sig"] = sign_ed25519(h.encode(), self.t.priv_hex)
                self._broadcast(MsgType.REPUTATION_UPDATE, payload)
            except Exception:
                pass



    def _broadcast_fraud_proof(self, miner: str, block_hash: str, proof: dict, reason: str):

        try:

            payload = {"miner": miner, "block_hash": block_hash, "proof": proof, "reason": reason, "ts": int(time.time()), "signer": self.t.pub_hex}

            import hashlib, json

            h = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

            payload["sig"] = sign_ed25519(h.encode(), self.t.priv_hex)

            self._broadcast(MsgType.FRAUD_PROOF, payload)

        except Exception:

            pass



    def _store_chunk_cache(self, block_hash: str, proofs: list):

        if not proofs:

            return

        self.chunk_cache[block_hash] = proofs

        self.chunk_cache_order = [h for h in self.chunk_cache_order if h != block_hash]

        self.chunk_cache_order.append(block_hash)

        max_cache = self.chunk_cache_limit

        while len(self.chunk_cache_order) > max_cache:

            oldest = self.chunk_cache_order.pop(0)

            self.chunk_cache.pop(oldest, None)



    def _is_public_ip(self, ip: str) -> bool:

        try:

            import ipaddress

            addr = ipaddress.ip_address(ip)

            return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast)

        except Exception:

            return False



    def _maybe_register_white_peer(self, ep: str):

        if not ep.startswith("udp://"):

            return

        try:

            host_port = ep.split("://", 1)[1]

            host, port = host_port.split(":", 1)

            port = int(port)

            if self._is_public_ip(host):

                self.white_peers.add((host, port))

                self._save_known_peer(host, port)

        except Exception:

            return



    def _load_known_peers(self) -> List[Tuple[str, int]]:

        try:

            import json

            if not os.path.exists(self.known_peers_file):

                return []

            with open(self.known_peers_file, "r", encoding="utf-8") as f:

                data = json.load(f)

            peers = []

            for item in data:

                if isinstance(item, list) and len(item) == 2:

                    host, port = item

                    peers.append((host, int(port)))

            return peers

        except Exception as exc:

            logger.debug(f"load known peers failed: {exc}")

            return []



    def _save_known_peer(self, host: str, port: int):

        try:

            import json

            existing = set(self._load_known_peers())

            existing.add((host, int(port)))

            with open(self.known_peers_file, "w", encoding="utf-8") as f:

                json.dump(list(existing), f)

        except Exception as exc:

            logger.debug(f"save known peer failed: {exc}")



    def _hp_loop(self):

        while not self._stop.is_set():

            try:

                self._prune_pending()

                for info in list(self.peers.values())[:8]:

                    for ep in info.endpoints:

                        if ep.startswith("udp://"):

                            try:

                                host_port = ep.split("://", 1)[1]

                                host, port = host_port.split(":", 1)

                                self.hp_initiate((host, int(port)), info.node_id)

                                break

                            except Exception:

                                continue

            except Exception:

                pass

            self._stop.wait(HP_INTERVAL)



    def hp_initiate(self, peer_endpoint: Tuple[str, int], peer_nid: str = "", prefer_relay_after: int = 10):

        import os

        # rate-limit HP attempts per peer

        now = time.time()

        if peer_nid:

            bucket = self.hp_attempts.get(peer_nid, {"ts": now, "cnt": 0})

            if now - bucket["ts"] > 60:

                bucket = {"ts": now, "cnt": 0}

            if bucket["cnt"] >= prefer_relay_after:

                if peer_nid not in self.relay_requested and self.bootstrap_peers:

                    coord = self.bootstrap_peers[0]

                    try:

                        self.request_relay(coord, between=[self.t.node_id, peer_nid])

                        self.relay_requested.add(peer_nid)

                        self.peer_state[peer_nid] = "RELAY_PENDING"

                        self.peer_state_ts[peer_nid] = now

                    except Exception:

                        pass

                return

            bucket["cnt"] += 1

            self.hp_attempts[peer_nid] = bucket

            self.peer_state[peer_nid] = "HP"

            self.peer_state_ts[peer_nid] = now



        token = self.room_tokens.get(peer_nid) if peer_nid else None



        # ask remote to return their view (STUN) to help classify NAT

        try:

            self.t.send_msg(peer_endpoint, MsgType.STUN_REQUEST, {})

        except Exception:

            pass



        # HP: aggressive probing phase: 50 probes over ~3 seconds

        start = time.time()

        timeout = float(getattr(self, "HP_PROBE_TIMEOUT", 3.0))

        attempts = 0

        success = False

        max_attempts = int(getattr(self, "HP_PROBE_ATTEMPTS", 60))

        while time.time() - start < timeout and attempts < max_attempts:

            nonce = os.urandom(8)

            try:

                self.t.send_hp_probe(peer_endpoint, nonce, shared_token=token)

            except Exception:

                pass

            attempts += 1

            # if we already got ack/ok, break early

            if peer_nid and self.peer_state.get(peer_nid) in ("HP_ACK", "OK"):

                success = True

                break

            time.sleep(0.06)



        if success:

            return



        # One-way fallback: try briefly to do one-way probes (no persistent ack expected)

        one_way_start = time.time()

        one_way_timeout = 2.0

        if peer_nid:

            self.peer_state[peer_nid] = "ONEWAY"

            # increment one-way attempts counter

            self.one_way_attempts[peer_nid] = self.one_way_attempts.get(peer_nid, 0) + 1

        while time.time() - one_way_start < one_way_timeout:

            nonce = os.urandom(8)

            try:

                # one-way sends but do not require shared_token

                self.t.send_hp_probe(peer_endpoint, nonce, shared_token=None)

            except Exception:

                pass

            time.sleep(0.1)



        # if still not successful, escalate to requesting a relay (if configured)

        if peer_nid:

            bucket = self.hp_attempts.get(peer_nid, {"ts": time.time(), "cnt": 0})

            if bucket["cnt"] >= prefer_relay_after and peer_nid not in self.relay_requested and self.bootstrap_peers:

                coord = self.bootstrap_peers[0]

                try:

                    self.request_relay(coord, between=[self.t.node_id, peer_nid])

                    self.relay_requested.add(peer_nid)

                    self.peer_state[peer_nid] = "RELAY_PENDING"

                    self.peer_state_ts[peer_nid] = time.time()

                except Exception:

                    pass



    def _on_hp_probe(self, msg: dict, addr):

        logger.debug(f"hp_probe from {addr}")



    def _on_hp_ack(self, msg: dict, addr):

        logger.debug(f"hp_ack from {addr}")

        # could initiate one-way flow if still pending

        try:

            nid = msg.get(3, b"").hex()

            if nid in self.peer_state and self.peer_state.get(nid) != "OK":

                self.peer_state[nid] = "HP_ACK"

                self.peer_state_ts[nid] = time.time()

        except Exception:

            pass



    def _on_stun_request(self, msg: dict, addr):

        try:

            # Respond with observed remote address info so requester can deduce mapping

            payload = {"seen_ip": addr[0], "seen_port": addr[1], "nat_type": os.environ.get("AURORA_NAT_TYPE", "4")}

            self.t.send_msg(addr, MsgType.STUN_RESPONSE, payload)

        except Exception:

            pass



    def _on_stun_response(self, msg: dict, addr):

        try:

            nid = msg.get(3, b"").hex()

            payload = msg.get(7, {}) or {}

            seen_ip = payload.get("seen_ip")

            seen_port = payload.get("seen_port")

            nat_type = payload.get("nat_type")

            if nid:

                self.nat_info[nid] = {"seen": (seen_ip, seen_port), "nat_type": nat_type}

                # åñëè îáà óçëà symmetric NAT è åñòü seed relays, ñðàçó ïðîñèì relay

                try:

                    local_nat = self.get_local_nat_type()

                    remote_nat = int(nat_type) if nat_type is not None else 4

                    if local_nat == 3 and remote_nat == 3 and self.seed_relays:

                        for seed in self.seed_relays:

                            try:

                                self.request_relay(seed, between=[self.t.node_id, nid])

                                self.peer_state[nid] = "RELAY_PENDING"

                                self.peer_state_ts[nid] = time.time()

                                break

                            except Exception:

                                continue

                except Exception:

                    pass

        except Exception:

            pass



    def get_local_nat_type(self) -> int:

        """Return local node's NAT type (int)  by default read from env or unknown (4)."""

        try:

            val = os.environ.get("AURORA_NAT_TYPE", None)

            if val is None:

                return 4

            return int(val)

        except Exception:

            return 4



    def classify_nat_type(self, nid: str | None) -> int:

        """Return the classified NAT type for a peer (0..4)."""

        if not nid:

            return 4

        entry = self.nat_info.get(nid)

        if not entry:

            return 4

        try:

            return int(entry.get("nat_type", 4))

        except Exception:

            return 4



    def decide_connection_mode(self, peer_nid: str) -> str:

        """Decide preferred connection mode with a peer: 'HP', 'ONEWAY', or 'RELAY'.



        Heuristics:

        - If neither side is Symmetric (3) -> HP

        - If one side is Symmetric and the other is not -> ONEWAY

        - If both Symmetric -> RELAY

        - Unknown falls back to HP conservative mode

        """

        local = self.get_local_nat_type()

        remote = self.classify_nat_type(peer_nid)

        if local != 3 and remote != 3:

            return "HP"

        if (local == 3 and remote != 3) or (local != 3 and remote == 3):

            return "ONEWAY"

        return "RELAY"



    def _on_heartbeat(self, msg: dict, addr):

        try:

            from aurora_protocol import verify_msg_signature

            if not verify_msg_signature(msg):

                return

        except Exception:

            return

        try:

            nid = msg.get(3, b"").hex()

            self.last_seen[nid] = time.time()

        except Exception:

            pass



    def _on_hp_success(self, msg: dict, addr):
        try:
            nid = msg.get(3, b"").hex()
            self.validated_hosts.add(addr[0])
            for ep, eid in list(self.pending_hp.items()):
                if addr[0] in ep and nid == eid:
                    self.pending_hp.pop(ep, None)
                    self.validated_hosts.add(addr[0])
            info = self.peers.get(nid)
            if info:
                self.pending_peers.pop(nid, None)
                self.validated_peers.add(nid)
                try:
                    ep = info.endpoints[0]
                    if ep.startswith("udp://"):
                        host_port = ep.split("://", 1)[1]
                        host, port = host_port.split(":", 1)
                        self._save_known_peer(host, int(port))
                except Exception:
                    pass
            self.peer_state[nid] = "OK"
            self.relay_requested.discard(nid)
            self.last_seen[nid] = time.time()
            self._notify_peer(nid, info.endpoints if info else [], validated=True)
            logger.debug(f"hp success with {addr} node={nid}")
        except Exception as exc:
            logger.debug(f"hp success handler error: {exc}")



    def _on_room_create(self, msg: dict, addr):

        try:

            if msg.get(1) != PROTO_VERSION:

                return

            self._remember_pub(msg)

            if self.t.pow_overload and not self._check_pow(msg, overload=True):

                return

            if not self._check_pow(msg):

                return

            payload = msg.get(7, {}) or {}

            participants = payload.get("participants", [])

            ttl = payload.get("ttl", 0)

            coord = msg.get(3, b"").hex()

            roles = payload.get("roles", [])

            if not ttl or ttl > 15:

                return

            if len(participants) > 8:

                return

            if not self._cap_compatible(coord):

                return

            if COORD_WHITELIST and coord not in COORD_WHITELIST:

                return

            if "stun_candidate" not in roles:

                return

            # rate-limit rooms from a single coordinator: max 2 per minute

            room_window = 60

            cnt = sum(1 for r in self.recent_rooms if r == coord and (time.time() - self.last_seen.get(coord, 0)) < room_window)

            if cnt >= 2:

                return

            # rate-limit rooms from a single coordinator: max 2 per minute

            now = time.time()

            window = 60

            lst = self.coord_room_ts.get(coord, [])

            # prune old

            lst = [ts for ts in lst if now - ts <= window]

            if len(lst) >= 2:

                return

            lst.append(now)

            self.coord_room_ts[coord] = lst



            if len(self.recent_rooms) >= 3 and all(x == coord for x in self.recent_rooms[-3:]):

                return

            self.recent_rooms.append(coord)

            if len(self.recent_rooms) > 256:

                self.recent_rooms = self.recent_rooms[-256:]

            my_id = self.t.node_id

            if not any(p.get("node_id") == my_id for p in participants):

                return

            room_id = payload.get("room_id")

            if isinstance(room_id, str):

                self._register_room_tokens(room_id, participants)

            for p in participants:

                pid = p.get("node_id")

                if pid == my_id:

                    continue

                eps = p.get("endpoints", [])

                for ep in eps:

                    if ep.startswith("udp://"):

                        try:

                            host_port = ep.split("://", 1)[1]

                            host, port = host_port.split(":", 1)

                            self.hp_initiate((host, int(port)), pid)

                            break

                        except Exception:

                            continue

        except Exception as exc:

            logger.debug(f"room_create error from {addr}: {exc}")



    def _relay_health_check(self, relay_ep: str) -> bool:

        try:

            import socket

            if "://" in relay_ep:

                _, rest = relay_ep.split("://", 1)

            else:

                rest = relay_ep

            host, port = rest.rsplit(":", 1)

            port = int(port)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            sock.settimeout(0.5)

            sock.sendto(b"ping", (host, port))

            sock.close()

            return True

        except Exception:

            return False



    # ---------------- MQTT signaling (gray-to-gray rendezvous) ----------------

    def _start_mqtt_signaling(self):

        try:

            import paho.mqtt.client as mqtt

        except Exception as exc:

            logger.debug(f"mqtt disabled (paho missing): {exc}")

            return



        def _loop():

            for broker in self.mqtt_brokers:

                if self._stop.is_set():

                    return

                try:

                    client = mqtt.Client(client_id=self.t.node_id, clean_session=True)

                    will_payload = json.dumps({"sender": self.t.node_id, "type": "bye", "ts": time.time()})

                    client.will_set(f"{self.mqtt_prefix}/presence", will_payload)

                    client.on_connect = self._mqtt_on_connect

                    client.on_message = self._mqtt_on_message

                    client.connect(broker, 1883, 60)

                    client.loop_start()

                    self.mqtt_client = client

                    logger.info(f"mqtt signaling connected to {broker}")

                    while not self._stop.is_set():

                        self._mqtt_publish_presence()

                        time.sleep(self.mqtt_presence_interval)

                    client.loop_stop()

                    client.disconnect()

                    break

                except Exception as exc:

                    logger.debug(f"mqtt connect failed to {broker}: {exc}")

                    time.sleep(1)



        self.mqtt_thread = threading.Thread(target=_loop, daemon=True)

        self.mqtt_thread.start()



    def _mqtt_on_connect(self, client, userdata, flags, rc):

        try:

            client.subscribe(f"{self.mqtt_prefix}/presence")

            client.subscribe(f"{self.mqtt_prefix}/{self.t.node_id}")

            self._mqtt_publish_presence()

        except Exception as exc:

            logger.debug(f"mqtt on_connect error: {exc}")



    def _mqtt_on_message(self, client, userdata, msg):

        try:

            payload = json.loads(msg.payload.decode())

            sender = payload.get("sender")

            mtype = payload.get("type")

            data = payload.get("data", {}) or {}

            if not sender or sender == self.t.node_id:

                return

            if msg.topic == f"{self.mqtt_prefix}/presence":

                self._mqtt_handle_presence(sender, mtype, data)

            else:

                self._mqtt_handle_signal(sender, mtype, data)

        except Exception as exc:

            logger.debug(f"mqtt handle message failed: {exc}")



    def _mqtt_publish_presence(self):

        if not self.mqtt_client:

            return

        try:

            ep_host = self._public_host()

            ep_port = self.public_binding[1] if self.public_binding else self.t.udp_port

            payload = {

                "sender": self.t.node_id,

                "type": "hello",

                "data": {

                    "endpoint": f"udp://{ep_host}:{ep_port}",

                    "ts": time.time(),

                    "pub": self.t.pub_hex,

                },

            }

            self.mqtt_client.publish(f"{self.mqtt_prefix}/presence", json.dumps(payload))

        except Exception:

            pass



    def _mqtt_handle_presence(self, sender: str, mtype: str, data: dict):

        if mtype not in ("hello", "offer"):

            return

        ep = data.get("endpoint")

        pub = data.get("pub")

        if not ep or "://" not in ep:

            return

        # çàïèñûâàåì ïóáëè÷íûé êëþ÷ äëÿ HMAC òîêåíîâ

        if pub:

            self.peer_pubs[sender] = pub

        # Äîáàâëÿåì ïèðà è ñðàçó ïðîáóåì HP

        self._add_or_update_peer(sender, ep)

        try:

            host_port = ep.split("://", 1)[1]

            host, port = host_port.split(":", 1)

            self.hp_initiate((host, int(port)), sender)

        except Exception:

            pass



    def _mqtt_handle_signal(self, sender: str, mtype: str, data: dict):

        # ïîêà èñïîëüçóåì òîò æå ôîðìàò, ÷òî presence (offer àíàëîãè÷åí hello)

        if mtype in ("offer", "hello"):

            self._mqtt_handle_presence(sender, "hello", data)



    def _add_or_update_peer(self, nid: str, ep: str):

        now = time.time()

        eps = [ep]

        self.pending_peers[nid] = now

        self.peers[nid] = PeerInfo(node_id=nid, endpoints=eps, last_seen=int(now))

        self.last_seen[nid] = now

        self._maybe_register_white_peer(ep)

        self.peer_state[nid] = "HP"



    def _discover_via_public_stun(self):

        """

        Ïîñëåäîâàòåëüíî ïðîáóåì ïóáëè÷íûå STUN-ñåðâåðû, ÷òîáû óçíàòü ñâîé âíåøíèé àäðåñ.

        Åñëè ïîëó÷èëè áåëûé àäðåñ  ñîõðàíÿåì â public_binding è ñòàâèì ðîëü stun_candidate.

        """

        import random

        servers = list(self.public_stun_list)

        random.shuffle(servers)

        for srv in servers:

            try:

                host, port_s = srv.split(":", 1)

                port = int(port_s)

                mapped = self._stun_binding_request(host, port)

                if mapped:

                    self.public_binding = mapped

                    try:

                        self.white_peers.add(mapped)

                        self._save_known_peer(mapped[0], mapped[1])

                    except Exception:

                        pass

                    # îáúÿâèì ñåáÿ êàê stun_candidate â ñëåäóþùèõ announce

                    self.capabilities[self.t.node_id] = list(CAPABILITIES) + ["stun_candidate"]

                    self.negotiated_caps[self.t.node_id] = self.capabilities[self.t.node_id]

                    logger.info(f"Public STUN discovered binding {mapped} via {srv}")

                    break

            except Exception as exc:

                logger.debug(f"public stun {srv} failed: {exc}")



    def _stun_binding_request(self, host: str, port: int) -> Tuple[str, int] | None:

        """

        Ìèíèìàëüíûé STUN Binding Request (RFC 5389) äëÿ ïîëó÷åíèÿ ïóáëè÷íîãî àäðåñà.

        """

        import socket

        import os

        import struct

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.settimeout(1.0)

        try:

            # STUN message: type 0x0001 (Binding Request), length 0, magic cookie 0x2112A442, transaction id 12 bytes

            tx_id = os.urandom(12)

            msg = struct.pack("!HHI12s", 0x0001, 0, 0x2112A442, tx_id)

            sock.sendto(msg, (host, port))

            data, _ = sock.recvfrom(2048)

            if len(data) < 20:

                return None

            _, msg_len, cookie = struct.unpack("!HHI", data[:8])

            if cookie != 0x2112A442:

                return None

            # parse attributes

            pos = 20

            mapped = None

            while pos + 4 <= len(data):

                attr_type, attr_len = struct.unpack("!HH", data[pos:pos+4])

                pos += 4

                if attr_type in (0x0001, 0x0020):  # MAPPED-ADDRESS or XOR-MAPPED-ADDRESS

                    family = data[pos + 1]

                    port_bytes = data[pos + 2:pos + 4]

                    ip_bytes = data[pos + 4:pos + 8]

                    if attr_type == 0x0020:  # XOR

                        port_val = struct.unpack("!H", port_bytes)[0] ^ (0x2112)

                        ip_val = struct.unpack("!I", ip_bytes)[0] ^ 0x2112A442

                    else:

                        port_val = struct.unpack("!H", port_bytes)[0]

                        ip_val = struct.unpack("!I", ip_bytes)[0]

                    if family == 0x01:  # IPv4

                        ip_str = socket.inet_ntoa(struct.pack("!I", ip_val))

                        mapped = (ip_str, port_val)

                        break

                pos += attr_len

                # align to 4 bytes

                if attr_len % 4 != 0:

                    pos += 4 - (attr_len % 4)

            return mapped

        except Exception:

            return None

        finally:

            try:

                sock.close()

            except Exception:

                pass



    def _on_relay_offer(self, msg: dict, addr):

        if len(self.active_relays) >= MAX_RELAY_SESSIONS:

            return

        payload = msg.get(7, {}) or {}

        between = payload.get("between", [])

        relay_ep = payload.get("relay_endpoint")

        score = payload.get("score", 0)

        # require that the sender advertises relay capability

        try:

            nid = msg.get(3, b"").hex()

        except Exception:

            nid = None

        if nid and "relay_v1" not in self.capabilities.get(nid, []):

            logger.debug("relay offer rejected - sender does not have relay_v1 capability")

            return

        if not relay_ep or not isinstance(relay_ep, str):

            return

        if not between or not isinstance(between, list):

            return

        if score < 0:

            return

        if not self._relay_health_check(relay_ep):

            return

        # require minimum relay score for accepting relay offers

        if score < getattr(self, "RELAY_SCORE_THRESHOLD", 10):

            logger.debug(f"relay offer rejected - score {score} below threshold")

            return

        logger.debug(f"relay offer from {addr}, between={between}, relay_ep={relay_ep}")

        if between and relay_ep:

            self.active_relays.add(str(between))

            # register a relay session entry with quota and expiry

            try:

                self.relay_sessions[relay_ep] = {"ts": time.time(), "bytes": 0, "quota": MAX_RELAY_RATE_BYTES_PER_MIN, "expires": time.time() + random.randint(60, 300)}

            except Exception:

                pass

            for nid in between:

                self.relay_endpoints[nid] = relay_ep

                self.relay_ts[nid] = time.time()

            # send ACK to coordinator to confirm accept

            try:

                coord_host, coord_port = addr

                payload_ack = {"between": between, "relay_endpoint": relay_ep}

                self.t.send_msg((coord_host, coord_port), MsgType.RELAY_ACK, payload_ack)

            except Exception:

                pass



    def request_relay(self, coordinator: Tuple[str, int], between: list):

        payload = {"between": between, "relay_endpoint": f"udp://{self._public_host()}:{self.t.udp_port}", "score": self.compute_relay_score()}

        try:

            self.t.send_msg(coordinator, MsgType.RELAY_OFFER, payload)

        except Exception as exc:

            logger.debug(f"relay request to {coordinator} failed: {exc}")



    def compute_relay_score(self) -> int:

        """Compute a simple relay score used for deciding relay authorization.



        Current implementation: read numeric env var AURORA_RELAY_SCORE (defaults to 10).

        Score is used to decide whether remote relays meet local threshold.

        """

        try:

            return int(os.environ.get("AURORA_RELAY_SCORE", "10"))

        except Exception:

            return 10



    def _on_relay_ack(self, msg: dict, addr):

        payload = msg.get(7, {}) or {}

        between = payload.get("between", [])

        relay_ep = payload.get("relay_endpoint")

        if not between or not relay_ep:

            return

        for nid in between:

            self.relay_endpoints[nid] = relay_ep

            self.relay_ts[nid] = time.time()

        logger.debug(f"relay ack from {addr} between={between} relay_ep={relay_ep}")



    def _relay_send(self, target_nid: str, msg_type: MsgType, payload: dict):

        relay_ep = self.relay_endpoints.get(target_nid)

        if not relay_ep:

            return False

        ts = self.relay_ts.get(target_nid, 0)

        if time.time() - ts > 300:

            self.relay_endpoints.pop(target_nid, None)

            self.relay_ts.pop(target_nid, None)

            return False

        try:

            if "://" in relay_ep:

                _, rest = relay_ep.split("://", 1)

            else:

                rest = relay_ep

            host, port = rest.rsplit(":", 1)

            port = int(port)

            # sign inner payload for authenticity

            inner = {

                "target": target_nid,

                "msg_type": int(msg_type),

                "payload": payload,

                "ts": int(time.time()),

                "sender_pub": self.t.pub_hex,

            }

            import cbor2

            encoded_inner = cbor2.dumps(inner)

            sig = sign_ed25519(encoded_inner, self.t.priv_hex)

            inner["sig"] = sig

            encoded_inner = cbor2.dumps(inner)

            self.t.send_relay_data((host, port), encoded_inner)

            return True

        except Exception as exc:

            logger.debug(f"relay send failed for {target_nid}: {exc}")

            return False



    def _on_relay_data(self, payload: dict, addr):

        try:

            import cbor2

            raw = payload.get("data", b"")

            obj = cbor2.loads(raw)

            target = obj.get("target")

            # reject relay_data if we don't have relay info for target

            if target not in self.relay_endpoints:

                return

            if target and target == self.t.node_id:

                sig = obj.get("sig")

                ts = obj.get("ts")

                msg_type_val = obj.get("msg_type")

                inner_payload = obj.get("payload") or {}

                sender_pub = obj.get("sender_pub")

                if not sig or not ts or not msg_type_val or not sender_pub:

                    return

                try:

                    if abs(time.time() - float(ts)) > 300:

                        return

                    encoded = cbor2.dumps(

                        {"target": target, "msg_type": msg_type_val, "payload": inner_payload, "ts": ts, "sender_pub": sender_pub}

                    )

                    if not verify_ed25519(sig, encoded, sender_pub):

                        return

                except Exception:

                    return

                try:

                    mtype = MsgType(msg_type_val)

                    handler = self.t.handlers.get(mtype)

                    if handler:

                        fake_msg = {1: PROTO_VERSION, 2: msg_type_val, 7: inner_payload, 3: bytes.fromhex(self.t.node_id)}

                        handler(fake_msg, addr)

                except Exception:

                    pass

                return

            msg_type_val = obj.get("msg_type")

            inner_payload = obj.get("payload") or {}

            sig = obj.get("sig")

            ts = obj.get("ts")

            sender_pub = obj.get("sender_pub")

            if not sig or not ts or not sender_pub:

                return

            try:

                if abs(time.time() - float(ts)) > 300:

                    return

                encoded = cbor2.dumps(

                    {"target": target, "msg_type": msg_type_val, "payload": inner_payload, "ts": ts, "sender_pub": sender_pub}

                )

                if not verify_ed25519(sig, encoded, sender_pub):

                    return

            except Exception:

                return

            if not target or not msg_type_val:

                return

            info = self.peers.get(target)

            if not info or not info.endpoints:

                return

            ep = info.endpoints[0]

            if not ep.startswith("udp://"):

                return

            host_port = ep.split("://", 1)[1]

            host, port = host_port.split(":", 1)

            self.t.send_msg((host, int(port)), MsgType(msg_type_val), inner_payload)

        except Exception as exc:

            logger.debug(f"relay data process error: {exc}")

    def _on_relay_close(self, msg: dict, addr):
        try:
            relay_ep = f"{addr[0]}:{addr[1]}"
            self.relay_sessions.pop(relay_ep, None)
            for nid, ep in list(self.relay_endpoints.items()):
                if ep.endswith(relay_ep):
                    self.relay_endpoints.pop(nid, None)
                    self.relay_ts.pop(nid, None)
        except Exception:
            pass

    # Probabilistic verification: chunk request/response and fraud proofs




    # Probabilistic verification: chunk request/response and fraud proofs (çàãëóøêè)

    def _on_request_chunk(self, msg: dict, addr):
        try:
            payload = msg.get(7, {}) or {}
            block_hash = payload.get("block_hash")
            idx = payload.get("idx")
            if idx is None or block_hash is None:
                return
            proofs = self.chunk_cache.get(block_hash)
            if not proofs:
                blk = self.chain.get_last_block() if self.chain else None
                if blk and hasattr(blk, "hash") and blk.hash() == block_hash:
                    proofs = getattr(blk, "chunk_proofs", []) or []
            if not proofs:
                return
            for p in proofs:
                if p.get("idx") == idx:
                    resp = {"block_hash": block_hash, "idx": idx, "data": p.get("data"), "path": p.get("path", []), "hash": None}
                    host, port = addr
                    self.t.send_msg((host, port), MsgType.CHUNK_RESPONSE, resp)
                    break
        except Exception as exc:
            logger.debug(f"request_chunk error: {exc}")

    def _on_chunk_response(self, msg: dict, addr):
        try:
            payload = msg.get(7, {}) or {}
            block_hash = payload.get("block_hash")
            data = payload.get("data")
            path = payload.get("path", [])
            idx = payload.get("idx")
            if not block_hash or data is None or idx is None:
                return
            blk = self.chain.get_last_block() if self.chain else None
            if blk and hasattr(blk, "hash") and blk.hash() == block_hash and blk.segment_root:
                import json, hashlib
                leaf = hashlib.sha256(json.dumps(data).encode()).hexdigest()
                cur = leaf
                for sibling in path:
                    cur = hashlib.sha256((cur + sibling).encode()).hexdigest()
                if cur != blk.segment_root:
                    self._broadcast_fraud_proof(
                        miner=blk.miner_address,
                        block_hash=block_hash,
                        proof={"idx": idx, "data": data, "path": path, "segment_root": blk.segment_root},
                        reason="segment_root_mismatch",
                    )
                else:
                    self._store_chunk_cache(block_hash, [{"idx": idx, "data": data, "path": path}])
        except Exception:
            pass

    def _on_fraud_proof(self, msg: dict, addr):
        try:
            payload = msg.get(7, {}) or {}
            import hashlib, json
            fp_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
            if fp_hash in self.fraud_seen:
                return
            miner = payload.get("miner")
            proof = payload.get("proof", {}) or {}
            segment_root = proof.get("segment_root")
            data = proof.get("data")
            path = proof.get("path", [])
            idx = proof.get("idx")
            if not miner or segment_root is None or data is None or idx is None:
                return
            # optional sig check
            sig = payload.get("sig")
            signer = payload.get("signer")
            ts = payload.get("ts", 0)
            if sig and signer and ts:
                try:
                    if abs(time.time() - float(ts)) > 300:
                        return
                    h = hashlib.sha256(json.dumps({k: payload[k] for k in payload if k not in ("sig",)}, sort_keys=True).encode()).hexdigest()
                    if not verify_ed25519(sig, h.encode(), signer):
                        return
                except Exception:
                    return
            import json, hashlib
            leaf = hashlib.sha256(json.dumps(data).encode()).hexdigest()
            cur = leaf
            for sibling in path:
                cur = hashlib.sha256((cur + sibling).encode()).hexdigest()
            if cur != segment_root:
                return
            self._update_rep(miner, -5)
            self.fraud_seen.add(fp_hash)
            self._broadcast(MsgType.FRAUD_PROOF, payload)
        except Exception as exc:
            logger.debug(f"fraud proof handle error: {exc}")

    def _on_rep_update(self, msg: dict, addr):
        try:
            payload = msg.get(7, {}) or {}
            miner = payload.get("miner")
            delta = payload.get("delta")
            sig = payload.get("sig")
            signer = payload.get("signer")
            ts = payload.get("ts", 0)
            import hashlib, json
            rep_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
            if rep_hash in self.rep_seen:
                return
            if sig and signer and ts:
                try:
                    if abs(time.time() - float(ts)) > 300:
                        return
                    h = hashlib.sha256(json.dumps({k: payload[k] for k in payload if k not in ("sig",)}, sort_keys=True).encode()).hexdigest()
                    if not verify_ed25519(sig, h.encode(), signer):
                        return
                except Exception:
                    return
            if miner and isinstance(delta, int):
                self.rep_seen.add(rep_hash)
                self._update_rep(miner, delta, broadcast=False)
        except Exception:
            pass

    def _dispatch_p2p_payload(self, payload: dict, kind: str):

        try:

            if kind == "block":

                from storage import block_from_dict

                blk_dict = payload.get("block")

                if not blk_dict or not self.chain:

                    return False

                blk = block_from_dict(blk_dict)

                if blk.miner_address in self.banned_miners:

                    return False

                prev = self.chain.get_last_block()

                if prev:

                    if blk.prev_hash != prev.hash() or blk.index != prev.index + 1:

                        return False

                # verify chunk proofs if present
                if blk.segment_root:
                    if not blk.chunk_proofs:
                        return False
                    if len(blk.chunk_proofs) < getattr(self, "proof_chunks_required", 1):
                        return False
                    try:
                        import json, hashlib
                        for proof in blk.chunk_proofs:
                            idx = proof.get("idx")
                            data = proof.get("data")
                            path = proof.get("path", [])
                            if idx is None or data is None:
                                return False
                            leaf = hashlib.sha256(json.dumps(data).encode()).hexdigest()
                            cur = leaf
                            for sibling in path:
                                pair = (cur + sibling).encode()
                                cur = hashlib.sha256(pair).hexdigest()
                            if cur != blk.segment_root:
                                self._broadcast_fraud_proof(
                                    miner=blk.miner_address,
                                    block_hash=blk.hash(),
                                    proof={"idx": idx, "data": data, "path": path, "segment_root": blk.segment_root},
                                    reason="segment_root_mismatch",
                                )
                                return False
                    except Exception:
                        return False
                ok = self.chain.add_block(blk)

            if ok and blk.miner_address:

                self._update_rep(blk.miner_address, +1)

            return ok



            if kind == "tx":

                from transaction import transaction_from_dict

                from transaction_pool import mempool

                tx_dict = payload.get("tx")

                if not tx_dict:

                    return False

                tx = transaction_from_dict(tx_dict)

                if not tx.verify() or tx.amount <= 0:

                    return False

                mempool.add(tx)

                return True



            if kind == "proposal":

                from consensus import Proposal as PropClass

                p = PropClass(**payload.get("proposal"))

                if hasattr(self, "consensus_state") and self.consensus_state:

                    self.consensus_state.add_proposal(p)

                return True



            if kind == "vote":

                from consensus import Vote as VoteClass

                v = VoteClass(**payload.get("vote"))

                if hasattr(self, "consensus_state") and self.consensus_state:

                    self.consensus_state.add_vote(v)

                return True



            if kind == "checkpoint":

                from checkpoint import Checkpoint

                cpd = payload.get("checkpoint")

                if not cpd:

                    return False

                cp = Checkpoint.from_dict(cpd)

                if self.chain:

                    self.chain.add_checkpoint(cp)

                return True



            if kind == "chain_response":

                from storage import block_from_dict

                blocks_raw = payload.get("blocks", [])

                cps_raw = payload.get("checkpoints", [])

                height = payload.get("height", 0)

                blocks = [block_from_dict(b) for b in blocks_raw]

                from checkpoint import Checkpoint

                cps = [Checkpoint.from_dict(c) for c in cps_raw]

                from chain import Blockchain

                new_chain = Blockchain(blocks=blocks, checkpoints=cps, validators=getattr(self, "validators", None))

                if not new_chain.is_valid_chain():

                    return False

                current_height = len(self.chain.blocks) if self.chain else 0

                if height > current_height and len(blocks) >= current_height:

                    self.chain = new_chain

                # optional mempool sync

                txs_raw = payload.get("txs", [])

                if txs_raw:

                    try:

                        from transaction import transaction_from_dict

                        from transaction_pool import mempool

                        for txd in txs_raw:

                            try:

                                mempool.add(transaction_from_dict(txd))

                            except Exception:

                                continue

                    except Exception:

                        pass

                return True

        except Exception as exc:

            logger.debug(f"dispatch {kind} failed: {exc}")

        return False



    def _on_block_msg(self, msg: dict, addr):

        payload = msg.get(7, {}) or {}

        block_dict = payload.get("block")

        if not block_dict:

            return

        self._dispatch_p2p_payload({"block": block_dict}, "block")



    def _on_tx_msg(self, msg: dict, addr):

        payload = msg.get(7, {}) or {}

        tx_dict = payload.get("tx")

        if not tx_dict:

            return

        self._dispatch_p2p_payload({"tx": tx_dict}, "tx")



    def _on_proposal_msg(self, msg: dict, addr):

        payload = msg.get(7, {}) or {}

        prop = payload.get("proposal")

        if not prop:

            return

        self._dispatch_p2p_payload({"proposal": prop}, "proposal")



    def _on_vote_msg(self, msg: dict, addr):

        payload = msg.get(7, {}) or {}

        vote = payload.get("vote")

        if not vote:

            return

        self._dispatch_p2p_payload({"vote": vote}, "vote")



    def _on_checkpoint_msg(self, msg: dict, addr):

        payload = msg.get(7, {}) or {}

        cp = payload.get("checkpoint")

        if not cp:

            return

        self._dispatch_p2p_payload({"checkpoint": cp}, "checkpoint")



    def _on_chain_request(self, msg: dict, addr):

        # respond with chain summary (height and maybe recent blocks)

        if not self.t:

            return

        try:

            from storage import load_chain, load_checkpoints

            from chain import Blockchain

            blocks = load_chain()

            cps = load_checkpoints()

            payload = {

                "height": len(blocks or []),

                "blocks": [b.to_dict() for b in (blocks or [])[-20:]],

                "checkpoints": [c.to_dict() for c in (cps or [])[-20:]],

            }

            host, port = addr

            self.t.send_msg((host, port), MsgType.CHAIN_RESPONSE, payload)

        except Exception as exc:

            logger.debug(f"chain request error: {exc}")



    def _on_chain_response(self, msg: dict, addr):

        payload = msg.get(7, {}) or {}

        ok = self._dispatch_p2p_payload(payload, kind="chain_response")

        if ok:

            self.chain_sync_done = True



    def _on_mempool_request(self, msg: dict, addr):

        try:

            from transaction_pool import mempool

            txs = [tx.to_dict() for tx in mempool.get_all()]

            host, port = addr

            self.t.send_msg((host, port), MsgType.MEMPOOL_RESPONSE, {"txs": txs})

        except Exception as exc:

            logger.debug(f"mempool request error: {exc}")



    def _on_mempool_response(self, msg: dict, addr):

        try:

            from transaction_pool import mempool

            from transaction import transaction_from_dict

            txs_raw = msg.get(7, {}).get("txs", [])

            for tx_dict in txs_raw:

                try:

                    tx = transaction_from_dict(tx_dict)

                    mempool.add(tx)

                except Exception:

                    continue

        except Exception as exc:

            logger.debug(f"mempool response error: {exc}")



    def _request_chain_bootstrap(self):

        try:

            peers = list(self.validated_peers) or list(self.peers.keys())

            if not peers and self.white_peers:

                # åñëè åñòü áåëûå ïèðîâûå àäðåñà, ïîïðîáóåì çàïðîñèòü ó íèõ

                peers = [f"{h}:{p}" for h, p in self.white_peers]

            if not peers:

                return

            target = random.choice(peers)

            info = self.peers.get(target)

            if info and info.endpoints:

                ep = info.endpoints[0]

                payload = {}

                if ep.startswith("udp://"):

                    host_port = ep.split("://", 1)[1]

                    host, port = host_port.split(":", 1)

                    self.t.send_msg((host, int(port)), MsgType.CHAIN_REQUEST, payload)

                    self.t.send_msg((host, int(port)), MsgType.MEMPOOL_REQUEST, {})

                else:

                    self._relay_send(target, MsgType.CHAIN_REQUEST, payload)

                    self._relay_send(target, MsgType.MEMPOOL_REQUEST, {})

            else:

                # seed peers encoded as host:port

                if isinstance(target, str) and ":" in target:

                    host, port = target.rsplit(":", 1)

                    self.t.send_msg((host, int(port)), MsgType.CHAIN_REQUEST, {})

                    self.t.send_msg((host, int(port)), MsgType.MEMPOOL_REQUEST, {})

        except Exception as exc:

            logger.debug(f"chain bootstrap request error: {exc}")



    def _notify_peer(self, nid: str, endpoints: list[str], validated: bool):

        if self.on_new_peer:

            try:

                self.on_new_peer(nid, endpoints, validated=validated)

            except TypeError:

                try:

                    self.on_new_peer(nid, endpoints)

                except Exception:

                    pass

            except Exception:

                pass

        # keep only validated peers in primary list? optional, but mark validation time

        if validated:

            try:

                self.pending_peers.pop(nid, None)

            except Exception:

                pass





if __name__ == "__main__":

    priv, pub = generate_ed25519_keypair()

    t = AuroraTransport(priv_hex=priv, pub_hex=pub, udp_port=9010)

    node = AuroraNode(t, bootstrap_peers=[("127.0.0.1", 9010)])

    node.start()

    try:

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        node.stop()