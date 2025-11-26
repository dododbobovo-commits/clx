"""
Minimal WebRTC + MQTT P2P signaling demo.

Goal: show how two nodes behind NAT can connect directly (UDP hole punching via ICE / STUN)
without any relay/bridge node with a public IP. MQTT is used only as a rendezvous channel
to exchange SDP/ICE; data flows peer-to-peer over the WebRTC data channel.
"""

import asyncio
import json
import random
import os
import time
from typing import Dict, List, Optional

import paho.mqtt.client as mqtt
from aiortc import (
    RTCConfiguration,
    RTCIceCandidate,
    RTCIceServer,
    RTCPeerConnection,
    RTCSessionDescription,
)
from aiortc.sdp import candidate_from_sdp


BROKER = os.getenv("CLX_MQTT", "test.mosquitto.org")
SIGNAL_PREFIX = os.getenv("CLX_SIGNAL_PREFIX", "clx/signal")
PRESENCE_TOPIC = f"{SIGNAL_PREFIX}/presence"
PRESENCE_INTERVAL = float(os.getenv("CLX_PRESENCE_SEC", "10"))

# Allow multiple STUNs and optional TURN via env:
#   CLX_STUNS=stun:stun.l.google.com:19302,stun:stun.cloudflare.com:3478
#   CLX_TURN=turn:turn.example.com:3478
#   CLX_TURN_USER=user
#   CLX_TURN_PASS=pass
STUN_LIST = [
    srv.strip()
    for srv in os.getenv(
        "CLX_STUNS", "stun:stun.l.google.com:19302,stun:stun.cloudflare.com:3478"
    ).split(",")
    if srv.strip()
]
TURN_URL = os.getenv("CLX_TURN")
TURN_USER = os.getenv("CLX_TURN_USER")
TURN_PASS = os.getenv("CLX_TURN_PASS")


class Node:
    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop
        self.my_id = f"Node_{random.randint(100, 999)}"
        self.my_topic = f"{SIGNAL_PREFIX}/{self.my_id}"

        self.peer_connections: Dict[str, RTCPeerConnection] = {}
        self.data_channels: Dict[str, any] = {}
        self.pending_ice: Dict[str, List[dict]] = {}
        self.known_peers: Dict[str, float] = {}

        self.mqtt = mqtt.Client(client_id=self.my_id, clean_session=True)
        self.mqtt.will_set(
            PRESENCE_TOPIC,
            json.dumps({"sender": self.my_id, "type": "bye", "ts": time.time()}),
        )
        self.mqtt.on_connect = self._on_mqtt_connect
        self.mqtt.on_message = self._on_mqtt_message

        print(f"--- CLX P2P NODE: {self.my_id} ---")
        print(f"Listening for signaling on topic: {self.my_topic}")

    def start(self) -> None:
        self.mqtt.connect(BROKER, 1883, 60)
        self.mqtt.loop_start()
        self.loop.create_task(self._presence_loop())

    def stop(self) -> None:
        self.mqtt.loop_stop()
        self.mqtt.disconnect()

    # MQTT callbacks -----------------------------------------------------
    def _on_mqtt_connect(self, client, userdata, flags, rc) -> None:
        client.subscribe(self.my_topic)
        client.subscribe(PRESENCE_TOPIC)
        print("MQTT connected. Waiting for peers...")
        # announce immediately
        self._publish_presence()

    def _on_mqtt_message(self, client, userdata, msg) -> None:
        try:
            payload = json.loads(msg.payload.decode())
            sender = payload["sender"]
            msg_type = payload["type"]
            data = payload.get("data")
            if msg.topic == PRESENCE_TOPIC:
                asyncio.run_coroutine_threadsafe(
                    self._handle_presence(msg_type, sender, payload.get("ts")), self.loop
                )
            else:
                print(f"\n[MQTT] received '{msg_type}' from {sender}")
                asyncio.run_coroutine_threadsafe(
                    self._handle_signaling(msg_type, data, sender), self.loop
                )
        except Exception as exc:
            print(f"[MQTT] failed to handle message: {exc}")

    def _publish(self, target_id: str, message: dict) -> None:
        topic = f"{SIGNAL_PREFIX}/{target_id}"
        self.mqtt.publish(topic, json.dumps(message))

    def _publish_presence(self) -> None:
        self.mqtt.publish(
            PRESENCE_TOPIC,
            json.dumps({"sender": self.my_id, "type": "hello", "ts": time.time()}),
        )

    # WebRTC helpers -----------------------------------------------------
    def _build_pc(self, peer_id: str) -> RTCPeerConnection:
        ice_servers = [RTCIceServer(urls=STUN_LIST)]
        if TURN_URL:
            ice_servers.append(
                RTCIceServer(urls=TURN_URL, username=TURN_USER, credential=TURN_PASS)
            )
        config = RTCConfiguration(iceServers=ice_servers)
        pc = RTCPeerConnection(configuration=config)
        self.peer_connections[peer_id] = pc

        @pc.on("icecandidate")
        async def on_icecandidate(candidate: Optional[RTCIceCandidate]) -> None:
            if candidate:
                print(
                    f"[ICE] send {candidate.type} {candidate.protocol} "
                    f"{candidate.address}:{candidate.port} -> {peer_id}"
                )
            else:
                print(f"[ICE] end-of-candidates -> {peer_id}")
            payload = None
            if candidate:
                payload = {
                    "candidate": candidate.to_sdp(),
                    "sdpMid": candidate.sdpMid,
                    "sdpMLineIndex": candidate.sdpMLineIndex,
                }
            self._publish(
                peer_id,
                {"sender": self.my_id, "type": "ice", "data": payload},
            )

        @pc.on("icegatheringstatechange")
        async def on_icegatheringstatechange() -> None:
            print(f"[ICE] gathering -> {pc.iceGatheringState} ({peer_id})")

        @pc.on("connectionstatechange")
        async def on_connectionstatechange() -> None:
            print(f"[P2P] {peer_id} state -> {pc.connectionState}")
            if pc.connectionState in ("failed", "closed", "disconnected"):
                self.peer_connections.pop(peer_id, None)
                self.data_channels.pop(peer_id, None)

        return pc

    def _wire_channel(self, channel, peer_id: str) -> None:
        print(f"[P2P] data channel ready: {channel.label} with {peer_id}")
        # Track immediately so sender can find it even before "open"
        self.data_channels[peer_id] = channel

        @channel.on("open")
        def on_open() -> None:
            print(f"[P2P] channel open with {peer_id}")
            channel.send(f"hi from {self.my_id}")

        @channel.on("message")
        def on_message(message) -> None:
            print(f"\n[P2P] {peer_id}: {message}")
            print(">> ", end="", flush=True)

        @channel.on("close")
        def on_close() -> None:
            self.data_channels.pop(peer_id, None)
            print(f"[P2P] channel closed with {peer_id}")

    # Signaling flows ----------------------------------------------------
    async def _handle_signaling(self, msg_type: str, data: dict, sender_id: str) -> None:
        if msg_type == "offer":
            await self._handle_offer(sender_id, data)
        elif msg_type == "answer":
            await self._handle_answer(sender_id, data)
        elif msg_type == "ice":
            await self._handle_ice(sender_id, data)

    async def _handle_offer(self, sender_id: str, sdp: dict) -> None:
        print(f"[SIGNAL] offer from {sender_id}, replying with answer")
        pc = self._build_pc(sender_id)

        @pc.on("datachannel")
        def on_datachannel(channel) -> None:
            self._wire_channel(channel, sender_id)

        await pc.setRemoteDescription(RTCSessionDescription(**sdp))
        await pc.setLocalDescription(await pc.createAnswer())
        # Wait briefly for candidates to gather before sending answer
        await asyncio.sleep(0.5)

        self._publish(
            sender_id,
            {
                "sender": self.my_id,
                "type": "answer",
                "data": {
                    "sdp": pc.localDescription.sdp,
                    "type": pc.localDescription.type,
                },
            },
        )
        await self._flush_pending_ice(sender_id)

    async def _handle_answer(self, sender_id: str, sdp: dict) -> None:
        pc = self.peer_connections.get(sender_id)
        if not pc:
            print(f"[WARN] answer from {sender_id} but no RTCPeerConnection")
            return
        await pc.setRemoteDescription(RTCSessionDescription(**sdp))
        await self._flush_pending_ice(sender_id)

    async def _handle_ice(self, sender_id: str, ice: Optional[dict]) -> None:
        pc = self.peer_connections.get(sender_id)
        if not pc:
            self.pending_ice.setdefault(sender_id, []).append(ice)
            return

        await self._apply_ice(pc, ice)

    async def _apply_ice(
        self, pc: RTCPeerConnection, ice: Optional[dict]
    ) -> None:
        if ice is None:
            await pc.addIceCandidate(None)
            return
        candidate = candidate_from_sdp(ice["candidate"])
        candidate.sdpMid = ice["sdpMid"]
        candidate.sdpMLineIndex = ice["sdpMLineIndex"]
        print(
            f"[ICE] recv {candidate.type} {candidate.protocol} "
            f"{candidate.address}:{candidate.port}"
        )
        await pc.addIceCandidate(candidate)

    async def _flush_pending_ice(self, peer_id: str) -> None:
        if peer_id not in self.pending_ice:
            return
        pc = self.peer_connections.get(peer_id)
        if not pc:
            return
        for ice in self.pending_ice.pop(peer_id, []):
            await self._apply_ice(pc, ice)

    async def _handle_presence(self, msg_type: str, sender: str, ts: Optional[float]) -> None:
        if sender == self.my_id:
            return
        if msg_type == "hello":
            self.known_peers[sender] = ts or time.time()
        elif msg_type == "bye":
            self.known_peers.pop(sender, None)

    async def _presence_loop(self) -> None:
        while True:
            self._publish_presence()
            await asyncio.sleep(PRESENCE_INTERVAL)

    # Public API ---------------------------------------------------------
    async def connect(self, target_id: str) -> None:
        print(f"[SIGNAL] initiating connection to {target_id}")
        pc = self._build_pc(target_id)
        channel = pc.createDataChannel("chat")
        self._wire_channel(channel, target_id)

        await pc.setLocalDescription(await pc.createOffer())
        await asyncio.sleep(0.5)  # let some candidates gather before sending offer
        self._publish(
            target_id,
            {
                "sender": self.my_id,
                "type": "offer",
                "data": {
                    "sdp": pc.localDescription.sdp,
                    "type": pc.localDescription.type,
                },
            },
        )

    def send_text(self, message: str, target_id: Optional[str] = None) -> None:
        if target_id:
            channel = self.data_channels.get(target_id)
            if not channel:
                print(f"[WARN] no channel to {target_id}")
                return
            if getattr(channel, "readyState", "") != "open":
                print(f"[WARN] channel to {target_id} not open yet (state={channel.readyState})")
                return
            channel.send(message)
            return

        if not self.data_channels:
            print("[WARN] no open P2P channels")
            return
        for pid, channel in self.data_channels.items():
            if getattr(channel, "readyState", "") != "open":
                print(f"[WARN] skip {pid}, channel state={channel.readyState}")
                continue
            channel.send(message)
            print(f"[P2P] sent to {pid}")


async def repl(node: Node) -> None:
    print("\nCommands:")
    print("  connect <Node_123>   - start P2P offer toward a peer")
    print("  msg <text>           - broadcast text to all open peers")
    print("  msgto <id> <text>    - send text to a specific peer")
    print("  peers                - list open data channels")
    print("  myid                 - show your node id")
    print("  seen                 - list discovered peers (presence)")
    print("  sdp <peer?>          - print local SDP for a peer (debug)\n")

    while True:
        cmd = await loop.run_in_executor(None, input, ">> ")
        if cmd.startswith("connect "):
            target = cmd.split(maxsplit=1)[1].strip()
            await node.connect(target)
        elif cmd.startswith("msgto "):
            try:
                _, peer, text = cmd.split(maxsplit=2)
                node.send_text(text, peer)
            except ValueError:
                print("usage: msgto <peer> <text>")
        elif cmd.startswith("msg "):
            text = cmd.split(maxsplit=1)[1] if " " in cmd else ""
            node.send_text(text)
        elif cmd == "peers":
            if not node.data_channels:
                print("no open peers")
            else:
                for pid in node.data_channels:
                    print(f"- {pid}")
        elif cmd == "seen":
            if not node.known_peers:
                print("no peers seen yet")
            else:
                now = time.time()
                for pid, ts in node.known_peers.items():
                    age = int(now - ts) if ts else 0
                    print(f"- {pid} (last {age}s ago)")
        elif cmd == "myid":
            print(node.my_id)
        elif cmd.startswith("sdp"):
            parts = cmd.split(maxsplit=1)
            target = parts[1].strip() if len(parts) > 1 else None
            if target and target in node.peer_connections:
                pc = node.peer_connections[target]
                if pc.localDescription:
                    print(pc.localDescription.sdp)
                else:
                    print("no localDescription yet")
            elif target:
                print("unknown peer")
            else:
                for pid, pc in node.peer_connections.items():
                    print(f"=== {pid} ===")
                    if pc.localDescription:
                        print(pc.localDescription.sdp)
                    else:
                        print("no localDescription yet")
        else:
            print("unknown command")


loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
node = Node(loop)
node.start()

try:
    loop.run_until_complete(repl(node))
finally:
    node.stop()
    loop.close()
