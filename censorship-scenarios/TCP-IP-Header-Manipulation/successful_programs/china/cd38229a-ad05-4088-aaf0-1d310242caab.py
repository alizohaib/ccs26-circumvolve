# EVOLVE-BLOCK-START
"""
1. Strategy: Triple-Path HTTP Host Confusion (Benign-First + Split-Host + RST Filtering)

2. Category: 
   - TCP Stream Reassembly / Segmentation Handling
   - TCP Segmentation Handling
   - TCP Connection Tracking (TCB Teardown / Desynchronization)
   - Malformed Packet Handling

3. Approach:
   - Incoming:
       * Drop incoming RSTs that are likely censor injections, to keep the
         client–server connection alive.
   - Outgoing:
       * Keep handshake untouched.
       * On the **first HTTP request** that contains the forbidden Host
         (e.g., `Host: pornhub.com`), send:
             (a) a **benign-lookalike copy** of the packet where only the
                 Host header is rewritten to `example.com`, and
             (b) the **original, untouched packet** for the real server.
         Both packets share the same 4‑tuple and sequence/ack numbers, so
         they race at the censor; whichever arrives first may be treated as
         the canonical HTTP request in its reassembly logic.
       * Unlike earlier checksum‑corruption designs, both copies are
         fully valid from the server’s point of view; only one is likely
         to be accepted, but the censor may parse the benign one first.
       * Additionally, to explore DPI timing sensitivity, the benign
         copy can be sent **slightly earlier** (e.g., 5–10 ms) than the
         real request using Scheduled transmission, encouraging
         “benign‑first wins” semantics in the censor’s reassembly.

4. Reasoning:
   - The PCAP shows a fast RST after `Host: pornhub.com`, which strongly
     suggests HTTP Host‑based blocking plus RST injection.
   - Many DPI engines:
       * treat the first reassembled HTTP request per flow as authoritative,
       * are confused by duplicate segments with identical sequence numbers
         but different payload bytes, and
       * may not re-parse later overlapping data once a request is logged.
   - By racing a benign Host header against the real request, we attempt to
     push the censor into classifying the flow as allowed while keeping the
     server‑facing stream valid and minimally altered.
   - By explicitly biasing the race with a small delay on the real packet,
     we exercise DPIs whose logic is “first packet wins” in the presence of
     overlaps, without significantly affecting end‑to‑end correctness.

6. Censor Hypothesis:
   - The censor:
       * inspects the first HTTP request on each TCP connection,
       * searches for forbidden hostnames in the Host header, and
       * enforces via injected RSTs from the server side.
   - Its overlap/duplicate‑segment handling may be simplistic (e.g.,
     “first packet wins” without careful conflict resolution). Feeding
     it a benign HTTP request with the same sequence space as the real
     one exercises that weakness while retaining correctness.
"""

from typing import Optional, List, Dict, Tuple, Any, Union
from scapy.all import IP, TCP, UDP, Raw, Packet
from dataclasses import dataclass, field


@dataclass
class Scheduled:
    """Wrapper for packets that should be sent after a delay."""
    packet: Packet
    delay_ms: int


@dataclass
class ConnectionState:
    """
    Lightweight per-connection state tracker.

    Extended with a simple HTTP marker so we only manipulate the first
    HTTP request per flow. This maintains correctness on allowed traffic
    and limits side effects.
    """
    last_direction: str = "unknown"  # "in", "out", "unknown"
    packet_count_in: int = 0
    packet_count_out: int = 0
    last_flags_in: Any = None
    last_flags_out: Any = None
    # Track whether we've already seen an HTTP request on this flow.
    http_request_seen: bool = False


class Strategy:
    """
    Base strategy class for TCP/IP packet manipulation.
    
    The Engine intercepts packets via NFQUEUE and calls these methods:
    - on_incoming_packet: Called for packets arriving at this host
    - on_outgoing_packet: Called for packets leaving this host
    
    Return values:
    - List[Packet]: Packets to send (can be modified, multiple, or scheduled)
    - None: Drop the packet
    - []: Drop the packet (empty list)
    """
    
    def __init__(self):
        """Initialize strategy state."""
        # Track connection state if needed for stateful evasion
        # Keyed by (src, sport, dst, dport, proto)
        self.connections: Dict[Tuple[str, int, str, int, str], ConnectionState] = {}

    # ---------- Internal helpers ----------

    def _make_key(self, pkt: Packet, reverse: bool = False) -> Optional[Tuple[str, int, str, int, str]]:
        """Create a canonical 5-tuple key for the connection."""
        if not pkt.haslayer(IP):
            return None

        ip = pkt[IP]

        proto = None
        sport = 0
        dport = 0

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            proto = "TCP"
            sport, dport = tcp.sport, tcp.dport
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            proto = "UDP"
            sport, dport = udp.sport, udp.dport
        else:
            proto = str(ip.proto)

        if reverse:
            return (ip.dst, dport, ip.src, sport, proto)
        return (ip.src, sport, ip.dst, dport, proto)

    def _get_or_create_state(self, pkt: Packet, direction: str) -> Optional[ConnectionState]:
        """Retrieve or lazily create state for a packet's connection."""
        key = self._make_key(pkt, reverse=(direction == "in"))
        if key is None:
            return None
        if key not in self.connections:
            self.connections[key] = ConnectionState()
        return self.connections[key]

    def _update_state_incoming(self, pkt: Packet) -> None:
        state = self._get_or_create_state(pkt, "in")
        if not state:
            return
        state.last_direction = "in"
        state.packet_count_in += 1
        if pkt.haslayer(TCP):
            state.last_flags_in = pkt[TCP].flags

    def _update_state_outgoing(self, pkt: Packet) -> None:
        state = self._get_or_create_state(pkt, "out")
        if not state:
            return
        state.last_direction = "out"
        state.packet_count_out += 1
        if pkt.haslayer(TCP):
            state.last_flags_out = pkt[TCP].flags

    # ---------- Public API ----------

    def on_incoming_packet(self, pkt: Packet) -> Optional[Union[List[Packet], List[Scheduled]]]:
        """
        Process incoming packets.
        
        Args:
            pkt: The incoming IP packet (Scapy Packet object)
            
        Returns:
            List of packets to accept, or []/None to drop
        """
        self._update_state_incoming(pkt)

        # If it's not TCP, just pass through.
        if not pkt.haslayer(TCP):
            return [pkt]

        tcp = pkt[TCP]

        # 1) DROP: Filter incoming RSTs which are likely censor injections.
        #    Keep FIN-based teardowns intact to preserve correctness.
        if tcp.flags & 0x04:  # RST flag set
            # Drop all incoming RSTs from the network; endpoints never see them.
            return []

        # Otherwise, forward unmodified.
        return [pkt]
    
    def on_outgoing_packet(self, pkt: Packet) -> Optional[Union[List[Packet], List[Scheduled]]]:
        """
        Process outgoing packets.
        
        Args:
            pkt: The outgoing IP packet (Scapy Packet object)
            
        Returns:
            List of packets to send (can include Scheduled for delayed sending),
            or []/None to drop the packet
        """
        self._update_state_outgoing(pkt)

        # Non-TCP traffic remains unchanged.
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return [pkt]

        ip = pkt[IP]
        tcp = pkt[TCP]

        # Only attempt tricks on established data packets (ACK set, no SYN/RST/FIN).
        is_data_phase = (tcp.flags & 0x10) and not (tcp.flags & 0x03) and not (tcp.flags & 0x04)
        if not is_data_phase:
            return [pkt]

        state = self._get_or_create_state(pkt, "out")
        if not state:
            return [pkt]

        payload_bytes = bytes(tcp.payload)
        if not payload_bytes:
            return [pkt]

        # Very light HTTP detection: look for "Host:" in the payload and
        # only interfere with the *first* HTTP request on this flow.
        if not state.http_request_seen and b"Host:" in payload_bytes:
            state.http_request_seen = True

            # Only manipulate when the forbidden hostname is present.
            # Allowed domains (e.g., example.com) pass through untouched.
            if b"pornhub.com" in payload_bytes:
                # -----------------------------
                # 1) Benign full-copy variant
                # -----------------------------
                # Build a benign-looking copy with the Host header rewritten
                # to an allowed domain. Keep seq/ack/flags identical so both
                # packets compete in the censor’s reassembly.
                benign_payload = payload_bytes.replace(b"pornhub.com", b"example.com")

                benign_pkt = IP(src=ip.src, dst=ip.dst) / TCP(
                    sport=tcp.sport,
                    dport=tcp.dport,
                    seq=tcp.seq,
                    ack=tcp.ack,
                    flags=tcp.flags,
                    window=tcp.window,
                    options=tcp.options
                ) / Raw(benign_payload)

                # -----------------------------
                # 2) Split-host real request
                # -----------------------------
                # Split "pornhub.com" across two TCP segments so that the
                # forbidden hostname crosses a segment boundary, stressing
                # DPI reassembly while remaining valid for the server.
                host_offset = payload_bytes.find(b"pornhub.com")
                host_len = len(b"pornhub.com")
                if host_offset != -1 and host_len >= 4:
                    # Choose "por" | "nhub.com" split.
                    split_point = host_offset + 3

                    seg1_payload = payload_bytes[:split_point]
                    seg2_payload = payload_bytes[split_point:]

                    # First segment: seq stays the same, shorter payload.
                    seg1 = IP(src=ip.src, dst=ip.dst) / TCP(
                        sport=tcp.sport,
                        dport=tcp.dport,
                        seq=tcp.seq,
                        ack=tcp.ack,
                        flags=tcp.flags,
                        window=tcp.window,
                        options=tcp.options
                    ) / Raw(seg1_payload)

                    # Second segment: seq advanced by length of seg1 payload.
                    seg2 = IP(src=ip.src, dst=ip.dst) / TCP(
                        sport=tcp.sport,
                        dport=tcp.dport,
                        seq=tcp.seq + len(seg1_payload),
                        ack=tcp.ack,
                        flags=tcp.flags,
                        window=tcp.window,
                        options=tcp.options
                    ) / Raw(seg2_payload)

                    # Let kernel recompute checksums.
                    for s in (seg1, seg2, benign_pkt):
                        s[IP].chksum = 0
                        s[TCP].chksum = 0

                    # Exploratory timing-based variant:
                    #   - benign full packet immediately (for DPI "first wins"),
                    #   - split real request slightly delayed.
                    delayed_seg1 = Scheduled(packet=seg1, delay_ms=5)
                    delayed_seg2 = Scheduled(packet=seg2, delay_ms=6)
                    return [benign_pkt, delayed_seg1, delayed_seg2]

                # Fallback: if we somehow couldn't split, keep original
                # scheduling behavior (benign + delayed real).
                delayed_real = Scheduled(packet=pkt, delay_ms=10)
                return [benign_pkt, delayed_real]

        # Default: transparent pass-through.
        return [pkt]
    
    
# EVOLVE-BLOCK-END