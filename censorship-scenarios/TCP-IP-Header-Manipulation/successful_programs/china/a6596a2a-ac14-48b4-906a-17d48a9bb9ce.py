# EVOLVE-BLOCK-START
"""
1. Strategy: Split HTTP Host Across Segments + Tiny-404 Filtering

2. Category: TCP Stream Reassembly, TCP Segmentation Handling, HTTP Header Parsing
   Robustness, RST Injection Filtering

3. Approach:
   - Keep the TCP 3‑way handshake untouched.
   - For the *first* client HTTP request packet carrying data, split the
     payload into two in‑order TCP segments:
       * seg1: contains the HTTP request line and headers **up to but not
         including** the Host header, so the DPI initially sees no Host.
       * seg2: contains the remainder of the original payload (including the
         real "Host: pornhub.com") with the correct next TCP sequence so
         the server reassembles a fully valid request.
   - On the server→client direction, drop:
       * all incoming RSTs (likely censor injections), and
       * very small early PSH+ACK responses that look like synthetic 404/blocked
         pages, while allowing normal, larger responses through.

4. Reasoning:
   The PCAP shows:
     - TCP handshake succeeds.
     - First client data packet with "Host: pornhub.com" immediately triggers:
       * an in-path RST from middlebox to client,
       * duplicate ACK+RST/404‑like traffic.
   This strongly suggests simple HTTP Host‑based filtering after basic TCP
   reassembly. Many DPIs:
     - only parse the first header block or first N bytes,
     - or make an "allow" decision once a partial header set is inspected.
   By sending a first segment that ends before the Host header, the censor
   may:
     - decide the request is benign and stop inspecting, or
     - fail to re‑parse later segments correctly.
   Meanwhile the server reassembles seg1+seg2 into the original HTTP request
   (including the forbidden Host) and responds normally. Tiny early responses
   are likely injected block pages, so we drop them.

6. Censor Hypothesis:
   The censor likely:
   - Tracks flows and performs linear TCP reassembly without overlap handling.
   - Scans only the first segment (or first few hundred bytes) of HTTP headers
     for "Host: <blocked‑domain>".
   - Injects small RST/404 responses when it detects the forbidden Host.
   - Does *not* fully re-parse headers if the Host is split across segments or
     located in a later segment, making segmentation-based evasion promising.
"""

from typing import Optional, List, Dict, Tuple, Any
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

    Even though the baseline behavior is pass-through, we track state to
    allow more complex strategies without changing the public interface.
    """
    last_direction: str = "unknown"  # 'incoming' or 'outgoing'
    packet_count_in: int = 0
    packet_count_out: int = 0
    last_seen_meta: Dict[str, Any] = field(default_factory=dict)


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
        # Use a dict keyed by a normalized 5-tuple to track connections.
        self.connections: Dict[Tuple, ConnectionState] = {}

    # ---------- internal helpers ----------

    def _normalize_5_tuple(self, pkt: Packet) -> Optional[Tuple]:
        """
        Build a direction-agnostic 5-tuple key for TCP/UDP flows.
        Returns None for non-IP or unsupported protocols.
        """
        if not pkt.haslayer(IP):
            return None

        ip = pkt[IP]
        proto = ip.proto

        if proto not in (6, 17):  # TCP=6, UDP=17
            # Non-TCP/UDP flows are not tracked; simple passthrough.
            return None

        # Determine L4 ports
        sport = dport = 0
        if proto == 6 and pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport
        elif proto == 17 and pkt.haslayer(UDP):
            udp = pkt[UDP]
            sport, dport = udp.sport, udp.dport

        # Create an unordered/normalized key so both directions map to same entry
        addr_pair = tuple(sorted([(ip.src, sport), (ip.dst, dport)]))
        key = (addr_pair[0], addr_pair[1], proto)

        return key

    def _get_or_create_conn_state(self, key: Tuple) -> ConnectionState:
        if key not in self.connections:
            self.connections[key] = ConnectionState()
        return self.connections[key]

    def _record_packet(
        self,
        pkt: Packet,
        direction: str,  # 'incoming' or 'outgoing'
    ) -> None:
        """Update per-connection statistics (no behavioral change)."""
        key = self._normalize_5_tuple(pkt)
        if key is None:
            return

        state = self._get_or_create_conn_state(key)
        state.last_direction = direction

        if direction == "incoming":
            state.packet_count_in += 1
        else:
            state.packet_count_out += 1

        # Save some lightweight metadata
        if pkt.haslayer(IP):
            ip = pkt[IP]
            state.last_seen_meta = {
                "src": ip.src,
                "dst": ip.dst,
                "ttl": ip.ttl,
                "len": ip.len,
                "proto": ip.proto,
            }

    # ---------- public API ----------

    def on_incoming_packet(self, pkt: Packet) -> Optional[List[Packet]]:
        """
        Process incoming packets (server → client).

        - Track basic per-connection stats.
        - Drop suspicious RST packets that may be injected by the censor.
        - Drop very small early PSH+ACK segments that look like synthetic
          block pages (tiny HTTP 404/redirect headers).
        """
        self._record_packet(pkt, direction="incoming")

        if not pkt.haslayer(TCP):
            return [pkt]

        tcp = pkt[TCP]

        # Hide all incoming RSTs from the client (likely censor injections).
        if tcp.flags & 0x04:  # RST bit set
            return []

        payload = bytes(tcp.payload) if tcp.payload else b""

        # Heuristic: drop tiny early data packets that look like
        # block-page headers (often < ~120 bytes, PSH+ACK)
        if payload and len(payload) < 120 and (tcp.flags & 0x18) == 0x18:
            key = self._normalize_5_tuple(pkt)
            if key is not None:
                state = self._get_or_create_conn_state(key)
                # Only apply during the very beginning of the flow
                if state.packet_count_in <= 4:
                    return []

        return [pkt]

    def on_outgoing_packet(self, pkt: Packet) -> Optional[List[Packet]]:
        """
        Process outgoing packets (client → server).

        New behavior:
        - Leave TCP handshake and non-data packets untouched.
        - For the first outgoing HTTP request segment on a flow, split the
          payload so that the Host header (and thus forbidden domain) starts
          only in the *second* TCP segment. The censor may only parse seg1.
        """
        self._record_packet(pkt, direction="outgoing")

        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return [pkt]

        tcp = pkt[TCP]
        payload = bytes(tcp.payload) if tcp.payload else b""
        if not payload:
            # Keep SYN/SYN-ACK/ACKs and pure ACKs intact.
            return [pkt]

        key = self._normalize_5_tuple(pkt)
        if key is None:
            return [pkt]
        state = self._get_or_create_conn_state(key)

        # Only touch the very first outgoing data packet of the flow.
        if state.packet_count_out > 1:
            return [pkt]

        # Try to interpret as HTTP request text.
        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            return [pkt]

        if "HTTP/" not in text:
            return [pkt]

        # Find the Host header; we want seg1 to end *before* this.
        host_idx = text.lower().find("host:")
        if host_idx == -1:
            return [pkt]

        # Require that there be at least a full request line and some headers
        # before Host; otherwise splitting is less meaningful.
        if host_idx < 16:
            return [pkt]

        # seg1: everything up to (but not including) "Host:"
        seg1_text = text[:host_idx]
        seg1_bytes = seg1_text.encode("utf-8")

        # seg2: the rest of the original payload (includes Host and beyond)
        seg2_bytes = payload

        # Sanity checks: seg1 must be shorter than original and non-trivial.
        if len(seg1_bytes) < 16 or len(seg1_bytes) >= len(seg2_bytes):
            return [pkt]

        # Build seg1: same seq as original, truncated payload.
        seg1 = pkt.copy()
        seg1[TCP].payload = Raw(seg1_bytes)
        # Force IP length and checksum recalculation by Scapy.
        seg1[IP].len = None
        seg1[TCP].chksum = None

        # Build seg2: carries the remaining bytes with the correct next seq.
        seg2 = pkt.copy()
        seg2[TCP].seq = (tcp.seq + len(seg1_bytes)) & 0xFFFFFFFF
        seg2[TCP].payload = Raw(seg2_bytes[len(seg1_bytes):])
        seg2[IP].len = None
        seg2[TCP].chksum = None

        # Send seg1 (no Host visible) first, then seg2 (real Host) second.
        return [seg1, seg2]
    
    
# EVOLVE-BLOCK-END