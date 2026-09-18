# EVOLVE-BLOCK-START

from typing import Optional, List, Union, Dict, Tuple
from scapy.all import IP, TCP, UDP, Raw, Packet  # type: ignore  # noqa  # pylint: disable=no-name-in-module
from dataclasses import dataclass, field
import copy
import random


@dataclass
class Scheduled:
    """Wrapper for packets that should be sent after a delay."""
    packet: Packet
    delay_ms: int


def recalculate_checksums(pkt: Packet) -> Packet:
    """Force recalculation of checksums by reconstructing layers."""
    if not pkt.haslayer(IP):
        return pkt

    # Extract fields and payload, then rebuild from scratch so Scapy recalculates
    ip_layer = pkt[IP]
    payload = ip_layer.payload

    new_ip = IP(
        version=ip_layer.version,
        ihl=ip_layer.ihl,
        tos=ip_layer.tos,
        id=ip_layer.id,
        flags=ip_layer.flags,
        frag=ip_layer.frag,
        ttl=ip_layer.ttl,
        proto=ip_layer.proto,
        src=ip_layer.src,
        dst=ip_layer.dst,
        options=ip_layer.options,
    )

    # Rebuild transport layer explicitly to avoid simply copying checksum fields
    if payload and payload.haslayer(TCP):
        tcp_layer = payload[TCP]
        tcp_payload = tcp_layer.payload if isinstance(tcp_layer.payload, Raw) else tcp_layer.payload
        new_tcp = TCP(
            sport=tcp_layer.sport,
            dport=tcp_layer.dport,
            seq=tcp_layer.seq,
            ack=tcp_layer.ack,
            dataofs=tcp_layer.dataofs,
            reserved=tcp_layer.reserved,
            flags=tcp_layer.flags,
            window=tcp_layer.window,
            urgptr=tcp_layer.urgptr,
            options=tcp_layer.options,
        )
        new_pkt = new_ip / new_tcp / tcp_payload

    elif payload and payload.haslayer(UDP):
        udp_layer = payload[UDP]
        udp_payload = udp_layer.payload if isinstance(udp_layer.payload, Raw) else udp_layer.payload
        new_udp = UDP(
            sport=udp_layer.sport,
            dport=udp_layer.dport,
            len=None,       # let Scapy compute
            chksum=None,    # let Scapy compute
        )
        new_pkt = new_ip / new_udp / udp_payload

    else:
        # No TCP/UDP; just re-wrap existing payload
        new_pkt = new_ip / payload

    return new_pkt


class Strategy:
    """
    1. Strategy: Minimal RST Filtering + First-Data Overlap Desync (HTTP-Scoped)

    2. Approach:
       - Keep the conservative baseline that yields good evasion:
         * Recalculate checksums.
         * Drop only clearly suspicious incoming bare RSTs.
       - Apply a *small overlapping desync* only on the first
         client→server HTTP request segment (instead of every first
         data-bearing TCP segment):
         * This keeps the successful desync mechanism focused where
           the forbidden Host header lives, while reducing the chance
           of harming non-HTTP traffic that influences allowed_access.
       - The overlap is tiny (a few bytes once per HTTP flow), keeping
         overhead low while still confusing simple DPI reassembly.

    3. Censor Hypothesis:
       - The censor reassembles HTTP streams and blocks on Host / path
         signatures for domains like "pornhub.com".
       - Overlapping bytes within the HTTP request line/headers can
         misalign or partially hide the Host header in the censor’s view
         while the server’s TCP stack still reconstructs it correctly.
       - Earlier results (evasion_success=100) suggest the overlap trick
         works, but applying it to all protocols may hurt correctness
         for benign / allowed traffic; restricting it to HTTP should
         improve the overall fitness score.

    The Engine intercepts packets via NFQUEUE and calls these methods:
    - on_incoming_packet: Called for packets arriving at this host
    - on_outgoing_packet: Called for packets leaving this host

    Return values:
    - List[Packet]: Packets to send (can be modified, multiple, or scheduled)
    - None: Drop the packet
    - []: Drop the packet (empty list)
    """

    def __init__(self):
        """Initialize strategy state with structured connection tracking."""
        # key: (src, sport, dst, dport, proto) -> arbitrary per-connection state
        self.connections: Dict[Tuple[str, int, str, int, int], dict] = {}
        # Track a small amount of per-flow information for HTTP request shaping.
        # We scope the desync to HTTP to avoid perturbing other protocols.
        self.http_state: Dict[Tuple[str, int, str, int, int], dict] = {}

    def _connection_key(self, pkt: Packet) -> Optional[Tuple[str, int, str, int, int]]:
        """Build a deterministic connection key for TCP/UDP packets."""
        if not pkt.haslayer(IP):
            return None
        ip = pkt[IP]

        if pkt.haslayer(TCP):
            l4 = pkt[TCP]
            proto = 6
        elif pkt.haslayer(UDP):
            l4 = pkt[UDP]
            proto = 17
        else:
            return None

        return (ip.src, int(l4.sport), ip.dst, int(l4.dport), proto)

    def _ensure_connection(self, pkt: Packet) -> None:
        """Create a minimal state record for a connection if it doesn't exist."""
        key = self._connection_key(pkt)
        if key is None:
            return
        if key not in self.connections:
            # Keep structure flexible for future strategies
            self.connections[key] = {
                "created": True,
                "packet_count": 0,
                "last_direction": None,  # 'in' or 'out'
            }

    def _register_packet(self, pkt: Packet, direction: str) -> None:
        """Update connection metadata for a packet."""
        key = self._connection_key(pkt)
        if key is None:
            return
        self._ensure_connection(pkt)
        state = self.connections[key]
        state["packet_count"] += 1
        state["last_direction"] = direction

    def on_incoming_packet(self, pkt: Packet) -> Optional[List[Union[Packet, Scheduled]]]:
        """
        Process incoming packets.

        Args:
            pkt: The incoming IP packet (Scapy Packet object)

        Returns:
            List of packets to accept, or None/[] to drop
        """
        # Track the packet
        self._register_packet(pkt, "in")

        # Simple protection against censor-injected RSTs:
        # if a lone incoming TCP RST arrives without any payload, drop it.
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            if tcp.flags & 0x04 and len(bytes(tcp.payload)) == 0:
                # Drop likely injected RST to keep connection alive
                return []

        processed = recalculate_checksums(copy.deepcopy(pkt))
        return [processed]

    def on_outgoing_packet(self, pkt: Packet) -> Optional[List[Union[Packet, Scheduled]]]:
        """
        Process outgoing packets.

        Args:
            pkt: The outgoing IP packet (Scapy Packet object)

        Returns:
            List of packets to send (can include Scheduled for delayed sending),
            or None/[] to drop the packet
        """
        self._register_packet(pkt, "out")

        processed = recalculate_checksums(copy.deepcopy(pkt))

        # Only manipulate TCP packets that likely carry HTTP requests
        if not (processed.haslayer(IP) and processed.haslayer(TCP)):
            return [processed]

        ip = processed[IP]
        tcp = processed[TCP]
        key = self._connection_key(processed)
        payload_bytes = bytes(tcp.payload) if tcp.payload else b""

        if key is None:
            return [processed]

        # Initialize per-flow state. We generalize the flag name to reflect
        # that we are acting on the first data segment in the flow, which
        # is often where HTTP headers or other cleartext metadata appear.
        if key not in self.http_state:
            self.http_state[key] = {"first_data_desync_done": False}

        state = self.http_state[key]

        # Only consider packets that actually carry payload; pure ACKs or
        # control packets are forwarded untouched.
        if len(payload_bytes) == 0:
            return [processed]

        # Heuristic: only treat clearly HTTP-like packets as candidates
        # for desynchronization. This avoids touching non-HTTP protocols
        # (e.g., other application traffic over TCP) that may affect
        # allowed_access and overall fitness.
        is_http_like = any(
            payload_bytes.startswith(m)
            for m in [b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS "]
        )

        if not is_http_like:
            return [processed]

        # Strategy: on the *first* HTTP request packet in a flow,
        # create a tiny overlapping segmentation pattern:
        #   - pkt1: first N bytes (seq = original_seq)
        #   - pkt2: entire payload, but starting at seq = original_seq + (N - K)
        # where K is a small overlap (e.g., 2 bytes).
        # This keeps correctness (server sees all bytes) but may confuse
        # simplistic DPI reassemblers that do not handle overlaps well.
        if (
            not state["first_data_desync_done"]
            and len(payload_bytes) > 24  # avoid very small app frames
        ):
            original_seq = tcp.seq
            # Take a modest prefix length that stays within the start of
            # the request line / headers, where Host appears.
            prefix_len = min(20, len(payload_bytes) // 2)
            # Overlap a couple of bytes so that some content appears twice.
            overlap = min(2, prefix_len // 2)

            # First segment: sends the prefix only.
            pkt1 = processed.copy()
            pkt1[TCP].seq = original_seq
            pkt1[TCP].payload = Raw(payload_bytes[:prefix_len])
            # Let Scapy recalc length and checksum.
            if hasattr(pkt1[IP], "len"):
                del pkt1[IP].len
            if hasattr(pkt1[IP], "chksum"):
                del pkt1[IP].chksum
            if hasattr(pkt1[TCP], "chksum"):
                del pkt1[TCP].chksum

            # Second segment: resend from slightly *before* the end of pkt1,
            # creating an intentional overlap of `overlap` bytes.
            pkt2 = processed.copy()
            pkt2[TCP].seq = original_seq + prefix_len - overlap
            pkt2[TCP].payload = Raw(payload_bytes[prefix_len - overlap :])
            if hasattr(pkt2[IP], "len"):
                del pkt2[IP].len
            if hasattr(pkt2[IP], "chksum"):
                del pkt2[IP].chksum
            if hasattr(pkt2[TCP], "chksum"):
                del pkt2[TCP].chksum

            state["first_data_desync_done"] = True
            return [pkt1, pkt2]

        # Default: forward unchanged (aside from checksum normalization).
        return [processed]


# EVOLVE-BLOCK-END