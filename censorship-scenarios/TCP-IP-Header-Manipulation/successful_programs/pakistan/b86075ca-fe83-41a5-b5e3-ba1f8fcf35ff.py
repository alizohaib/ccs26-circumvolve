# EVOLVE-BLOCK-START

from typing import Optional, List, Union
from scapy.all import IP, TCP, UDP, Raw, Packet  # type: ignore  # noqa  # pylint: disable=no-name-in-module
from dataclasses import dataclass
import copy
import random


@dataclass
class Scheduled:
    """Wrapper for packets that should be sent after a delay."""
    packet: Packet
    delay_ms: int


def recalculate_checksums(pkt: Packet) -> Packet:
    """Force recalculation of checksums by deleting them."""
    if pkt.haslayer(IP):
        del pkt[IP].chksum
        del pkt[IP].len
    if pkt.haslayer(TCP):
        del pkt[TCP].chksum
    if pkt.haslayer(UDP):
        del pkt[UDP].chksum
    return pkt


class Strategy:
    """
    1. Strategy: Triple-view handshake + first-data fragmentation and header quirks
    
    2. Approach:
       - Preserve the proven SYN-duplication trick and add a third, checksum-
         poisoned "ghost" SYN variant so the censor sees multiple conflicting
         handshakes while the server only accepts the valid one.
       - Fragment only the first substantial client→server data packet, with a
         short delay on the second segment, to stress DPI reassembly logic.
       - Apply a one-shot header-quirk duplicate mid-flow (TTL/DF/window tweak)
         to create asymmetric state between censor and endpoints.
       - Track basic per-flow state so these behaviors are applied exactly once
         per connection, keeping overhead low and correctness high.
    
    3. Censor Hypothesis:
       - The censor inspects early handshake packets and the first request
         segment, building its own TCB that may not fully validate TCP
         checksums or handle unusual flag/option combinations.
       - It likely reassembles the first few kilobytes of payload but may have
         bugs around small early fragments and timing gaps.
       - By giving it three different views of the SYN, a split first request
         segment, and a slightly inconsistent header snapshot, we desynchronize
         its view of sequence space and stream contents while the endpoints use
         the canonical, valid packets.
    """
    
    def __init__(self):
        """Initialize strategy state."""
        # Track simple per-flow state so we can vary behavior after the handshake
        # Key: (src, sport, dst, dport)
        # Value: {"seen_data": bool, "first_fragment_done": bool}
        self.connections = {}
        # Track whether we already applied our IP / TCP header quirks per flow
        # to add diversity without breaking successful behavior.
        self.header_quirks_done = {}
    
    def _flow_key(self, pkt: Packet):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return None
        ip = pkt[IP]
        tcp = pkt[TCP]
        return (ip.src, tcp.sport, ip.dst, tcp.dport)
    
    def on_incoming_packet(self, pkt: Packet) -> Optional[List[Union[Packet, Scheduled]]]:
        """
        Process incoming packets (server → client).
        
        For diversity and robustness, drop likely injected RSTs
        while allowing legitimate traffic through unchanged.
        """
        if not pkt.haslayer(TCP):
            return [pkt]
        
        tcp = pkt[TCP]
        # Filter out in-path censor RST injections, but keep FIN/ACK etc.
        # This increases robustness without affecting successful flows.
        if tcp.flags & 0x04:  # RST flag
            # Simple heuristic: if we have seen data on this flow, ignore RSTs
            key = self._flow_key(pkt)
            if key in self.connections and self.connections[key].get("seen_data", False):
                return []
        return [pkt]
    
    def on_outgoing_packet(self, pkt: Packet) -> Optional[List[Union[Packet, Scheduled]]]:
        """
        Process outgoing packets (client → server).
        
        - Keep the successful SYN-duplication+payload trick and add a checksum-
          poisoned ghost SYN to further desync censor TCB state.
        - Fragment the first data packet to stress DPI reassembly.
        - Occasionally send a header-quirked duplicate mid-flow.
        """
        if not pkt.haslayer(TCP):
            return [pkt]
        
        tcp = pkt[TCP]
        key = self._flow_key(pkt)
        
        # Track whether we've seen application data on this flow
        if key is not None:
            st = self.connections.setdefault(key, {"seen_data": False, "first_fragment_done": False})
            if len(bytes(tcp.payload)) > 0 and not (tcp.flags & 0x02):  # not SYN
                st["seen_data"] = True
        
        # 1. Preserve existing high-fitness behavior: duplicate SYN with junk payload
        if tcp.flags == "S":
            corrupted_syn = copy.deepcopy(pkt)
            # Add small random payload to confuse DPI that inspects SYN contents
            corrupted_syn = corrupted_syn / Raw(load=bytes([random.randint(0, 255) for _ in range(10)]))
            corrupted_syn = recalculate_checksums(corrupted_syn)

            # Additionally, send a slightly "odd" SYN-like packet with wrong checksum
            # toward the server to potentially desync censor state without confusing
            # the server, since checksum is invalid.
            syn_like_ghost = copy.deepcopy(pkt)
            if syn_like_ghost.haslayer(IP) and syn_like_ghost.haslayer(TCP):
                # Flip a rarely used TCP flag combination (SYN+ECE) and poison checksum
                syn_like_ghost[TCP].flags = "SE"
                syn_like_ghost[TCP].chksum = 0xFFFF  # invalid on purpose

            return [pkt, corrupted_syn, syn_like_ghost]
        
        # 2. New behavior (diversity): cautiously fragment only the first data packet
        #    of a connection. This targets content-based DPI while keeping overhead small.
        if key is not None:
            st = self.connections.setdefault(key, {"seen_data": False, "first_fragment_done": False})
            # Only modify the very first data segment of the flow and only once
            if not st.get("first_fragment_done", False):
                payload = bytes(tcp.payload)
                # Avoid touching pure ACKs or very small packets
                if payload and len(payload) > 24 and tcp.flags & 0x18:  # PSH/ACK typical for data
                    st["first_fragment_done"] = True
                    
                    # Split into two TCP segments: a small leading piece + remainder.
                    # This can desync DPI reassembly while endpoints reassemble correctly.
                    split_point = min(16, len(payload) // 2)
                    
                    pkt1 = copy.deepcopy(pkt)
                    pkt2 = copy.deepcopy(pkt)
                    
                    # First segment: early small payload
                    pkt1[TCP].payload = Raw(load=payload[:split_point])
                    pkt1 = recalculate_checksums(pkt1)
                    
                    # Second segment: adjust sequence and send remainder
                    pkt2[TCP].seq = (pkt2[TCP].seq + split_point) & 0xFFFFFFFF
                    pkt2[TCP].payload = Raw(load=payload[split_point:])
                    pkt2 = recalculate_checksums(pkt2)
                    
                    # Send the first fragment immediately, and slightly delay the second
                    delayed_second = Scheduled(packet=pkt2, delay_ms=5)
                    return [pkt1, delayed_second]

            # 3. Header-quirk dimension: once per flow, slightly perturb IP/TCP header
            # fields in a way endpoints tolerate but naive DPI state machines may mishandle.
            quirks = self.header_quirks_done.setdefault(key, {"applied": False})
            if not quirks["applied"] and tcp.flags & 0x10:  # ACK set (post-handshake)
                quirks["applied"] = True
                quirky_pkt = copy.deepcopy(pkt)
                if quirky_pkt.haslayer(IP):
                    # Decrease TTL a bit to look like asymmetric routing,
                    # but keep it far from expiring.
                    if quirky_pkt[IP].ttl > 8:
                        quirky_pkt[IP].ttl -= 3
                    # Toggle DF bit to change fragmentation expectations.
                    quirky_pkt[IP].flags = "DF"
                if quirky_pkt.haslayer(TCP):
                    # Slightly shrink the advertised window; valid but unusual.
                    if quirky_pkt[TCP].window > 1024:
                        quirky_pkt[TCP].window -= 512
                quirky_pkt = recalculate_checksums(quirky_pkt)
                # Send both original and quirky version to increase diversity.
                return [pkt, quirky_pkt]
        
        # Default: forward unmodified
        return [pkt]


# EVOLVE-BLOCK-END

