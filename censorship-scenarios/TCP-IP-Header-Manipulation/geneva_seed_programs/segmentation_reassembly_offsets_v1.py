# EVOLVE-BLOCK-START
"""
Segmentation - Reassembly - Offsets, subvariant 1
Geneva: [TCP:flags:PA]-fragment{tcp:8:True}(,fragment{tcp:4:True})-
Success rate: 98% against China GFW
"""

from typing import Optional, List, Union
from scapy.all import IP, TCP, UDP, Raw, Packet  # type: ignore  # noqa  # pylint: disable=no-name-in-module
from dataclasses import dataclass
import copy


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
        self.connections = {}
    
    def on_incoming_packet(self, pkt: Packet) -> Optional[List[Union[Packet, Scheduled]]]:
        """
        Process incoming packets.
        
        Args:
            pkt: The incoming IP packet (Scapy Packet object)
            
        Returns:
            List of packets to accept, or None to drop
        """
        return [pkt]
    
    def on_outgoing_packet(self, pkt: Packet) -> Optional[List[Union[Packet, Scheduled]]]:
        """
        Process outgoing packets.
        
        Args:
            pkt: The outgoing IP packet (Scapy Packet object)
            
        Returns:
            List of packets to send (can include Scheduled for delayed sending),
            or None to drop the packet
        """
        if not pkt.haslayer(TCP) or pkt[TCP].flags != 'PA':
            return [pkt]
        
        if not pkt.haslayer(Raw):
            return [pkt]
        
        payload = bytes(pkt[Raw].load)
        if len(payload) < 12:
            return [pkt]
        
        seq = pkt[TCP].seq
        
        # First fragment: first 8 bytes
        pkt1 = copy.deepcopy(pkt)
        pkt1[Raw].load = payload[:8]
        pkt1 = recalculate_checksums(pkt1)
        
        # Second fragment: bytes 4-end (overlapping)
        pkt2 = copy.deepcopy(pkt)
        pkt2[TCP].seq = seq + 4
        pkt2[Raw].load = payload[4:]
        pkt2 = recalculate_checksums(pkt2)
        
        return [pkt1, pkt2]


# EVOLVE-BLOCK-END


