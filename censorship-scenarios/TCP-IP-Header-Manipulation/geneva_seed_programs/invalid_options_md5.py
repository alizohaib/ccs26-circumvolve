# EVOLVE-BLOCK-START
r"""
India: Invalid Options (MD5)
Geneva: [TCP:options-mss:]-tamper{TCP:options-md5header:corrupt}-| \/
Success rate: 100% against India censors
"""

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
        if not pkt.haslayer(TCP):
            return [pkt]
        
        # Check for MSS option
        has_mss = False
        if pkt[TCP].options:
            for opt in pkt[TCP].options:
                if opt[0] == 'MSS':
                    has_mss = True
                    break
        
        if not has_mss:
            return [pkt]
        
        modified = copy.deepcopy(pkt)
        new_options = list(modified[TCP].options or [])
        new_options.append(('MD5', bytes([random.randint(0, 255) for _ in range(16)])))
        modified[TCP].options = new_options
        modified = recalculate_checksums(modified)
        
        return [modified]


# EVOLVE-BLOCK-END


