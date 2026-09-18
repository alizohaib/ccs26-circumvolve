# EVOLVE-BLOCK-START
"""
TCB Teardown - with RST/ACK - Small TTL, High Percentage
Geneva: [TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{IP:ttl:replace:10},))-
Success rate: 94% against China GFW
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
        if not pkt.haslayer(TCP) or pkt[TCP].flags != 'A':
            return [pkt]
        
        rst_ack = copy.deepcopy(pkt)
        rst_ack[TCP].flags = 'RA'
        rst_ack[IP].ttl = 10
        rst_ack = recalculate_checksums(rst_ack)
        
        return [pkt, rst_ack]


# EVOLVE-BLOCK-END


