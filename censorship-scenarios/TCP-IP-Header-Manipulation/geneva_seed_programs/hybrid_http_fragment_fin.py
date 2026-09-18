# EVOLVE-BLOCK-START
r"""
Hybrid Strategy - HTTP - Fragment and set Fin flag
Geneva: [TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:F}(tamper{IP:len:replace:68},),)-| \/
Success rate: 53% against China GFW (HTTP)
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
        
        fin_pkt = copy.deepcopy(pkt)
        fin_pkt[TCP].flags = 'F'
        fin_pkt[IP].len = 68
        # Don't recalculate - keep invalid length
        
        return [fin_pkt, pkt]


# EVOLVE-BLOCK-END


