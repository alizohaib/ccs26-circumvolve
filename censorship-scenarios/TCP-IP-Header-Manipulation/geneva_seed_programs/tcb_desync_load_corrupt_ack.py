# EVOLVE-BLOCK-START
"""
TCP Desync - Invalid Payload - Corrupt ACK
Geneva: [TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{TCP:ack:corrupt}(duplicate(fragment{tcp:-1:False},),),),)-
Success rate: 93% against China GFW
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


def fragment_tcp(pkt: Packet, fragsize: int, in_order: bool = True) -> List[Packet]:
    """Fragment a TCP packet's payload into multiple segments."""
    if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
        return [pkt]
    
    payload = bytes(pkt[Raw].load)
    if fragsize == -1:
        fragsize = len(payload) // 2
    
    if fragsize <= 0 or fragsize >= len(payload):
        return [pkt]
    
    fragments = []
    seq = pkt[TCP].seq
    
    pkt1 = copy.deepcopy(pkt)
    pkt1[Raw].load = payload[:fragsize]
    pkt1 = recalculate_checksums(pkt1)
    fragments.append(pkt1)
    
    pkt2 = copy.deepcopy(pkt)
    pkt2[TCP].seq = seq + fragsize
    pkt2[Raw].load = payload[fragsize:]
    pkt2 = recalculate_checksums(pkt2)
    fragments.append(pkt2)
    
    if not in_order:
        fragments.reverse()
    
    return fragments


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
        
        corrupted = copy.deepcopy(pkt)
        if corrupted.haslayer(Raw):
            corrupted[Raw].load = bytes([random.randint(0, 255) for _ in range(len(corrupted[Raw].load))])
        corrupted[TCP].ack = random.randint(0, 65535)
        corrupted = recalculate_checksums(corrupted)
        
        fragments = fragment_tcp(corrupted, -1, in_order=False)
        
        return fragments + [pkt]


# EVOLVE-BLOCK-END


