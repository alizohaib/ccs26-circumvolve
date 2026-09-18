# EVOLVE-BLOCK-START
"""
1. Strategy: Overlapping Host-Header Decoy + Tiny Ghost Segment (Shadow SYN removed)

2. Category: TCP Stream Reassembly, TCP Header Parsing, Malformed Packet Handling,
   TCB Desynchronization

3. Approach:
   - Keep the core, high-performing trick: for the first HTTP request,
     show the censor a different Host header than the server sees by:
       * Sending a tiny 1-byte bad-checksum "ghost" segment at the correct
         seq to skew early-byte parsing on DPI that ignores checksums.
       * Sending an overlapping full decoy segment whose Host header is
         rewritten locally to an allowed domain (example.com) and whose
         checksum is bad, so endpoints drop it but DPI may still classify.
       * Then sending the original, unmodified request as a clean segment
         that the server actually accepts (Host: pornhub.com).
   - Incoming: once HTTP data has been sent, aggressively drop incoming
     RST/FIN as likely censor injections.

   - Compared to the previous version, we remove the injected "shadow SYN"
     mid-flow. That non-standard packet adds complexity and anomaly surface
     but is not needed for evasion, and dropping it improves robustness and
     keeps the implementation simpler and shorter.

4. Censor Hypothesis:
   The pcap shows midbox RSTs immediately after the first HTTP request with
   Host: pornhub.com, suggesting:
     - The censor inspects the first request packet after the handshake.
     - It likely ignores checksum errors for classification and has naive
       overlap handling ("first bytes win").
   By feeding it a benign Host in an overlapping, checksum-bad decoy while
   the server only processes the untouched real request, and by shielding
   against RST/FIN, we desynchronize the censor’s view from end-host reality
   with minimal complexity.
"""

from typing import Optional, List, Tuple, Dict, Union
from scapy.all import IP, TCP, UDP, Raw, Packet
from dataclasses import dataclass, field
import time
import threading


@dataclass
class Scheduled:
    """Wrapper for packets that should be sent after a delay."""
    packet: Packet
    delay_ms: int


class Strategy:
    """
    TCP/IP packet manipulation strategy focused on early-stream skew.
    
    The Engine intercepts packets via NFQUEUE and calls these methods:
    - on_incoming_packet: Called for packets arriving at this host
    - on_outgoing_packet: Called for packets leaving this host
    
    Return values:
    - List[Packet]: Packets to send (can be modified, multiple)
    - List[Scheduled]: Packets to send later (for delay-based tricks)
    - [] or None: Drop the packet
    """
    
    def __init__(self):
        """Initialize strategy state."""
        # Track endpoints as sorted tuples (src, sport, dst, dport)
        # and store per-connection metadata.
        self.connections: Dict[Tuple[str, int, str, int], Dict] = {}
        self._lock = threading.Lock()
        # Forbidden/allowed host markers used only for packet-shape decisions.
        # We do NOT rewrite the actual request payload.
        self.forbidden_host = b"pornhub.com"
        self.allowed_host = b"example.com"

    def _make_key(self, pkt: Packet) -> Optional[Tuple[str, int, str, int]]:
        """Normalize 4-tuple key for TCP/UDP flows (direction-agnostic)."""
        if IP not in pkt:
            return None
        ip = pkt[IP]

        if TCP in pkt:
            l4 = pkt[TCP]
        elif UDP in pkt:
            l4 = pkt[UDP]
        else:
            return None

        sport, dport = int(l4.sport), int(l4.dport)
        a = (ip.src, sport)
        b = (ip.dst, dport)
        if a <= b:
            return (a[0], a[1], b[0], b[1])
        else:
            return (b[0], b[1], a[0], a[1])

    def _get_or_create_conn(self, key: Tuple[str, int, str, int]) -> Dict:
        """Fetch or create connection metadata."""
        with self._lock:
            if key not in self.connections:
                self.connections[key] = {
                    "created_at": time.time(),
                    "packet_count": 0,          # total packets seen (both dirs)
                    "directions": set(),        # 'out', 'in'
                    "first_data_split_done": False,  # tiny-segment skew done?
                    "http_data_seen": False,    # did we see outgoing HTTP payload?
                }
            return self.connections[key]

    def _track_packet(self, pkt: Packet, outgoing: bool) -> None:
        """Update connection statistics for given packet."""
        key = self._make_key(pkt)
        if key is None:
            return
        conn = self._get_or_create_conn(key)
        with self._lock:
            conn["packet_count"] += 1
            conn["directions"].add("out" if outgoing else "in")

    def _maybe_cleanup_connections(self, ttl: float = 300.0) -> None:
        """Periodic cleanup based on simple TTL."""
        now = time.time()
        with self._lock:
            stale = [k for k, v in self.connections.items()
                     if now - v.get("created_at", now) > ttl]
            for k in stale:
                del self.connections[k]

    def _should_attempt_split(self, pkt: Packet, conn: Dict) -> bool:
        """
        Decide whether to manipulate this packet.

        We are now stricter: we only attempt the special split once, on the
        first HTTP request-like packet (payload beginning with 'GET ' or
        'POST ') and only if there is enough room to embed a shadow Host
        header fragment.
        """
        if TCP not in pkt or IP not in pkt:
            return False

        tcp = pkt[TCP]

        # Skip control packets; we only touch data segments
        if tcp.flags & 0x29:  # SYN=0x02, FIN=0x01, RST=0x04
            return False

        payload_bytes = bytes(tcp.payload)
        if len(payload_bytes) < 32:
            # Need some space to contain HTTP start-line and Host header
            return False

        # Only perform this special split once per connection
        if conn.get("first_data_split_done", False):
            return False

        # Heuristic: only engage on HTTP-like methods
        if not (payload_bytes.startswith(b"GET ") or payload_bytes.startswith(b"POST ")):
            return False

        return True

    def _build_decoy_segment(self, base_ip: IP, base_tcp: TCP, full_payload: bytes) -> Optional[Packet]:
        """
        Build an overlapping 'decoy' segment that advertises a benign Host
        header, on the same sequence number as the real request, with a
        deliberately bad checksum so the server should drop it but the
        censor may still parse it.
        """
        try:
            # Very simple parsing: look for "Host: " and overwrite only
            # within our local copy; we do NOT modify the real payload.
            host_idx = full_payload.find(b"\r\nHost:")
            if host_idx == -1:
                return None

            line_start = host_idx + 2  # skip initial CRLF
            line_end = full_payload.find(b"\r\n", line_start)
            if line_end == -1:
                return None

            # Build a shallow copy to edit a decoy host line
            decoy = bytearray(full_payload)
            host_line = decoy[line_start:line_end]

            # Only adjust the hostname portion between "Host: " and any port
            prefix = b"Host:"
            if not host_line.startswith(prefix):
                return None
            # Try to locate space after "Host:"
            space_idx = host_line.find(b" ")
            if space_idx == -1:
                return None

            # Replace the hostname token with allowed_host, preserving length
            # as much as possible to keep offsets similar.
            rest = host_line[space_idx + 1 :]
            # rest is "hostname[:port]..."
            # Find end of hostname token (space or CRLF)
            token_end = rest.find(b"\r")
            if token_end == -1:
                token_end = len(rest)
            hostname = rest[:token_end]
            # Create new hostname padded/truncated to same length
            new_host = self.allowed_host.ljust(len(hostname), b"x")[: len(hostname)]
            rest_mut = bytearray(rest)
            rest_mut[: len(new_host)] = new_host
            new_host_line = prefix + b" " + bytes(rest_mut)

            # Install modified line
            decoy[line_start:line_end] = new_host_line[: line_end - line_start]

            # Build segment with same seq/ack as real packet
            seg = base_ip.copy()
            seg[TCP] = base_tcp.copy()
            seg[TCP].remove_payload()
            seg = seg / Raw(bytes(decoy))

            # Bad checksum so endpoints ignore, censor might not.
            seg[TCP].chksum = 0xffff

            # Add odd options to further differentiate parsing
            try:
                opts = list(seg[TCP].options) if seg[TCP].options else []
                opts.append(("NOP", None))
                opts.append((30, b"\x00"))  # experimental option
                seg[TCP].options = opts
            except Exception:
                pass

            return seg
        except Exception:
            return None

    def _split_and_skew_first_data(self, pkt: Packet, conn: Dict) -> List[Packet]:
        """
        Perform the core evasion for the first HTTP request:

        - Construct a decoy overlapping segment that appears to contain a
          benign Host header and has a bad checksum.
        - Immediately send the real, unmodified HTTP request as a clean
          segment with a correct checksum.
        - Optionally still keep the tiny-leading-segment behavior by
          prepending a very small corrupt segment before both, to tickle
          DPI reassembly corner cases.
        """
        ip = pkt[IP]
        tcp = pkt[TCP]
        full_payload = bytes(tcp.payload)

        # Base template with headers but no payload
        base_ip = ip.copy()
        base_tcp = tcp.copy()
        base_tcp.remove_payload()

        packets: List[Packet] = []

        # Tiny corrupt lead segment (1 byte) to keep previous behavior
        lead_len = 1
        lead_bytes = full_payload[:lead_len]
        tiny = base_ip.copy()
        tiny[TCP] = base_tcp.copy()
        tiny[TCP].seq = tcp.seq
        tiny = tiny / Raw(lead_bytes)
        tiny[TCP].chksum = 0xffff
        packets.append(tiny)

        # Overlapping decoy with allowed Host, same seq as real
        decoy = self._build_decoy_segment(base_ip, base_tcp, full_payload)
        if decoy is not None:
            packets.append(decoy)

        # Real, valid segment carrying the full correct payload
        real = base_ip.copy()
        real[TCP] = base_tcp.copy()
        real = real / Raw(full_payload)
        real[TCP].chksum = 0
        packets.append(real)

        conn["first_data_split_done"] = True
        conn["http_data_seen"] = True

        return packets

    def on_incoming_packet(self, pkt: Packet) -> Optional[List[Packet]]:
        """
        Process incoming packets (server → client).

        - Track flows and clean up.
        - Once we know outgoing HTTP data has been sent, aggressively drop
          incoming RST/FIN as likely censor injections.
        """
        self._track_packet(pkt, outgoing=False)
        self._maybe_cleanup_connections()

        if TCP in pkt and IP in pkt:
            tcp = pkt[TCP]
            key = self._make_key(pkt)
            if key is not None:
                conn = self._get_or_create_conn(key)
                # Stronger shield once HTTP data is seen
                if conn.get("http_data_seen", False):
                    if tcp.flags & 0x04 or tcp.flags & 0x01:  # RST or FIN
                        return []

                # Also drop clear midstream RSTs after multiple packets
                if tcp.flags & 0x04 and conn.get("packet_count", 0) > 4 and "out" in conn["directions"]:
                    return []

        return [pkt]
    


    def on_outgoing_packet(self, pkt: Packet) -> Optional[Union[List[Packet], List[Scheduled]]]:
        """
        Process outgoing packets (client → server).

        - On the first HTTP request packet, perform overlapping decoy/real
          segment injection to desynchronize censor vs server.
        """
        self._track_packet(pkt, outgoing=True)
        self._maybe_cleanup_connections()

        if TCP in pkt and IP in pkt:
            key = self._make_key(pkt)
            if key is not None:
                conn = self._get_or_create_conn(key)
                tcp = pkt[TCP]
                payload_bytes = bytes(tcp.payload)
                if payload_bytes:
                    conn["http_data_seen"] = True

                # First, see if this should be our special first HTTP packet
                if self._should_attempt_split(pkt, conn):
                    return self._split_and_skew_first_data(pkt, conn)

        # Default: forward unchanged.
        return [pkt]
    
    
# EVOLVE-BLOCK-END