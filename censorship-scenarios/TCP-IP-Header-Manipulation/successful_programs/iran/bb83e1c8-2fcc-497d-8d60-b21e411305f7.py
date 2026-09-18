# EVOLVE-BLOCK-START
"""
1. Strategy: Quad-Phase Shadow Handshake + Early Teardown Race

2. Category: TCP Connection Tracking, TCP Header Parsing, Malformed Packet Handling,
             Timing-Based Evasion

3. Approach:
   - Keep the HTTP payload path clean to preserve allowed_access and the current
     perfect evasion_success, but add *more lifecycle desync hooks* around the
     TCP handshake.
   - Phase 1 (client→server): Keep the existing one-shot shadow SYN:
       * invalid TCP checksum,
       * slightly perturbed sequence number,
       * extra TCP NOP option.
   - Phase 2 (server→client): On the first incoming SYN‑ACK for a flow, inject a
     mirrored shadow SYN‑ACK with:
       * invalid checksum,
       * tweaked ACK number,
       * extra NOP option.
   - Phase 3 (client→server): On the first *pure ACK* that completes the 3‑way
     handshake (ACK only, no payload, no other flags), inject an early bogus
     FIN/ACK with an invalid checksum toward the server so some DPIs believe the
     flow just closed and downgrade or delete their TCB.
   - Phase 4 (server→client): When we later see the first *server FIN/ACK*, we
     race it with a shadow FIN/ACK carrying an invalid checksum and a slightly
     shifted sequence; this can confuse teardown logic in DPIs that treat FIN in
     either direction as authoritative.
   - Continue to drop inbound RSTs (likely censor injections) defensively.

4. Reasoning:
   - All top performers already rely on handshake-time shadow SYN desync.
   - Adding symmetric shadow SYN‑ACK plus *two teardown-oriented shadows* means:
       * we now exercise DPI state transitions at connection open and close,
       * we support both client-driven and server-driven teardown paths,
       * we do this with only a few extra packets per flow and no payload edits.
   - This should keep scores at 100 while exploring an under-sampled region of
     the evasion space: bugs in half-closed / closing TCB handling, and DPIs
     that over-trust FIN with weak checksum validation.

6. Censor Hypothesis:
   - The censor:
       * learns sequence/ack from SYN/SYN‑ACK/ACK,
       * performs HTTP Host-based filtering on early client→server data,
       * maintains flow state until explicit FIN/RST or timeout,
       * may accept or semi-parse packets even if checksums are invalid.
   - By feeding it malformed shadow SYN + SYN‑ACK, we risk initial desync.
   - The early bogus FIN/ACK right after the handshake can cause it to:
       * mark the flow closed immediately on the client side, or
       * move it into a "linger but no more inspection" state.
   - When the real server eventually sends its FIN/ACK, the extra shadow FIN
     in the opposite direction can:
       * produce inconsistent half-close state in its TCB, or
       * trigger corner-case teardown code paths.
   - All of these outcomes reduce its chance of correctly reassembling and
     matching forbidden Host headers, while the endpoints ignore bad-checksum
     shadows and communicate normally.
"""

from typing import Optional, List, Union
from scapy.all import IP, TCP, UDP, Raw, Packet
from dataclasses import dataclass


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
        # Track connection state if needed for stateful evasion
        # Use a tuple-based key for (src, sport, dst, dport, proto)
        self.connections = {}

        # Track whether we've already injected a shadow SYN for a given flow
        # (client -> server).
        self._shadow_syn_used = {}

        # Track whether we've already injected a shadow SYN-ACK for a given flow
        # (server -> client). We namespace keys to avoid another dict.
        self._shadow_synack_used = {}

        # Track whether we've already injected an *early* fake FIN/ACK right
        # after the handshake (client -> server).
        self._early_fin_sent = {}

        # Track whether we've already injected a teardown shadow FIN/ACK in
        # response to the first real server FIN/ACK (server -> client).
        self._shadow_fin_used = {}

    # --- internal helpers -------------------------------------------------

    def _flow_key(self, pkt: Packet) -> Optional[tuple]:
        """Create a stable flow key for TCP/UDP/IP packets."""
        ip = pkt.getlayer(IP)
        if ip is None:
            return None

        l4 = ip.payload
        proto = ip.proto

        if isinstance(l4, TCP) or isinstance(l4, UDP):
            sport = int(l4.sport)
            dport = int(l4.dport)
        else:
            sport = 0
            dport = 0

        return (ip.src, sport, ip.dst, dport, proto)

    def _mark_seen(self, pkt: Packet, direction: str) -> None:
        """
        Track flows with a small bitmask of seen directions.
        direction: 'in' or 'out'
        """
        key = self._flow_key(pkt)
        if key is None:
            return

        # bit 0: seen outgoing, bit 1: seen incoming
        mask = self.connections.get(key, 0)
        if direction == "out":
            mask |= 0b01
        elif direction == "in":
            mask |= 0b10

        self.connections[key] = mask

    def _should_drop(self, pkt: Packet, direction: str) -> bool:
        """
        Lightweight sanitization:

        - Drop inbound RST packets (likely censor injections) to protect
          otherwise healthy connections.
        - Do not drop anything else to preserve baseline behavior.
        """
        tcp = pkt.getlayer(TCP)
        if direction == "in" and tcp is not None:
            # If RST flag is set, drop it.
            if tcp.flags & 0x04:  # RST
                return True
        return False

    def _wrap_result(
        self, pkt: Packet
    ) -> Optional[List[Union[Packet, Scheduled]]]:
        """
        Wrap a single packet into the expected list form,
        maintaining the baseline pass-through behavior.
        """
        return [pkt]

    # --- public API -------------------------------------------------------

    def on_incoming_packet(self, pkt: Packet) -> Optional[List[Packet]]:
        """
        Process incoming packets (server → client).

        We add two evasive behaviors on the incoming side:
        - Mirror shadow SYN desync with a shadow SYN-ACK for the first SYN-ACK.
        - Race the first real server FIN/ACK with a malformed FIN/ACK that only
          the censor should treat as valid, confusing teardown tracking.
        """
        self._mark_seen(pkt, "in")
        if self._should_drop(pkt, "in"):
            return None

        ip = pkt.getlayer(IP)
        tcp = pkt.getlayer(TCP)
        if ip is None or tcp is None:
            return self._wrap_result(pkt)

        key = self._flow_key(pkt)
        if key is None:
            return self._wrap_result(pkt)

        results: List[Packet] = []

        # --- Phase 2: shadow SYN-ACK (handshake desync in server→client dir) ---
        is_syn = (tcp.flags & 0x02) != 0
        is_ack = (tcp.flags & 0x10) != 0
        if is_syn and is_ack:
            shadow_key = ("synack",) + key
            if not self._shadow_synack_used.get(shadow_key, False):
                self._shadow_synack_used[shadow_key] = True

                shadow_synack = pkt.copy()
                # Slightly perturb ACK so censor may map seq/ack incorrectly.
                shadow_synack[TCP].ack = (shadow_synack[TCP].ack + 11) & 0xFFFFFFFF
                # Invalid checksum: real client drops, censor may still parse.
                shadow_synack[TCP].chksum = 0xFFFF
                opts = shadow_synack[TCP].options or []
                opts.append(("NOP", None))
                shadow_synack[TCP].options = opts

                real_synack = pkt.copy()
                real_synack[TCP].chksum = 0

                # Shadow first (for DPI), then valid SYN-ACK (for client).
                results.extend([shadow_synack, real_synack])
                return results

        # --- Phase 4: shadow FIN/ACK on first server FIN/ACK ----------------
        fin_flag = (tcp.flags & 0x01) != 0
        ack_flag = (tcp.flags & 0x10) != 0
        if fin_flag and ack_flag and not self._shadow_fin_used.get(key, False):
            self._shadow_fin_used[key] = True

            # Copy the FIN/ACK and perturb seq slightly; keep checksum invalid.
            shadow_fin = pkt.copy()
            shadow_fin[TCP].seq = (shadow_fin[TCP].seq + 5) & 0xFFFFFFFF
            shadow_fin[TCP].chksum = 0xFFFF

            real_fin = pkt.copy()
            real_fin[TCP].chksum = 0

            # Send malformed FIN first, then the real one.
            results.extend([shadow_fin, real_fin])
            return results

        # Default: pass through unchanged if no special handling used.
        return self._wrap_result(pkt)
    
    def on_outgoing_packet(self, pkt: Packet) -> Optional[List[Packet]]:
        """
        Process outgoing packets (client → server).

        Evasion logic:
        - Phase 1: For the first SYN of each TCP flow, inject a shadow SYN with
          bad checksum and slightly altered sequence/options to confuse the
          censor's initial TCB, while forwarding the real SYN.
        - Phase 3: For the first pure ACK that completes the handshake (ACK only,
          no payload, no SYN/FIN/RST), inject a bogus FIN/ACK with invalid
          checksum so the censor may consider the flow closed while the server
          ignores it.
        - All other packets are forwarded unchanged.
        """
        self._mark_seen(pkt, "out")
        if self._should_drop(pkt, "out"):
            return None

        ip = pkt.getlayer(IP)
        tcp = pkt.getlayer(TCP)
        if ip is None or tcp is None:
            return self._wrap_result(pkt)

        key = self._flow_key(pkt)
        if key is None:
            return self._wrap_result(pkt)

        results: List[Packet] = []

        # --- Phase 3: early fake teardown after 3-way handshake -------------
        payload_bytes = bytes(tcp.payload) if tcp.payload is not None else b""
        control_mask = tcp.flags & 0x3F  # SYN/FIN/RST/PSH/ACK/URG
        ack_flag = (tcp.flags & 0x10) != 0
        is_pure_ack = ack_flag and control_mask == 0x10 and len(payload_bytes) == 0

        if is_pure_ack and not self._early_fin_sent.get(key, False):
            self._early_fin_sent[key] = True
            fake_fin = IP(src=ip.src, dst=ip.dst) / TCP(
                sport=tcp.sport,
                dport=tcp.dport,
                seq=tcp.seq,
                ack=tcp.ack,
                flags="FA",     # FIN + ACK
                chksum=0xFFFF,  # invalid checksum: endpoints drop, censor may accept
            )
            results.append(fake_fin)

        # --- Phase 1: initial SYN shadow logic ------------------------------
        is_syn = (tcp.flags & 0x02) != 0
        is_ack = (tcp.flags & 0x10) != 0
        if not is_syn or is_ack:
            # Not an initial SYN; forward original along with any fake FIN.
            results.append(pkt)
            return results

        # Only do the shadow SYN trick once per flow.
        if self._shadow_syn_used.get(key, False):
            results.append(pkt)
            return results

        self._shadow_syn_used[key] = True

        shadow_syn = pkt.copy()
        # Slightly perturb sequence number so censor may track a wrong seq;
        # invalid checksum ensures the real server drops it.
        shadow_syn[TCP].seq = (shadow_syn[TCP].seq + 7) & 0xFFFFFFFF
        shadow_syn[TCP].chksum = 0xFFFF
        opts = shadow_syn[TCP].options or []
        opts.append(("NOP", None))
        shadow_syn[TCP].options = opts

        real_syn = pkt.copy()
        real_syn[TCP].chksum = 0

        # Shadow first (for censor), then real SYN (for server).
        results.extend([shadow_syn, real_syn])
        return results
    
    
# EVOLVE-BLOCK-END