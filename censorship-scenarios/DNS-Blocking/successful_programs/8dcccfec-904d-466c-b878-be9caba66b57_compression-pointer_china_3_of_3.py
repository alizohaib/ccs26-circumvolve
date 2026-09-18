# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import os
import random
import struct

def _encode_qname(domain: str) -> bytes:
    """
    Encode a domain into DNS QNAME format manually.
    This lets us control label structure and possible corner cases
    while still producing a standards-compliant packet.
    """
    if not domain:
        return b"\x00"
    parts = domain.strip(".").split(".")
    out = b""
    for label in parts:
        # Clamp label length to 63 as per RFC, but allow odd patterns
        l = len(label)
        if l == 0:
            continue
        if l > 63:
            label = label[:63]
            l = 63
        out += struct.pack("!B", l) + label.encode("ascii")
    out += b"\x00"
    return out

def generate_dns_request(target_domain=None):
    """
    Generate a DNS request that stays very close to a vanilla successful
    candidate, but adds a second, compressed QNAME for the same target.
    Aim:
    - Preserve stage‑1 validity (stick to QTYPE=A which is known to work)
    - Keep header counters completely standard
    - Use an extra question whose QNAME is *only* a compression pointer
      back into the first QNAME. Many DPI implementations only parse
      the first question (QDCOUNT>=1) and ignore subsequent ones,
      while real resolvers are required to handle multiple questions.
    """
    if target_domain is None:
        target_domain = "example.com"

    # Build canonical QNAME bytes once, starting right after the 12‑byte header.
    # We will reference this location with a compression pointer in Q2.
    qname_bytes = _encode_qname(target_domain)

    # Random transaction ID, 16 bits
    tid = random.randint(0, 0xFFFF)

    # Flags: standard query, RD=1 only
    flags = 0x0100

    # Two questions, no answers/authority/additional
    # This is fully legal but uncommon on the wire.
    qdcount = 2
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)

    # First question: normal A/IN for the target domain (known to be accepted)
    qtype = 1   # A
    qclass = 1  # IN
    question1 = qname_bytes + struct.pack("!HH", qtype, qclass)

    # Second question: same type/class, but QNAME is a pure compression pointer
    #
    # Layout on the wire:
    #   [0..11] header
    #   [12..]  qname_bytes of Q1
    #
    # The start offset of Q1's QNAME is 12 (0x000c), so the compression pointer
    # uses 0xc0 0x0c. Some DPI stacks only parse the first question or mishandle
    # a QNAME that starts directly with a compression pointer.
    pointer_offset = 12
    qname_ptr = struct.pack("!H", 0xC000 | pointer_offset)
    question2 = qname_ptr + struct.pack("!HH", qtype, qclass)

    packet_bytes = header + question1 + question2
    return packet_bytes

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
