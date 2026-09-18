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
    Generate a DNS request that:
    - Stays very close to the best‑known successful candidate (Program 1)
    - Uses two questions, with the second QNAME being a pure compression pointer
    - Keeps QTYPE=A so stage‑1 validity remains high

    This reuses the proven “double‑question + compression pointer” trick that
    previously achieved evasion_success=1.0, but keeps our manual QNAME encoder.
    """
    if target_domain is None:
        target_domain = "example.com"

    # Build canonical QNAME bytes once, starting right after the 12‑byte header.
    qname_bytes = _encode_qname(target_domain)

    # Random transaction ID, 16 bits
    tid = random.randint(0, 0xFFFF)

    # Flags: standard query, RD=1 only (0x0100)
    flags = 0x0100

    # Two questions, no answers/authority/additional
    qdcount = 2
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)

    # First question: normal A/IN for the target domain
    qtype = 1   # A
    qclass = 1  # IN
    question1 = qname_bytes + struct.pack("!HH", qtype, qclass)

    # Second question: QNAME is a pure compression pointer back to Q1's QNAME.
    # Q1's QNAME starts immediately after the 12‑byte header, so offset = 12 (0x000c).
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
