# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import os
import random
import struct

def _random_tid():
    # Random transaction ID to avoid trivial fingerprinting
    return random.randint(0, 0xFFFF)

def _encode_qname(domain: str) -> bytes:
    """
    Manually encode QNAME with randomized case (0x20 encoding)
    to evade simple case-sensitive matchers, while remaining
    fully RFC-compliant for resolvers.
    """
    labels = domain.strip(".").split(".")
    encoded = b""
    for label in labels:
        # Randomize case per character
        rc_label = "".join(
            (ch.upper() if random.getrandbits(1) else ch.lower())
            for ch in label
        )
        encoded += bytes([len(rc_label)]) + rc_label.encode("ascii")
    encoded += b"\x00"
    return encoded

def generate_dns_request(target_domain=None):
    """
    Generates a slightly 'weird' but valid DNS request payload.
    Techniques used (aimed at DPI evasion while staying valid):
      - 0x20 case randomization of QNAME
      - TC (truncated) bit set on UDP query (some DPI skip these)
      - Non-zero Z bits (some DPI are strict here, resolvers ignore)
    """

    if target_domain is None:
        target_domain = "example.com"

    # Build DNS header manually for finer control:
    # ID | Flags | QDCOUNT | ANCOUNT | NSCOUNT | ARCOUNT
    tid = _random_tid()

    # Flags: QR=0, OPCODE=0, AA=0, TC=1, RD=1, RA=0, Z=0b101, RCODE=0
    # bit layout:  QR(1) OPCODE(4) AA(1) TC(1) RD(1) RA(1) Z(3) RCODE(4)
    # We'll construct: 0b0000_0111_0110_0000 = 0x0760
    flags = 0x0760

    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)

    # QNAME (with case-randomization), QTYPE=A, QCLASS=IN
    qname = _encode_qname(target_domain)
    qtype = 1
    qclass = 1
    question = qname + struct.pack("!HH", qtype, qclass)

    packet_bytes = header + question
    return packet_bytes

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
