# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import os
import random
import struct


def _encode_qname(domain: str) -> bytes:
    """
    Manually encode QNAME with randomized case (0x20 encoding)
    to evade simple case-sensitive matchers, while remaining
    fully RFC-compliant for resolvers.
    """
    labels = domain.strip(".").split(".")
    encoded = b""
    for label in labels:
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

    Evasive tweaks (while staying resolver-compatible and close to
    previously good performers):
      - Manual QNAME encoding with randomized case (0x20 encoding)
      - TC (truncated) bit set on UDP query (some DPI engines skip these)
      - Non-zero Z bits (some DPI are strict here, resolvers typically ignore)
    """
    if target_domain is None:
        target_domain = "example.com"

    # Transaction ID: random 16-bit
    tid = random.randint(0, 0xFFFF)

    # Flags layout: QR(1) OPCODE(4) AA(1) TC(1) RD(1) RA(1) Z(3) RCODE(4)
    # We want: QR=0, OPCODE=0, AA=0, TC=1, RD=1, RA=0, Z=0b101, RCODE=0
    # Binary: 0000 0111 0110 0000 = 0x0760
    flags = 0x0760

    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)

    # Manually encoded QNAME (with case randomization), QTYPE=A, QCLASS=IN
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
