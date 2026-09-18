# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import random
import struct


def _encode_qname(domain: str) -> bytes:
    """
    Manually encode QNAME with 0x20 case randomization to defeat
    naive case-sensitive DPI, while remaining RFC-compliant.
    """
    labels = domain.strip(".").split(".")
    encoded = b""
    for label in labels:
        # Randomize case per character (0x20 encoding)
        rc_label = "".join(
            (ch.upper() if random.getrandbits(1) else ch.lower())
            for ch in label
        )
        encoded += bytes([len(rc_label)]) + rc_label.encode("ascii")
    # Standard root terminator
    encoded += b"\x00"
    return encoded


def generate_dns_request(target_domain=None):
    """
    Generates a slightly 'weird' but valid DNS request payload aimed at
    improving evasion while staying resolver-compatible.

    Changes vs baseline:
    - Manual QNAME encoding with randomized case (0x20 encoding)
    - TC bit set (truncation) in header – some DPI engines ignore such packets
    - Z bits set non‑zero (some DPI are strict here, resolvers typically ignore)
    """
    if target_domain is None:
        target_domain = "example.com"

    # Transaction ID: random 16‑bit
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
