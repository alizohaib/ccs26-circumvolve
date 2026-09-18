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
    Generates a DNS request payload that is still resolver‑compatible but
    changes the control‑plane characteristics compared to the current best
    programs, to explore a different evasion region.

    Key differences vs current program:
    - Use non‑standard OpCode=STATUS (2) in a "query" (many resolvers just
      treat it as a normal query, but DPI that key on OpCode=0 may skip it).
    - Keep TC=1 and non‑zero Z bits (which previously preserved Stage‑1),
      but adjust the overall flag word accordingly.
    """
    if target_domain is None:
        target_domain = "example.com"

    # Transaction ID: random 16‑bit
    tid = random.randint(0, 0xFFFF)

    # Build flags via bit fields instead of a magic constant to change OpCode:
    # QR=0 (query)
    # OPCODE=2 (STATUS)  -> 0b0010
    # AA=0
    # TC=1
    # RD=1
    # RA=0
    # Z=0b101
    # RCODE=0
    qr = 0
    opcode = 2
    aa = 0
    tc = 1
    rd = 1
    ra = 0
    z = 0b101
    rcode = 0

    flags = (
        (qr << 15)
        | (opcode << 11)
        | (aa << 10)
        | (tc << 9)
        | (rd << 8)
        | (ra << 7)
        | (z << 4)
        | rcode
    )

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
