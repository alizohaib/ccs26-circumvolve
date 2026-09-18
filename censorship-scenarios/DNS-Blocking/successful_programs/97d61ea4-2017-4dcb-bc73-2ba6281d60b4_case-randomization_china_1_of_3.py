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
    Generates a valid but slightly unusual DNS request payload aimed at
    improving DPI evasion while remaining resolver-compatible.

    Evasion choices:
    - Manual QNAME encoding with randomized case (0x20 encoding)
    - OpCode set to STATUS (2) instead of standard QUERY (0) – many
      resolvers still answer it as a normal query, while some DPI
      implementations only scrutinize opcode=0 traffic.
    - TC bit cleared and Z bits kept 0 to look more conventional than
      the previous version (which may have attracted attention).
    """
    if target_domain is None:
        target_domain = "example.com"

    # Transaction ID: random 16‑bit
    tid = random.randint(0, 0xFFFF)

    # Flags layout: QR(1) OPCODE(4) AA(1) TC(1) RD(1) RA(1) Z(3) RCODE(4)
    # We choose: QR=0, OPCODE=2 (STATUS), AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
    # Bits: QR=0 at bit15
    #       OPCODE=2 at bits 14..11  -> 0b0010
    #       AA=0 (bit10), TC=0 (bit9), RD=1 (bit8)
    #       RA=0 (bit7), Z=0 (bits6..4), RCODE=0 (bits3..0)
    flags = (2 << 11) | (1 << 8)  # 0x0480

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
