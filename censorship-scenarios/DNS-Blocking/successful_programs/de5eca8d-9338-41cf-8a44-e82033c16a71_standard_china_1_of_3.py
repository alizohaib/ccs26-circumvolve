# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import os
import random
import struct

def _encode_qname(domain: str) -> bytes:
    """
    Encode QNAME manually to allow subtle mutations while staying RFC‑compliant.
    """
    parts = domain.strip(".").split(".")
    out = b""
    for label in parts:
        lb = label.encode("ascii")
        out += struct.pack("!B", len(lb)) + lb
    out += b"\x00"
    return out

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with slight, RFC‑compliant header mutations
    to explore DPI parsing edge cases while remaining valid for real resolvers.
    Args:
        target_domain (str): The domain name to resolve.
    """
    if target_domain is None:
        target_domain = "example.com"

    # Random but stable-enough transaction ID
    tid = random.randint(0, 0xFFFF)

    # Flags: standard query, RD=1, but set Z bits to non‑zero (many DPI assume Z=0)
    # QR(0) OPCODE(0000) AA(0) TC(0) RD(1) RA(0) Z(111) RCODE(0000) = 0x0170
    flags = 0x0170

    qname = _encode_qname(target_domain)
    qtype = 1   # A
    qclass = 1  # IN

    header = struct.pack("!HHHHHH",
                         tid,      # ID
                         flags,    # Flags with non‑zero Z bits
                         1,        # QDCOUNT
                         0,        # ANCOUNT
                         0,        # NSCOUNT
                         0)        # ARCOUNT

    question = qname + struct.pack("!HH", qtype, qclass)

    packet = header + question
    return packet

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
