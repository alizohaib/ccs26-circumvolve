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
    Generates a DNS request payload that remains RFC‑compliant for real
    resolvers but uses a slightly more complex question layout (two
    questions, with the second using a compression pointer) to try to
    confuse DPI that assumes a single, linear QNAME.
    """
    if target_domain is None:
        target_domain = "example.com"

    # Transaction ID: random 16‑bit
    txid = random.randint(0, 0xFFFF)

    # Flags: standard query, RD=1, all Z bits zero to stay maximally
    # compatible with resolvers and avoid them treating the query as odd.
    flags = (0x01 << 8)

    # We advertise two questions (QDCOUNT = 2).
    # The first is a normal QNAME; the second's NAME is a compression
    # pointer back into the first QNAME. Real resolvers must handle this.
    # Some DPI stacks only parse the first question or fail to follow
    # pointers in later questions, which may help evade injection.
    qdcount = 2
    ancount = 0
    nscount = 0
    arcount = 0
    header = struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)

    # First Question: standard, explicit QNAME
    qname = _encode_qname(target_domain)
    qtype = 1   # A
    qclass = 1  # IN
    question1 = qname + struct.pack("!HH", qtype, qclass)

    # Second Question: NAME is a compression pointer (C0 0C) to offset 12
    # (start of first QNAME right after the 12‑byte header).
    pointer_to_qname = b"\xc0\x0c"
    qtype2 = 1
    qclass2 = 1
    question2 = pointer_to_qname + struct.pack("!HH", qtype2, qclass2)

    packet_bytes = header + question1 + question2
    return packet_bytes

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
