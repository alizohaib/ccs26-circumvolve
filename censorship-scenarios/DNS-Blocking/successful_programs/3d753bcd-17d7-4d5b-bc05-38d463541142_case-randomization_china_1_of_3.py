# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import os
import random
import struct

def _random_txid():
    # Random transaction ID to avoid simple replay signatures
    return random.randint(0, 0xFFFF)

def _encode_qname_with_case_randomization(name: str) -> str:
    """
    Apply 0x20 case randomization to the QNAME.
    Functionally identical for DNS, but can break naive
    case-sensitive DPI domain matchers.
    """
    res = []
    for ch in name:
        if "a" <= ch <= "z" or "A" <= ch <= "Z":
            # Randomly choose upper or lower case
            if random.getrandbits(1):
                res.append(ch.lower())
            else:
                res.append(ch.upper())
        else:
            res.append(ch)
    return "".join(res)

def generate_dns_request(target_domain=None):
    """
    Keep close to historically best-performing structure to recover
    Stage‑1 validity, while still adding some evasion features.

    Changes from current version:
    - Remove EDNS0 / OPT record, which previously correlated with -10 validity.
    - Return to a plain single‑question query (qdcount=1, arcount=0).
    - Keep 0x20 case randomization (cheap, RFC‑compliant evasion).
    - Keep TC=1 (seen to work in top programs) but switch to manual header
      packing to exactly mirror successful layouts (flags=0x0760).
    """
    if target_domain is None:
        raise ValueError("target_domain must be provided")

    # Apply QNAME case randomization
    randomized_qname = _encode_qname_with_case_randomization(target_domain)

    # Manually encode QNAME into DNS wire format to avoid scapy quirks
    labels = randomized_qname.strip(".").split(".")
    qname_bytes = b""
    for lbl in labels:
        b = lbl.encode("ascii")
        qname_bytes += bytes([len(b)]) + b
    qname_bytes += b"\x00"

    # Header fields matching top-performing programs (flags=0x0760)
    tid = _random_txid()
    flags = 0x0760  # QR=0, OPCODE=0, AA=0, TC=1, RD=1, RA=0, Z=0b101, RCODE=0
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)

    # QTYPE=A, QCLASS=IN
    question = qname_bytes + struct.pack("!HH", 1, 1)

    return header + question

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
