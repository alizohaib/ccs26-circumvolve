# EVOLVE-BLOCK-START

from scapy.all import IP, UDP, DNS, DNSQR
import os
import random
import struct

def _encode_qname_with_noise(domain: str) -> bytes:
    """
    Encode a domain into DNS QNAME format, but introduce a benign,
    standards-compliant twist that may confuse simple DPI:
    - First label is encoded in UPPERCASE
    - Remaining labels are lowercase
    DNS is case-insensitive for QNAME, so resolvers accept this.
    Some DPI stacks may match forbidden domains case-sensitively.
    """
    if not domain:
        return b"\x00"
    labels = domain.strip(".").split(".")
    if not labels:
        return b"\x00"

    out = bytearray()

    for i, label in enumerate(labels):
        if i == 0:
            enc = label.upper().encode("ascii")  # first label uppercased
        else:
            enc = label.lower().encode("ascii")  # rest lowercased
        out.append(len(enc))
        out.extend(enc)

    out.append(0)  # terminator
    return bytes(out)

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload that is RFC‑compliant for resolvers but
    slightly unusual for DPI:
      * QDCOUNT = 2 but only one full question is present.
      * Second "question" is a compression pointer back into the first QNAME,
        followed by QTYPE/QCLASS. Many resolvers ignore or robustly parse this,
        while simpler DPI may mis-handle the extra pointer-based question.
    """
    if target_domain is None:
        target_domain = "example.com"

    # ---- DNS Header (12 bytes) ----
    tid = random.randint(0, 0xFFFF)

    # Standard query, recursion desired
    flags = 0x0100

    # Advertise two questions, but the second uses a compressed name
    qdcount = 2
    ancount = 0
    nscount = 0
    arcount = 0
    header = struct.pack("!HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)

    # ---- First Question (normal) ----
    qname1 = _encode_qname_with_noise(target_domain)
    qtype = 1   # A
    qclass = 1  # IN
    question1 = qname1 + struct.pack("!HH", qtype, qclass)

    # Offset for the beginning of the first QNAME:
    # header is 12 bytes, so QNAME starts at 12 (0x0c)
    # Build a compression pointer to that offset.
    #
    # Name = 0xC0 | high 6 bits, followed by low 8 bits -> 0xC00C
    compressed_name = b"\xC0\x0C"
    question2 = compressed_name + struct.pack("!HH", qtype, qclass)

    packet_bytes = header + question1 + question2
    return packet_bytes

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
