# EVOLVE-BLOCK-START

from scapy.all import IP, UDP, DNS, DNSQR
import os
import random
import struct

def _encode_qname_with_noise(domain: str) -> bytes:
    """
    Encode a domain into DNS QNAME format, but introduce benign,
    standards-compliant twists that may confuse simple DPI:
      * Random case per label (DNS is case-insensitive)
      * Optional trailing dot stripped
    Real resolvers accept this; DPI that does case-sensitive or naive
    string matching may fail.
    """
    if not domain:
        return b"\x00"
    labels = domain.strip(".").split(".")
    if not labels:
        return b"\x00"

    out = bytearray()

    for label in labels:
        # Randomize case per-character in each label
        encoded_chars = []
        for ch in label:
            if random.getrandbits(1):
                encoded_chars.append(ch.upper())
            else:
                encoded_chars.append(ch.lower())
        enc = "".join(encoded_chars).encode("ascii")
        out.append(len(enc))
        out.extend(enc)

    out.append(0)  # terminator
    return bytes(out)

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload that stays RFC‑compliant but introduces
    a second, compressed question. This mirrors the best‑performing prior
    program while still using our noisy QNAME encoder to keep diversity.
    """
    if target_domain is None:
        target_domain = "example.com"

    # ---- DNS Header (12 bytes) ----
    tid = random.randint(0, 0xFFFF)

    # Standard query, recursion desired
    flags = 0x0100

    # Two questions: one full QNAME, one compressed pointer to it
    qdcount = 2
    ancount = 0
    nscount = 0
    arcount = 0
    header = struct.pack("!HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)

    # ---- First Question (normal, noisy‑case QNAME) ----
    qname1 = _encode_qname_with_noise(target_domain)
    qtype = 1   # A
    qclass = 1  # IN
    question1 = qname1 + struct.pack("!HH", qtype, qclass)

    # ---- Second Question (compressed name) ----
    # QNAME starts immediately after the 12‑byte header, so offset is 0x0c.
    # Compression pointer format: 0b11xxxxxx xxxxxxxx => 0xC0 0x0C
    compressed_name = b"\xC0\x0C"
    question2 = compressed_name + struct.pack("!HH", qtype, qclass)

    packet_bytes = header + question1 + question2
    return packet_bytes

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
