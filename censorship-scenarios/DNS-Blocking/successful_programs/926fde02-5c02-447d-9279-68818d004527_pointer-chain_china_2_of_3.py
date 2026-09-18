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
    Generates a DNS request payload with a deep compression‑pointer chain.
    This follows the "Pointer Chain Depth Attack" strategy:

    - Question.QNAME is a compression pointer into the Answer section.
    - The Answer NAME field points to a chain of 10 compression pointers.
    - The final pointer in the chain points to the real, uncompressed
      target_domain labels at the end of the packet.

    Real resolvers are tolerant of such structures, but DPI engines may
    impose low recursion limits and thus fail to fully resolve the QNAME.
    """
    if target_domain is None:
        target_domain = "client-cdn4.hola.org"

    # --- DNS header ---
    tid = os.urandom(2)
    flags = 0x0100  # standard query, RD=1
    qdcount = 1
    ancount = 1  # synthetic answer hosts the chain
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

    # Question section
    # QNAME will be a compression pointer; we patch the offset later.
    qname_pointer_offset = len(packet)
    packet.extend(b"\xc0\x00")  # placeholder pointer

    # QTYPE=A, QCLASS=IN
    packet.extend(struct.pack("!HH", 1, 1))

    # Record where the Answer section NAME field starts
    answer_start_offset = len(packet)

    # --- Answer section: build pointer chain host record ---
    # NAME: pointer to first chain element (patched later)
    name_pointer_offset = len(packet)
    packet.extend(b"\xc0\x00")  # placeholder

    # TYPE=A, CLASS=IN, TTL, RDLENGTH, RDATA (dummy)
    packet.extend(struct.pack("!HHI", 1, 1, 60))
    packet.extend(struct.pack("!H", 4))
    packet.extend(b"\x7f\x00\x00\x01")  # 127.0.0.1 dummy IP

    # After the fixed fields, place a chain of compression pointers.
    chain_depth = 10  # requested 10–20; we choose 10
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

    # Question.QNAME pointer points to start of Answer section (NAME field)
    ptr_val = 0xC000 | answer_start_offset
    packet[qname_pointer_offset] = (ptr_val >> 8) & 0xFF
    packet[qname_pointer_offset + 1] = ptr_val & 0xFF

    return bytes(packet)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
