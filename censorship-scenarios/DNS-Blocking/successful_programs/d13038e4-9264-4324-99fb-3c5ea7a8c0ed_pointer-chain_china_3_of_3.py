# EVOLVE-BLOCK-START

import os

def _encode_labels(domain: str) -> bytes:
    """
    Encode a domain into DNS label format: len(label) + label ... + 0x00
    """
    parts = domain.strip(".").split(".")
    out = bytearray()
    for label in parts:
        # guard against empty labels to keep packet RFC‑conformant
        if not label:
            continue
        out.append(len(label))
        out.extend(label.encode("ascii"))
    out.append(0)
    return bytes(out)

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with a controlled compression pointer
    chain, but always includes at least one completely normal question
    for robust Stage‑1 validity.

    Strategy:
    - Question 1: standard QNAME/QTYPE/QCLASS (no compression).
    - Append a name pool containing the real domain.
    - Build a 10‑deep pointer chain in that pool.
    - Question 2: QNAME is a single pointer to the head of this chain.
    """
    if target_domain is None:
        target_domain = "client-cdn4.hola.org"

    # --- DNS header (12 bytes) ---
    tid = int.from_bytes(os.urandom(2), "big")  # random transaction ID
    flags = 0x0100  # standard query, RD=1

    # Two questions: one plain, one pointer‑chain based
    qdcount = 2
    ancount = 0
    nscount = 0
    arcount = 0

    packet = bytearray()
    packet.extend(tid.to_bytes(2, "big"))
    packet.extend(flags.to_bytes(2, "big"))
    packet.extend(qdcount.to_bytes(2, "big"))
    packet.extend(ancount.to_bytes(2, "big"))
    packet.extend(nscount.to_bytes(2, "big"))
    packet.extend(arcount.to_bytes(2, "big"))

    # --- Question 1: fully normal encoding of the target domain ---
    qname_normal = _encode_labels(target_domain)
    qtype = 1   # A
    qclass = 1  # IN

    packet.extend(qname_normal)
    packet.extend(qtype.to_bytes(2, "big"))
    packet.extend(qclass.to_bytes(2, "big"))

    # --- Name pool for the pointer chain used by Question 2 ---
    base_offset = len(packet)
    packet.extend(qname_normal)  # store canonical domain once

    # Build a deeper pointer chain (depth 10) that eventually resolves
    # back to base_offset. Real resolvers will follow it; DPI may not.
    chain_depth = 10
    prev_offset = base_offset
    chain_offsets = []
    for _ in range(chain_depth):
        current_offset = len(packet)
        chain_offsets.append(current_offset)
        pointer_val = 0xC000 | prev_offset  # compression pointer
        packet.extend(pointer_val.to_bytes(2, "big"))
        prev_offset = current_offset

    # --- Question 2: QNAME is a pointer to the head of the chain ---
    head_offset = chain_offsets[-1]
    qname_pointer = 0xC000 | head_offset
    packet.extend(qname_pointer.to_bytes(2, "big"))
    packet.extend(qtype.to_bytes(2, "big"))
    packet.extend(qclass.to_bytes(2, "big"))

    return bytes(packet)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
