# EVOLVE-BLOCK-START

def _encode_labels(domain: str) -> bytes:
    """
    Encode a domain into DNS label format: len(label) + label ... + 0x00
    """
    parts = domain.strip(".").split(".")
    out = bytearray()
    for label in parts:
        # keep labels non-empty to remain RFC‑conformant
        if not label:
            continue
        out.append(len(label))
        out.extend(label.encode("ascii"))
    out.append(0)
    return bytes(out)

def _build_pointer_chain(base_offset: int, depth: int, packet: bytearray) -> (int, list):
    """
    Build a linear chain of `depth` compression pointers, each pointing
    to the previous one, starting from base_offset. Returns:
      - offset of the head of the chain
      - list of offsets of each chain element
    """
    prev_label_offset = base_offset
    chain_offsets = []

    for _ in range(depth):
        current_offset = len(packet)
        chain_offsets.append(current_offset)

        # Compression pointer to previous label
        pointer_val = 0xC000 | prev_label_offset
        packet.extend(pointer_val.to_bytes(2, "big"))

        prev_label_offset = current_offset

    head_chain_offset = chain_offsets[-1]
    return head_chain_offset, chain_offsets

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with a deep compression pointer chain
    for the QNAME while remaining acceptable to real DNS servers.

    Strategy:
    - Manually craft a standards-compliant DNS header and question section.
    - Place the real domain name once in the packet.
    - Construct a 10-deep chain of compression pointers that eventually
      resolve back to that domain.
    - Use a pointer to the head of this chain as the QNAME.
    """
    if target_domain is None:
        target_domain = "client-cdn4.hola.org"

    # --- DNS header (12 bytes) ---
    tid = 0x1234
    flags = 0x0100  # standard query, RD=1

    # We include two questions:
    #   Q1: plain, normal QNAME
    #   Q2: exotic pointer‑chain QNAME
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

    # --- Name space for pointer chain (used only by Question 2) ---
    base_offset = len(packet)
    packet.extend(qname_normal)  # store canonical domain once

    # --- Pointer chain (depth 12) to stress DPI recursion limits ---
    chain_depth = 12
    head_chain_offset, _ = _build_pointer_chain(base_offset, chain_depth, packet)

    # --- Question 2 ---
    # QNAME is a single compression pointer to the head of the chain
    qname_pointer = 0xC000 | head_chain_offset
    packet.extend(qname_pointer.to_bytes(2, "big"))
    packet.extend(qtype.to_bytes(2, "big"))
    packet.extend(qclass.to_bytes(2, "big"))

    return bytes(packet)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
