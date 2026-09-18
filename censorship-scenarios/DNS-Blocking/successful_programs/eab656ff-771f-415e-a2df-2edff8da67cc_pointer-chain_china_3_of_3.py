# EVOLVE-BLOCK-START

# NOTE: We intentionally avoid external packet-building libraries here and
# instead craft the DNS payload manually so we can precisely control
# compression pointer layout and depth.

def _encode_labels(domain: str) -> bytes:
    parts = domain.strip(".").split(".")
    out = bytearray()
    for label in parts:
        out.append(len(label))
        out.extend(label.encode("ascii"))
    out.append(0)  # terminating 0-length label
    return bytes(out)

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with a deep chain of compression pointers
    appended after a fully normal question. This keeps at least one
    RFC-compliant question for Stage 1 resolvers while still exercising
    DPI pointer-depth limits on a second question.

    Strategy:
    - Build a completely standard query (header + QNAME + QTYPE/QCLASS).
    - Append a "name space" containing the real domain and a pointer chain.
    - Add a *second* question whose QNAME is a pointer into the head of
      that chain.
    - QDCOUNT is set to 2 so resolvers have one trivial and one exotic
      question.
    """
    if target_domain is None:
        target_domain = "client-cdn4.hola.org"

    # --- DNS header (12 bytes) ---
    tid = 0x1234
    flags = 0x0100  # standard query, RD=1
    # We will include two questions:
    #   Q1: plain, normal QNAME
    #   Q2: pointer-chain QNAME
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

    # --- Question 1: completely normal encoding of the domain ---
    qname_normal = _encode_labels(target_domain)
    qtype = 1   # A
    qclass = 1  # IN
    packet.extend(qname_normal)
    packet.extend(qtype.to_bytes(2, "big"))
    packet.extend(qclass.to_bytes(2, "big"))

    # --- "Name space" for pointer chain (used only by Question 2) ---
    name_space_start = len(packet)

    # Place the canonical domain once in the name space.
    base_domain_offset = name_space_start
    packet.extend(qname_normal)  # reuse exact same encoding

    # Build a deeper pointer chain that eventually resolves to the base domain.
    # Increase depth to better explore DPI recursion limits while keeping at
    # least one fully standard question (Q1) for resolver robustness.
    chain_depth = 12
    prev_label_offset = base_domain_offset
    chain_offsets = []

    for _ in range(chain_depth):
        current_offset = len(packet)
        chain_offsets.append(current_offset)
        # Standard DNS compression pointer: top two bits 11, lower 14 bits offset
        pointer_val = 0xC000 | prev_label_offset
        packet.extend(pointer_val.to_bytes(2, "big"))
        prev_label_offset = current_offset

    # --- Question 2: QNAME is a pointer to the head of the chain ---
    head_chain_offset = chain_offsets[-1]
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
