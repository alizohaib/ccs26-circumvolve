# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import os

def _build_pointer_chain_name(raw_pkt: bytes, depth: int) -> bytes:
    """
    Build a QNAME that is a chain of compression pointers, but keep the
    original plain QNAME immediately before it to maximize compatibility.

    Layout after transformation:

        [0:12]   DNS header
        [12:?]   original QNAME (labels + 0x00)
        [? :?+4] original QTYPE + QCLASS   <-- we keep these bytes
        [name_pool...]
        [pointer_chain...]
        [QNAME = pointer into chain]
        [QTYPE + QCLASS]

    This preserves the entire original question section and simply appends
    an additional question that uses the deep pointer chain. Resolvers will
    still parse at least one valid question; DPI might focus on the second
    one and get confused by the chain.
    """
    pkt = bytearray(raw_pkt)

    # Locate the end of the current QNAME by walking labels.
    idx = 12
    while idx < len(pkt) and pkt[idx] != 0:
        if idx + 1 > len(pkt):
            return raw_pkt
        length = pkt[idx]
        idx += 1 + length
    if idx >= len(pkt):
        return raw_pkt

    qname_start = 12
    qname_end = idx + 1  # include terminating 0x00

    # Original QTYPE/QCLASS
    if qname_end + 4 > len(pkt):
        return raw_pkt
    qtype_qclass = pkt[qname_end:qname_end + 4]

    # We keep the entire original message intact and only append a second
    # question that uses the pointer-chain name.
    out = bytearray(pkt)

    # ARCOUNT, NSCOUNT, ANCOUNT remain zero; we only modify QDCOUNT to 2.
    # QDCOUNT is at bytes 4–5 of the DNS header.
    if len(out) < 12:
        return raw_pkt
    # Existing QDCOUNT from original Scapy packet is 1; set to 2.
    out[4:6] = (2).to_bytes(2, "big")

    # Start of our appended "name pool" is current length.
    base_offset = len(out)

    # Place the canonical encoded domain once in the new area so that
    # our pointer chain ultimately resolves to a real name.
    base_domain_offset = base_offset
    base_domain_bytes = pkt[qname_start:qname_end]
    out.extend(base_domain_bytes)

    # Build the pointer chain in the new area.
    chain_depth = max(10, min(depth, 20))
    prev_offset = base_domain_offset
    chain_offsets = []
    for _ in range(chain_depth):
        current_offset = len(out)
        chain_offsets.append(current_offset)
        pointer_val = 0xC000 | prev_offset
        out.extend(pointer_val.to_bytes(2, "big"))
        prev_offset = current_offset

    # Second question's QNAME: pointer to the head of the chain.
    head_offset = chain_offsets[-1]
    qname_pointer = 0xC000 | head_offset
    out.extend(qname_pointer.to_bytes(2, "big"))

    # Second question's QTYPE/QCLASS: same as original.
    out.extend(qtype_qclass)

    return bytes(out)

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with a controlled compression pointer
    chain in the QNAME to explore DPI parsing weaknesses while staying
    close to a resolver‑valid Scapy packet.
    """
    if target_domain is None:
        target_domain = "client-cdn4.hola.org"

    # Start from a normal Scapy DNS query for maximum Stage‑1 robustness.
    base_dns = DNS(
        rd=1,
        qd=DNSQR(qname=target_domain)
    )

    # Convert to bytes, then post‑process to inject our pointer‑chain QNAME.
    raw = bytes(base_dns)

    # Use a moderate chain depth; deeper chains can be tried by the search
    # algorithm but we keep a safe default here.
    crafted = _build_pointer_chain_name(raw, depth=5)

    return crafted

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
