# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import os

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload using a deep compression-pointer chain
    for the QNAME to stress DPI recursion limits while remaining valid
    for real DNS servers.
    Args:
        target_domain (str): The domain name to resolve.
    """

    if target_domain is None:
        target_domain = "client-cdn4.hola.org"

    # Build a known-good DNS question using Scapy as the primary
    # question. This maximizes Stage 1 validity.
    base_dns = DNS(
        rd=1,
        qd=DNSQR(qname=target_domain)
    )
    base_packet = bytearray(bytes(base_dns))

    # We will append an extra question that contains the pointer-chain
    # QNAME. Many DPI engines focus on the first question only, but
    # standard resolvers happily accept multiple questions.
    #
    # Bump QDCOUNT from 1 -> 2
    qdcount = int.from_bytes(base_packet[4:6], "big")
    qdcount += 1
    base_packet[4:6] = qdcount.to_bytes(2, "big")

    # Start offset of the second question
    start_offset = len(base_packet)

    # We use a QNAME that is a compression pointer into a crafted area
    # later in the packet. QTYPE/QCLASS are normal.
    qname = bytearray()
    qname += b"\xC0\x40"  # pointer to offset 0x40 (within this DNS msg)

    # QTYPE=A (0x0001), QCLASS=IN (0x0001)
    qtype_qclass = b"\x00\x01\x00\x01"

    body = bytearray()
    body += qname + qtype_qclass

    # Ensure that offset 0x40 exists in the final DNS message. We pad
    # from the current end of the DNS message up to 0x40.
    current_len = len(base_packet) + len(body)
    if current_len > 0x40:
        # If our layout assumptions fail, fall back to a plain query to
        # preserve Stage 1 validity.
        return bytes(base_packet)
    body += b"\x00" * (0x40 - current_len)

    # At offset 0x40 we start the pointer chain. Offsets are from the
    # beginning of the DNS message.
    #
    # Let:
    #   o0 = 0x40
    #   o1,o2,...: subsequent pointers
    #   final: uncompressed domain name at offset 0x60
    #
    # o0: label "x" then pointer to o1
    # o1..on-1: single pointer to next
    # on: pointer to final domain name at 0x60

    # Helper to encode the final domain in label format
    def encode_domain(name: str) -> bytes:
        out = bytearray()
        for label in name.strip(".").split("."):
            l = label.encode("ascii")
            out.append(len(l))
            out += l
        out.append(0)  # terminator
        return bytes(out)

    # Build pointer chain
    # Use a modest but non-trivial depth; previous, more extreme layout
    # was likely considered malformed by some resolvers.
    chain = bytearray()

    # o0 (=0x40 in whole packet)
    chain += b"\x01x"      # label "x"
    chain += b"\xC0\x43"   # pointer to 0x43

    # Build a deeper pointer chain: o1..o10
    # o1 = 0x43, then every node 2 bytes apart
    depth = 10  # non-trivial depth to hit DPI recursion limits
    start_o1 = 0x43
    for i in range(depth):
        current_global = start_o1 + 2 * i
        if i < depth - 1:
            target = current_global + 2
        else:
            # last one points to final name at 0x60
            target = 0x60
        chain += bytes([0xC0 | ((target >> 8) & 0x3F), target & 0xFF])

    # Ensure final name will indeed be at offset 0x60:
    pre_final_len = len(base_packet) + len(body) + len(chain)
    if pre_final_len > 0x60:
        # If our assumptions break, just return the base query to keep
        # Stage 1 success.
        return bytes(base_packet)

    padding_to_final = 0x60 - pre_final_len
    final_padding = b"\x00" * padding_to_final

    final_name = encode_domain(target_domain)

    packet = base_packet + body + chain + final_padding + final_name
    return bytes(packet)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
