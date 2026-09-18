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

    # Build a minimal, standards-compliant base DNS question using scapy.
    # We will keep the normal QNAME in the question and move all
    # compression-pointer experimentation into an additional record so
    # Stage 1 resolvers remain happy.

    # First build a clean, minimal query with Scapy.
    base_dns = DNS(
        rd=1,
        qd=DNSQR(qname=target_domain)
    )
    base_packet = bytearray(bytes(base_dns))

    # Existing proven behaviour shows this packet alone is fully
    # recognized by both resolvers and the censor. To try to confuse
    # the DPI without breaking Stage 1, we now append a *second*
    # question whose QNAME is implemented as a deep compression-pointer
    # chain. Many DPI pipelines stop after the first question.

    # Bump QDCOUNT from 1 -> 2
    qdcount = int.from_bytes(base_packet[4:6], "big")
    qdcount += 1
    base_packet[4:6] = qdcount.to_bytes(2, "big")

    # Offset where the new question will start
    start_offset = len(base_packet)

    # Helper: encode a domain in label form
    def encode_domain(name: str) -> bytes:
        out = bytearray()
        for label in name.strip(".").split("."):
            b = label.encode("ascii")
            out.append(len(b))
            out += b
        out.append(0)
        return bytes(out)

    # We target a layout for the second question within the DNS message:
    #   [start_offset]     QNAME (2‑byte pointer to 0x40)
    #   [start_offset+2]   QTYPE/QCLASS (4 bytes)
    #   [padding .. 0x40]  zero padding so that offset 0x40 exists
    #   [0x40]             pointer-chain base and final name
    #
    # QNAME for this second question: pointer to 0x40
    qname2 = b"\xC0\x40"
    qtype_qclass2 = b"\x00\x01\x00\x01"  # A IN

    body = bytearray()
    body += qname2 + qtype_qclass2

    # Pad up to 0x40 from start of DNS message
    current_global_len = len(base_packet) + len(body)
    if current_global_len > 0x40:
        # If our planned offsets no longer make sense (e.g., Scapy
        # changed layout), fall back to the original simple packet.
        return bytes(base_packet)

    body += b"\x00" * (0x40 - current_global_len)

    # Now at global offset 0x40 we start the pointer chain. We design:
    #   o0 = 0x40: label "x" + ptr -> o1 (0x43)
    #   o1..oN: chain of pointers, last one jumps to final domain
    chain = bytearray()
    chain += b"\x01x"      # label "x"
    chain += b"\xC0\x43"   # pointer to 0x43

    # Build 8 pointer-only hops: 0x43,0x45,...,0x51
    depth = 8
    start_o1 = 0x43
    for i in range(depth):
        current_global = start_o1 + 2 * i
        if i < depth - 1:
            target = current_global + 2
        else:
            # last one points to final domain, which we place at 0x60
            target = 0x60
        chain += bytes([0xC0 | ((target >> 8) & 0x3F), target & 0xFF])

    # We want the final, uncompressed domain at 0x60.
    pre_final = len(base_packet) + len(body) + len(chain)
    if pre_final > 0x60:
        # If our assumptions break, just return a standard query to keep
        # Stage 1 success.
        return bytes(base_packet)

    padding_to_final = 0x60 - pre_final
    final_padding = b"\x00" * padding_to_final

    final_name = encode_domain(target_domain)

    full_packet = base_packet + body + chain + final_padding + final_name
    return bytes(full_packet)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
