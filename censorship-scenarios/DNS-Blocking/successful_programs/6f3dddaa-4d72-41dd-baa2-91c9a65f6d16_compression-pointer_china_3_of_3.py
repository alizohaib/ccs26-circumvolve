from scapy.all import DNS, DNSQR
import os

# EVOLVE-BLOCK-START
def generate_dns_request(target_domain=None):
    """
    Generates a DNS A-record request using an explicit header and
    compressed QNAME layout to alter packet structure while keeping
    the target domain intact.
    """
    if target_domain is None:
        target_domain = "example.com"

    # Randomize ID and some less-critical flags for diversity
    txid = int.from_bytes(os.urandom(2), "big")

    # Build a normal question first so scapy serializes QNAME correctly
    base_dns = DNS(
        id=txid,
        qr=0,
        rd=1,
        qdcount=1,
        qd=DNSQR(qname=target_domain, qtype="A", qclass="IN")
    )

    raw = bytearray(bytes(base_dns))

    # Implement minimal manual name compression:
    # leave QNAME as-is, but add a fake second question that points
    # back to the first QNAME using a compression pointer (0xC0 0x0C).
    # This changes the packet shape while still having the domain
    # present in clear text in the first question.
    #
    # DNS header is 12 bytes; first QNAME starts at offset 12 (0x0c).
    pointer_offset = 0x0C

    # Find end of first QNAME (terminated by 0x00)
    idx = 12
    while idx < len(raw) and raw[idx] != 0:
        idx += 1
    if idx >= len(raw):
        # fallback: if parsing fails, just return base packet
        return bytes(raw)

    qname_end = idx + 1  # include the zero terminator

    # After QNAME: type (2 bytes) + class (2 bytes)
    first_q_end = qname_end + 4

    # Construct a second question using only a compressed name pointer
    compressed_qname = bytes([0xC0, pointer_offset])
    qtype_qclass = raw[qname_end:first_q_end]  # reuse A/IN

    second_question = compressed_qname + qtype_qclass

    # Update qdcount from 1 to 2 in DNS header
    raw[4] = 0x00
    raw[5] = 0x02

    # Append the compressed second question
    raw.extend(second_question)

    return bytes(raw)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END

