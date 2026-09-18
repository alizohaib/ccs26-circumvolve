from scapy.all import DNS, DNSQR
import os

# EVOLVE-BLOCK-START
def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload.
    Args:
        target_domain (str): The domain name to resolve.
    """
    if target_domain is None:
        target_domain = "example.com"

    # Build a minimal, standard A-record query first (single QNAME present)
    base_dns = DNS(
        rd=1,
        qd=DNSQR(qname=target_domain, qtype="A")
    )

    # Serialize to wire format so we can manually tweak header and question
    wire = bytearray(bytes(base_dns))

    # DNS header layout: [0:2] ID, [2:4] flags, [4:6] QDCOUNT, [6:8] ANCOUNT,
    #                    [8:10] NSCOUNT, [10:12] ARCOUNT
    # We keep counts as‑is (1 question, no answers/NS/AR).

    # Locate the end of QNAME to overwrite QTYPE/QCLASS in place.
    # QNAME is a sequence of length‑prefixed labels ending in 0x00, then:
    #   QTYPE (2 bytes) | QCLASS (2 bytes)
    idx = 12  # first byte after header
    while idx < len(wire) and wire[idx] != 0:
        idx += 1 + wire[idx]  # skip length byte + label
    qname_end = idx  # points at the 0x00 root label
    type_offset = qname_end + 1  # first byte of QTYPE

    # Change QTYPE from A(1) to ANY(255) to perturb semantics while
    # still keeping the QNAME intact and visible in the question.
    wire[type_offset:type_offset + 2] = (255).to_bytes(2, "big")

    # Now append a second question that uses a pointer compression to the
    # original QNAME, but explicitly asks type A, satisfying the "A record
    # request" requirement while putting the true A‑query later in the packet.
    #
    # Pointer to the original QNAME at offset 12 (0x0c): 0xC0 0x0C
    compressed_qname = b"\xc0\x0c"
    qtype_a = (1).to_bytes(2, "big")     # A
    qclass_in = (1).to_bytes(2, "big")   # IN
    second_q = compressed_qname + qtype_a + qclass_in

    # Increase QDCOUNT from 1 to 2
    qdcount = int.from_bytes(wire[4:6], "big")
    wire[4:6] = (qdcount + 1).to_bytes(2, "big")

    # Append the compressed second question to the packet
    wire.extend(second_q)

    return bytes(wire)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END

