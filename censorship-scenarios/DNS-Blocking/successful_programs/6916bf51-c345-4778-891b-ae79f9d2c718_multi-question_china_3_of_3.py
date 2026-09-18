# EVOLVE-BLOCK-START

from scapy.all import DNS

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload.
    Args:
        target_domain (str): The domain name to resolve.
    """
    if target_domain is None:
        raise ValueError("target_domain must be provided")

    # Encode the target as a normal QNAME (we keep it completely standard)
    labels = target_domain.strip(".").split(".")
    qname = b"".join(
        bytes((len(label),)) + label.encode("utf-8") for label in labels if label
    ) + b"\x00"

    # DNS header claims TWO questions, but we will actually include only ONE.
    # Some DPI implementations respect QDCOUNT strictly and may try to parse
    # a second (non-existent) question, getting desynchronized and failing
    # to reliably extract the QNAME, while typical resolvers just parse
    # the first one and ignore the mismatch.
    header = (
        b"\x12\x34"  # ID
        b"\x01\x00"  # standard query, RD=1
        b"\x00\x02"  # QDCOUNT = 2 (intentional mismatch)
        b"\x00\x00"  # ANCOUNT
        b"\x00\x00"  # NSCOUNT
        b"\x00\x00"  # ARCOUNT
    )

    # Only one well-formed question carrying the censored domain.
    question = qname + b"\x00\x01" + b"\x00\x01"  # QTYPE=A, QCLASS=IN

    raw_pkt = header + question

    # Let Scapy normalize basic fields while keeping the odd QDCOUNT layout.
    scapy_pkt = DNS(raw_pkt)
    return bytes(scapy_pkt)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END