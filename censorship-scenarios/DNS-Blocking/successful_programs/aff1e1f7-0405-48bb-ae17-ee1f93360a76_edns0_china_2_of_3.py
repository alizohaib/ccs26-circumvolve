# EVOLVE-BLOCK-START

import os

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with slight DNS-layer mutations
    that remain RFC-compliant but may confuse simplistic DPI.
    Args:
        target_domain (str): The domain name to resolve.
    """
    # Fallback domain if none provided
    if target_domain is None:
        target_domain = "example.com"

    # Randomize transaction ID while keeping it in integer form for simpler tooling
    # Use 0 so that some DPI might treat this as a "default" or malformed ID and ignore it,
    # but it is still fully valid for servers.
    txid = (0).to_bytes(2, "big")

    # Build DNS header + question manually so we can tweak fields:
    # - Set RD=1 (recursion desired) as usual
    # - Set OPCODE to "IQuery" (0) but flip the "Z" reserved bits in flags to non-zero.
    #   Some DPI implementations incorrectly assume Z==0 and may bail out.
    #
    # Flags layout (16 bits):
    # QR(1) OPCODE(4) AA(1) TC(1) RD(1) RA(1) Z(3) RCODE(4)
    #
    # We'll set:
    #   QR=0 (query)
    #   OPCODE=0 (standard)
    #   AA=0, TC=0
    #   RD=1
    #   RA=0
    #   Z=0b101 (non-zero reserved bits, still accepted by many servers)
    #   RCODE=0
    flags = 0
    flags |= (0 << 15)      # QR
    flags |= (0 << 11)      # OPCODE
    flags |= (0 << 10)      # AA
    flags |= (0 << 9)       # TC
    flags |= (1 << 8)       # RD
    flags |= (0 << 7)       # RA
    flags |= (0b101 << 4)   # Z (non-zero)
    flags |= 0              # RCODE

    # One question, but *spoof* an extra additional record count.
    # We do NOT actually append that record so many DPI engines that
    # trust ARCOUNT may overrun or give up, while tolerant DNS servers
    # ignore the inconsistent count and still parse QNAME.
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 1

    # Encode QNAME manually to keep it totally standard on the wire
    labels = target_domain.strip(".").split(".")
    qname_bytes = b"".join(len(label).to_bytes(1, "big") + label.encode("ascii") for label in labels) + b"\x00"

    # Standard A IN query
    qtype = 1
    qclass = 1

    header = (
        txid +
        flags.to_bytes(2, "big") +
        qdcount.to_bytes(2, "big") +
        ancount.to_bytes(2, "big") +
        nscount.to_bytes(2, "big") +
        arcount.to_bytes(2, "big")
    )
    question = qname_bytes + qtype.to_bytes(2, "big") + qclass.to_bytes(2, "big")

    packet_bytes = header + question
    return packet_bytes

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
