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

    # Directly craft a minimally valid DNS query in raw bytes, without Scapy DNSQR,
    # and place the QNAME so that the censor sees a slightly shifted header/QNAME layout.
    #
    # Layout:
    #   [0:2]  Transaction ID
    #   [2:4]  Flags (RD=1)
    #   [4:6]  QDCOUNT = 1
    #   [6:8]  ANCOUNT = 0
    #   [8:10] NSCOUNT = 0
    #   [10:12]ARCOUNT = 0
    #   [12:..] Question (QNAME + QTYPE + QCLASS)

    # Encode QNAME manually
    labels = target_domain.strip(".").split(".")
    qname = bytearray()
    for lab in labels:
        l = len(lab)
        if l == 0 or l > 63:
            raise ValueError("invalid label length in domain")
        qname.append(l)
        qname.extend(lab.encode("ascii"))
    qname.append(0)

    # Standard A/IN
    qtype_qclass = (1).to_bytes(2, "big") + (1).to_bytes(2, "big")

    # Build header with a non-zero ANCOUNT to confuse simple parsers,
    # while still being parseable by a tolerant resolver.
    tid = 0x1234.to_bytes(2, "big")
    flags = 0x0100.to_bytes(2, "big")  # RD=1
    qdcount = (1).to_bytes(2, "big")
    ancount = (1).to_bytes(2, "big")   # non-zero, but no answer section present
    nscount = (0).to_bytes(2, "big")
    arcount = (0).to_bytes(2, "big")

    header = tid + flags + qdcount + ancount + nscount + arcount
    packet = header + bytes(qname) + qtype_qclass
    return packet

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END