from scapy.all import DNS, DNSQR
import os

# EVOLVE-BLOCK-START
def generate_dns_request(target_domain=None):
    """
    Generates a DNS A-record query while mutating rarely used header flags to
    perturb DPI parsing, without using EDNS0, multiple QNAMEs, or compression.
    """
    if target_domain is None:
        target_domain = "example.com"

    # Random transaction ID
    tid = int.from_bytes(os.urandom(2), "big")

    # Build a single-question A-record query
    dns_layer = DNS(
        id=tid,
        # Non-standard but syntactically valid flag combination:
        # AA (authoritative answer) set in a query + reserved Z bit set.
        # Some DPI implementations may mis-handle this unusual header.
        qr=0,   # query
        opcode=0,
        aa=1,   # uncommon for queries
        tc=0,
        rd=1,
        ra=0,
        z=1,    # reserved bit set
        ad=0,
        cd=0,
        qdcount=1,
        ancount=0,
        nscount=0,
        arcount=0,
        qd=DNSQR(qname=target_domain, qtype="A", qclass="IN"),
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END

