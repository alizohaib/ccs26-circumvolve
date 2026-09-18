# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import os

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with slightly unusual but RFC‑compliant
    characteristics to explore DPI edge cases while remaining valid for
    standard DNS resolvers.
    Args:
        target_domain (str): The domain name to resolve.
    """

    if target_domain is None:
        raise ValueError("target_domain must be provided")

    # Generate a random 16‑bit Transaction ID for diversity
    tid = os.urandom(2)
    tid_int = int.from_bytes(tid, "big")

    # Build a very standard-looking query first so we regain stage‑1 validity.
    # Use a classic A‑record query, which resolvers definitely support well.
    base_q = DNSQR(
        qname=target_domain,
        qtype=1,       # A record
        qclass=0x0001  # IN class
    )

    # Add a *second* question with a different QTYPE. Multiple‑question
    # queries are rare but RFC‑legal. Many DNS servers answer only the
    # first question but still parse the packet correctly, while DPI
    # often assumes QDCOUNT==1 and only inspects the first QNAME.
    extra_q = DNSQR(
        qname=target_domain,
        qtype=0x001c,  # AAAA record
        qclass=0x0001
    )

    # Manually chain the questions: in scapy, multiple questions can be
    # represented via the / operator. This keeps the packet valid while
    # exercising DPI assumptions about QDCOUNT handling.
    qd_chain = base_q / extra_q

    dns_layer = DNS(
        id=tid_int,
        rd=1,
        qdcount=2,     # two questions
        ancount=0,
        nscount=0,
        arcount=0,     # drop EDNS(0) for now to simplify and fix validity
        qd=qd_chain,
    )

    # Return only the raw DNS payload bytes
    return bytes(dns_layer)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
