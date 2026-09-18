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

    # Build two questions to exploit DPI assumptions about QDCOUNT==1.
    # First is a very standard A query that resolvers will happily answer.
    base_q = DNSQR(
        qname=target_domain,
        qtype=1,        # A record
        qclass=0x0001   # IN class
    )

    # Second question is an AAAA query for the same name. Multiple
    # questions are rare but RFC‑compliant and previously achieved
    # good fitness in Program 1.
    extra_q = DNSQR(
        qname=target_domain,
        qtype=0x001c,   # AAAA record
        qclass=0x0001
    )

    # Chain questions so scapy encodes them sequentially.
    qd_chain = base_q / extra_q

    dns_layer = DNS(
        id=tid_int,
        rd=1,
        qdcount=2,      # two questions in the Question Section
        ancount=0,
        nscount=0,
        arcount=0,
        qd=qd_chain,
    )

    # Return only the raw DNS payload bytes
    return bytes(dns_layer)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
