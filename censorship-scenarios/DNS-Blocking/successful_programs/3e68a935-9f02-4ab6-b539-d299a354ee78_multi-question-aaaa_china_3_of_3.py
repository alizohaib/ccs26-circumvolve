# EVOLVE-BLOCK-START

from scapy.all import IP, UDP, DNS, DNSQR
import os

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload crafted to remain valid for real DNS
    servers but slightly unusual to potentially evade simplistic DPI.
    Args:
        target_domain (str): The domain name to resolve.
    """

    # Fallback domain if none provided (keeps function usable in other tests)
    if target_domain is None:
        target_domain = "example.com"

    # Use an explicit random transaction ID to avoid any predictable pattern.
    txid = int.from_bytes(os.urandom(2), "big")

    # Build a query with two questions:
    #  - Q1: target_domain A
    #  - Q2: target_domain AAAA
    # Many DPI implementations assume a single question and either:
    #  * parse only the first and ignore the rest, or
    #  * mishandle multi-question parsing under performance constraints.
    #
    # Standard DNS resolvers accept multi-question queries (even if many
    # reply only to the first), so stage 1 validity should remain good
    # while changing evasion behavior relative to the simple single-question
    # baseline that scored -3.
    dns_layer = DNS(
        id=txid,
        rd=1,
        qdcount=2,
        qd=DNSQR(qname=target_domain, qtype="A", qclass="IN") /
           DNSQR(qname=target_domain, qtype="AAAA", qclass="IN")
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
