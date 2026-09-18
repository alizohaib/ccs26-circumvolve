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

    # Fallback domain if none provided
    if target_domain is None:
        target_domain = "example.com"

    # Build a more complex, but still standards-compliant, query:
    # - Explicit random transaction ID (instead of scapy default)
    # - Two questions:
    #     Q1: target_domain A
    #     Q2: a harmless extra AAAA query for the same name
    # Some DPI implementations assume a single question and may only
    # parse the first or may mishandle multi-question messages.
    txid = int.from_bytes(os.urandom(2), "big")

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
