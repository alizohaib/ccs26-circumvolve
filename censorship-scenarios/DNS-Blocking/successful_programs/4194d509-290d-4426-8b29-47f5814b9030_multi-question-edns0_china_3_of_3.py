# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
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

    # Core idea: keep the previously high‑fitness multi‑question structure,
    # but remove the EDNS(0) OPT record which recently caused stage1_validity
    # to drop to -10. This returns to a simpler, well‑proven format while
    # still being slightly unusual (QDCOUNT=2) for DPI.
    #
    # Question 1: target_domain A
    # Question 2: target_domain AAAA
    qd = DNSQR(qname=target_domain, qtype="A", qclass="IN") / \
         DNSQR(qname=target_domain, qtype="AAAA", qclass="IN")

    # Explicitly set qdcount to match the two chained DNSQR entries.
    dns_layer = DNS(
        id=txid,
        rd=1,
        qdcount=2,
        qd=qd
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
