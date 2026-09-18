# EVOLVE-BLOCK-START

from scapy.all import IP, UDP, DNS, DNSQR
import os

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload that stays RFC‑compliant for real resolvers
    but is slightly unusual to potentially confuse simplistic DPI.
    Args:
        target_domain (str): The domain name to resolve.
    """
    if target_domain is None:
        raise ValueError("target_domain must be provided")

    # Use a fixed, non‑zero transaction ID for reproducibility
    txid = 0x4242

    # Ask both A and AAAA in the same packet (QDCOUNT=2). Some DPI
    # implementations assume a single question and may mis‑parse multi‑QNAME.
    dns_layer = DNS(
        id=txid,
        rd=1,
        qdcount=2,
        qd=DNSQR(qname=target_domain, qtype="A", qclass="IN") /
           DNSQR(qname=target_domain, qtype="AAAA", qclass="IN")
    )

    # Return raw UDP payload bytes
    return bytes(dns_layer)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
