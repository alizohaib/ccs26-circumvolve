# EVOLVE-BLOCK-START

from scapy.all import IP, UDP, DNS, DNSQR
import os

def generate_dns_request(target_domain=None):
    """
    Generates a slightly non-standard but still valid DNS request payload.

    Strategy:
    - Use a randomized Transaction ID to avoid simple correlation.
    - Ask multiple questions in one DNS packet:
        * Q1: target_domain (A)
        * Q2: a benign domain (AAAA)
      Many DPI systems only inspect the first question (QD[0]) and ignore
      subsequent QNAMEs for speed, while real resolvers handle multi-question
      packets more robustly.
    - Keep the packet otherwise RFC-compliant to preserve Stage 1 validity.
    """
    if target_domain is None:
        raise ValueError("target_domain must be provided")

    # Random transaction ID to avoid simple pattern matching
    tid = os.urandom(2)
    tid_int = int.from_bytes(tid, "big")

    # First question: the forbidden / target domain (type A)
    q1 = DNSQR(qname=target_domain, qtype="A", qclass="IN")
    # Second question: a benign domain (type AAAA) that DPI is more likely to see
    # and potentially focus on, ignoring the first/others.
    benign_domain = "example.com"
    q2 = DNSQR(qname=benign_domain, qtype="AAAA", qclass="IN")

    dns_layer = DNS(
        id=tid_int,
        rd=1,
        qdcount=2,         # explicitly declare two questions
        qd=q1 / q2         # scapy stacks them as multiple questions
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
