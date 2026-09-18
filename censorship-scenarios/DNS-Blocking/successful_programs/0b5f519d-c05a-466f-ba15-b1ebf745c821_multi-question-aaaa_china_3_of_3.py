from scapy.all import DNS, DNSQR
import os

# EVOLVE-BLOCK-START
def generate_dns_request(target_domain=None):
    """
    Generate a DNS request payload that:
      - Contains a required A-record question for target_domain.
      - Also adds an AAAA question for the same QNAME in the question section.
    This uses a standard header but a less common dual A+AAAA question layout,
    which may confuse DPI tuned for single-question A-only queries.
    """
    if target_domain is None:
        target_domain = "example.com"

    txid = int.from_bytes(os.urandom(2), "big")

    # Two questions for the same QNAME: first A (required), then AAAA.
    q_a = DNSQR(qname=target_domain, qtype="A", qclass="IN")
    q_aaaa = DNSQR(qname=target_domain, qtype="AAAA", qclass="IN")

    dns_layer = DNS(
        id=txid,
        qr=0,
        opcode=0,
        rd=1,
        qdcount=2,
        ancount=0,
        nscount=0,
        arcount=0,
        qd=q_a / q_aaaa,
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END

