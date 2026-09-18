from scapy.all import DNS, DNSQR
import os

# EVOLVE-BLOCK-START
def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with two questions for the
    same QNAME but different QCLASS values to alter DPI patterns
    while still including a standard A/IN query.
    """
    if target_domain is None:
        target_domain = "maps.google.sm"

    # Random transaction ID for some variability
    tid = int.from_bytes(os.urandom(2), "big")

    # First question: normal A / IN (required)
    q1 = DNSQR(qname=target_domain, qtype="A", qclass="IN")
    # Second question: same name, A / CH (Chaosnet) – uncommon but valid
    q2 = DNSQR(qname=target_domain, qtype="A", qclass="CH")

    dns_layer = DNS(
        id=tid,
        qr=0,
        opcode=0,
        rd=1,
        qdcount=2,
        qd=q1 / q2,
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END

