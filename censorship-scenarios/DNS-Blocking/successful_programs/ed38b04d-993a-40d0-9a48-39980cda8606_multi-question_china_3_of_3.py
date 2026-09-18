from scapy.all import IP, UDP, DNS, DNSQR
import os

# EVOLVE-BLOCK-START
def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload where the real A-record question for
    target_domain is the *second* question. A harmless first question
    shifts the offset of the target QNAME, exploring DPI that assumes
    the censored domain is always in the first Question entry.
    """
    if target_domain is None:
        raise ValueError("target_domain must not be None")

    # Dummy first question (benign domain, still valid A/IN query)
    dummy_qd = DNSQR(qname="example.com", qtype="A", qclass="IN")

    # Real censored target as second question, A/IN as required
    real_qd = DNSQR(qname=target_domain, qtype="A", qclass="IN")

    dns_layer = DNS(
        rd=1,
        qd=dummy_qd / real_qd  # two questions, real one second
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END

