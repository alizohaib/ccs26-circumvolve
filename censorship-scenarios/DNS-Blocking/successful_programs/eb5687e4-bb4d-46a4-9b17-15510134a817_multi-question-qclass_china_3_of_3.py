# EVOLVE-BLOCK-START

from scapy.all import IP, UDP, DNS, DNSQR
import os
import random

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload.
    Args:
        target_domain (str): The domain name to resolve.
    """
    # Randomize transaction ID for diversity
    txid = random.randint(0, 0xFFFF)

    # Hybrid strategy:
    # - Keep a first, fully standard A/IN question to satisfy Stage 1
    #   resolvers (mirrors the behavior of prior high-fitness programs).
    # - Add a second "weird" question that mutates QCLASS and QTYPE
    #   (CH/AAAA) to explore DPI parsing edge cases.
    #
    # This restores the Stage 1 robustness that was lost when we sent
    # only a CH/AAAA question (which scored -10), while still using
    # QCLASS/QTYPE mutation as required.
    normal_q = DNSQR(
        qname=target_domain,
        qtype=1,   # A
        qclass=1   # IN
    )

    mutated_q = DNSQR(
        qname=target_domain,
        qtype=28,  # AAAA
        qclass=3   # CH (Chaos)
    )

    dns_layer = DNS(
        id=txid,
        rd=1,
        # Two questions: standard first, mutated second
        qdcount=2,
        qd=normal_q / mutated_q
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
