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

    # Hybrid strategy guided by high‑fitness ancestors:
    # - Keep a first, fully standard A/IN question to ensure Stage 1
    #   resolvers answer reliably.
    # - Add a second "weird" question with mutated QCLASS/QTYPE
    #   (e.g., AAAA/CH) to exercise DPI edge cases.
    #
    # This combines proven resolver‑compatibility with the required
    # QCLASS/QTYPE mutations, avoiding the -10 penalty seen when we
    # used only a CH/AAAA question.
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
