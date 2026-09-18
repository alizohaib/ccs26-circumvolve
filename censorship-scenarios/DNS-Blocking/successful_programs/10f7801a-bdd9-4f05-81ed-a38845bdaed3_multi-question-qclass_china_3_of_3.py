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

    # Strategy per instructions:
    # - Keep at least one fully standard, highly-compatible question
    #   so Stage 1 resolvers are very likely to answer.
    # - Add a *second* question in the same packet that uses a
    #   non-IN QCLASS and non-A QTYPE to probe DPI parsing behavior.
    #
    # Many DPI systems only inspect the first question (QD[0]) or
    # only care about QCLASS=IN and QTYPE=A. By putting the
    # “normal” query first and the “weird” one second, we maintain
    # resolver compatibility while exploring an evasion angle.
    #
    # Question 0: standard A/IN query (high Stage 1 validity)
    # Question 1: mutated AAAA/CH query (for evasion signal)
    normal_q = DNSQR(
        qname=target_domain,
        qtype=1,   # A record
        qclass=1   # IN
    )

    mutated_q = DNSQR(
        qname=target_domain,
        qtype=28,  # AAAA instead of A
        qclass=3   # CH (Chaos) instead of IN
    )

    dns_layer = DNS(
        id=txid,
        rd=1,
        # Two questions in one DNS packet
        qdcount=2,
        qd=normal_q / mutated_q
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
