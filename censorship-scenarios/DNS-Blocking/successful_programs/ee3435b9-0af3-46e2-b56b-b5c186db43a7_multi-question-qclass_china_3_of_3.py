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
    # Randomize transaction ID and add a second, mutated question
    # to combine strong Stage 1 validity with a QCLASS/QTYPE
    # variant that may confuse DPI.
    txid = random.randint(0, 0xFFFF)

    # Question 0: standard A/IN query (maximizes resolver success)
    normal_q = DNSQR(
        qname=target_domain,
        qtype=1,   # A
        qclass=1   # IN
    )

    # Question 1: mutated query with non-IN class and different type
    mutated_q = DNSQR(
        qname=target_domain,
        qtype=28,  # AAAA
        qclass=3   # CH (Chaos)
    )

    dns_layer = DNS(
        id=txid,
        rd=1,
        qdcount=2,
        qd=normal_q / mutated_q
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
