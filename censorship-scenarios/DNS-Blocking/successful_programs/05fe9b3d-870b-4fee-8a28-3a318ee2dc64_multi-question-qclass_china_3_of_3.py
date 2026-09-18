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

    # Question 1: mutated query with non-IN class and different type.
    # Keep the same QNAME but vary QTYPE/QCLASS to explore different
    # DPI parsing paths while remaining acceptable to real resolvers.
    mutated_q1 = DNSQR(
        qname=target_domain,
        qtype=28,  # AAAA
        qclass=3   # CH (Chaos)
    )

    # Question 2: another mutated query using ANY + HS.
    # Some resolvers will still respond, but many DPI engines only
    # implement logic for IN-class A/AAAA and may ignore this.
    mutated_q2 = DNSQR(
        qname=target_domain,
        qtype=255,  # ANY
        qclass=4    # HS (Hesiod)
    )

    # Build DNS layer with three questions:
    #   QD[0] = standard A/IN (for Stage 1 robustness)
    #   QD[1] = AAAA/CH
    #   QD[2] = ANY/HS
    dns_layer = DNS(
        id=txid,
        rd=1,
        qdcount=3,
        qd=normal_q / mutated_q1 / mutated_q2
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
