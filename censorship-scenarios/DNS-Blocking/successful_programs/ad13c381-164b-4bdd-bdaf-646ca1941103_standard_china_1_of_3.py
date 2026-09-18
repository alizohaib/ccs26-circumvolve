from scapy.all import DNS, DNSQR

# EVOLVE-BLOCK-START
def generate_dns_request(target_domain=None):
    """
    Generates a DNS A-record request payload with non-default flags and IDs.
    Args:
        target_domain (str): The domain name to resolve.
    """
    # Randomize transaction ID to diversify packets
    import random
    txid = random.randint(0, 0xFFFF)

    # Craft a slightly unusual but valid DNS header:
    # - recursion desired (rd=1)
    # - non-zero z field (implementation-specific, some resolvers ignore it)
    # - opcode left at default (0 = standard query)
    dns_layer = DNS(
        id=txid,
        rd=1,
        z=1,
        qdcount=1,
        qd=DNSQR(qname=target_domain, qtype="A", qclass="IN")
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END

