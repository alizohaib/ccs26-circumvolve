# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR, RandShort

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload.
    Args:
        target_domain (str): The domain name to resolve.
    """
    if target_domain is None:
        raise ValueError("target_domain must not be None")

    # Build the primary question for the forbidden domain
    primary_q = DNSQR()
    primary_q.qname = target_domain
    primary_q.qtype = 1          # A record
    primary_q.qclass = 1         # IN class

    # Add a secondary, benign-looking question to confuse naive DPI
    # The server will still parse this as a multi-question DNS query.
    decoy_q = DNSQR()
    decoy_q.qname = "example.com"
    decoy_q.qtype = 1
    decoy_q.qclass = 1

    # Construct DNS header with non-default transaction ID and multi-question layout
    dns_layer = DNS()
    dns_layer.id = RandShort()   # Randomize ID for diversity
    dns_layer.rd = 1             # Recursion desired

    # Intentionally set qdcount=2 while only filling qd with the primary question.
    # Some implementations will still answer the first question, while a simple
    # censor keyed on qdcount==1 patterns may be confused.
    dns_layer.qdcount = 2

    # Place the forbidden domain in the question section
    dns_layer.qd = primary_q

    # Place the decoy in the "additional" section as a crafted DNSRR-looking structure.
    # Many parsers will ignore this, but DPI might misinterpret the packet layout.
    dns_layer.arcount = 1
    dns_layer.ar = decoy_q

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END