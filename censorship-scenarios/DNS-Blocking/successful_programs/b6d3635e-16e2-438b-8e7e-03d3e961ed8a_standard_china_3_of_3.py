# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload.
    Args:
        target_domain (str): The domain name to resolve.
    """
    if not target_domain:
        raise ValueError("target_domain must be provided")

    # Manually construct the DNS layer using a dict, then feed to DNS(**fields)
    dns_header_fields = {
        "id": 0,        # transaction ID (let Scapy randomize later if needed)
        "qr": 0,        # query
        "opcode": 0,    # standard query
        "aa": 0,
        "tc": 0,
        "rd": 1,        # recursion desired
        "ra": 0,
        "z": 0,
        "ad": 0,
        "cd": 0,
        "rcode": 0,
        "qdcount": 1,
        "ancount": 0,
        "nscount": 0,
        "arcount": 0,
    }

    question_fields = {
        "qname": target_domain,
        "qtype": 1,   # A record
        "qclass": 1,  # IN
    }

    dns_layer = DNS(**dns_header_fields) / DNSQR(**question_fields)
    return bytes(dns_layer)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END