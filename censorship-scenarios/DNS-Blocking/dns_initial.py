# EVOLVE-BLOCK-START

from scapy.all import IP, UDP, DNS, DNSQR
import os

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload.
    Args:
        target_domain (str): The domain name to resolve.
    """
    
    dns_layer = DNS(
        rd=1, 
        qd=DNSQR(qname=target_domain)
    )
    
    return bytes(dns_layer)

if __name__ == "__main__":
    target = "blocked.com"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
