# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import random

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with small, RFC‑compliant quirks that may
    confuse DPI while still being accepted by standard resolvers.
    Args:
        target_domain (str): The domain name to resolve.
    """
    if target_domain is None:
        # Match evaluation environment default
        target_domain = "client-cdn4.hola.org"

    # Randomize transaction ID for realism and to avoid easy fingerprinting
    txid = random.getrandbits(16)

    # Build DNS layer explicitly so we can tweak header counters
    dns_layer = DNS(
        id=txid,
        qr=0,          # query
        opcode=0,      # standard query
        rd=1,          # recursion desired
        qdcount=1,     # one question
        ancount=0,
        nscount=0,
        arcount=1,     # claim one additional record (slightly unusual)
        qd=DNSQR(qname=target_domain, qtype="A", qclass="IN"),
    )

    # Attach an empty additional record structure. Scapy will serialize this
    # as an odd but still tolerated AR section. Some DPI engines mishandle
    # additional/EDNS sections or only parse the first section.
    dns_layer.ar = DNS(an=None, ns=None, ar=None)

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
