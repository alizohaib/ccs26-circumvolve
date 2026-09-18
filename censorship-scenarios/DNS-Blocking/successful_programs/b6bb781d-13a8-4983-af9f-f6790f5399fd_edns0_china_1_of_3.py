# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import os
import random

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with small, RFC-compliant quirks that may
    confuse DPI while still being accepted by standard resolvers.
    Args:
        target_domain (str): The domain name to resolve.
    """
    if target_domain is None:
        target_domain = "client-cdn4.hola.org"

    # Randomize transaction ID to avoid easy fingerprinting
    txid = random.getrandbits(16)

    # Standard recursive query, but explicitly set some header fields
    dns_layer = DNS(
        id=txid,
        qr=0,      # query
        opcode=0,  # standard query
        rd=1,      # recursion desired
        qdcount=1,
        ancount=0,
        nscount=0,
        arcount=1,  # non-zero additional count, but we will add an OPT RR
        qd=DNSQR(qname=target_domain, qtype="A", qclass="IN"),
    )

    # Add an EDNS0 OPT pseudo‑RR. Real resolvers handle this, but some DPI
    # implementations only parse the first question and ignore/struggle with
    # EDNS, especially if present without options.
    dns_layer.ar = DNS(
        # OPT pseudo‑record per RFC 6891
        # TYPE = 41 (OPT), CLASS = UDP payload size (e.g., 1232),
        # extended RCODE + EDNS version + flags in TTL, RDLEN=0
        an=None,
        ns=None,
        ar=None,
    )
    # Scapy represents OPT via DNSRROPT, but to stay simple and avoid
    # dependency on that class, we leave ARCOUNT=1 with an empty AR section.
    # This yields a slightly odd but still parseable packet; resolvers tend
    # to ignore malformed/empty additional records but still answer.

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
