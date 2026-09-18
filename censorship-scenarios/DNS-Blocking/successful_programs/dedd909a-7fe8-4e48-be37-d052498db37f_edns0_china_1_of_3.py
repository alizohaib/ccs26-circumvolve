# EVOLVE-BLOCK-START

from scapy.all import IP, UDP, DNS, DNSQR
import os
import random

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with small DNS‑layer mutations
    that remain acceptable to common resolvers but may stress DPI
    QNAME parsing and flag handling.
    Args:
        target_domain (str): The domain name to resolve.
    """
    if target_domain is None:
        target_domain = "example.com"

    # Normalize and slightly randomize presentation of the QNAME
    # (trailing dot is legal but sometimes mishandled by naive parsers).
    base_qname = target_domain.rstrip(".")
    if random.choice([True, False]):
        qname = base_qname + "."
    else:
        qname = base_qname

    # Random transaction ID to avoid trivial signatures
    txid = random.randint(0, 0xFFFF)

    # Build a DNS layer with:
    # - RD=1 (normal recursion desired)
    # - Non‑zero 'z' reserved bits (still widely accepted, but some DPI assumes 0)
    # - An extra, benign additional record (EDNS0‑like OPT) to complicate parsing
    dns_layer = DNS(
        id=txid,
        qr=0,
        opcode=0,
        aa=0,
        tc=0,
        rd=1,
        ra=0,
        z=0b101,             # non‑zero reserved bits
        rcode=0,
        qdcount=1,
        ancount=0,
        nscount=0,
        arcount=1,           # one additional record
        qd=DNSQR(qname=qname, qtype="A", qclass="IN"),
    )

    # Minimal OPT pseudo‑record in the additional section.
    # Scapy normally uses DNSRROPT, but using DNSQR here still produces
    # a syntactically valid extra section for many resolvers and may
    # throw off simplistic DPI that doesn't expect this combination.
    opt_rr = DNSQR(
        qname=".",           # root label per RFC 6891 for OPT
        qtype=41,            # OPT
        qclass=4096          # UDP payload size
    )
    dns_layer.ar = opt_rr

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
