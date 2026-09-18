# EVOLVE-BLOCK-START

from scapy.all import IP, UDP, DNS, DNSQR
import os

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload crafted to remain valid for real DNS
    servers but slightly unusual to potentially confuse simple DPI.
    Args:
        target_domain (str): The domain name to resolve.
    """
    if target_domain is None:
        target_domain = ""

    # Random transaction ID to add variability between queries
    txid = int.from_bytes(os.urandom(2), "big")

    # Build a slightly non‑default but still standards‑compliant query:
    # - Explicitly set qtype and qclass
    # - Add an empty EDNS(0) OPT record in the additional section using the
    #   minimal fields Scapy understands, which is widely accepted by resolvers
    #   but can stress DPI parsers that only focus on the question section.
    dns_layer = DNS(
        id=txid,
        rd=1,
        qdcount=1,
        qd=DNSQR(
            qname=target_domain,
            qtype="A",
            qclass="IN",
        ),
        # Lightweight EDNS-like additional record: an empty root-name record
        # in the additional section. This keeps the packet valid but adds
        # structural complexity (non-empty ARCOUNT) for DPI.
        arcount=1,
        ar=DNS(
            qd=None,
            an=None,
            ns=None,
            ar=None,
            qr=0,
            opcode=0,
            aa=0,
            tc=0,
            rd=1,
            ra=0,
            z=0,
            rcode=0
        )
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
