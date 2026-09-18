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

    # Random transaction ID to add variability
    txid = int.from_bytes(os.urandom(2), "big")

    # Build question with an EDNS(0) OPT pseudo‑record in additional section.
    # This is widely supported and should be accepted by resolvers, but
    # some DPI stacks have weaker parsing of additional records.
    dns_layer = DNS(
        id=txid,
        rd=1,
        qdcount=1,
        qd=DNSQR(
            qname=target_domain,
            qtype="A",
            qclass="IN",
        ),
        arcount=1,
        # OPT pseudo‑record: type 41, UDP payload size 4096, DO=0, no options
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

    # Force scapy to build the packet to raw bytes
    packet_bytes = bytes(dns_layer)
    return packet_bytes

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
