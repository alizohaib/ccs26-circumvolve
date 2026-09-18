# EVOLVE-BLOCK-START

from scapy.all import IP, UDP, DNS, DNSQR
import os

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload that stays RFC‑compliant for real resolvers
    but is slightly unusual to potentially confuse simplistic DPI.
    Args:
        target_domain (str): The domain name to resolve.
    """
    if target_domain is None:
        raise ValueError("target_domain must be provided")

    # Use a fixed, non‑zero transaction ID for reproducibility
    txid = 0x4242

    # Build a slightly more complex but still RFC‑compliant query:
    # - Two questions for the same name (A and AAAA)
    # - One EDNS(0) OPT pseudo‑record in the additional section
    #
    # Multiple questions + EDNS0 increases parser complexity, which can
    # diversify behavior vs. the current best solution while remaining valid.
    dns_layer = DNS(
        id=txid,
        rd=1,
        qdcount=2,
        ancount=0,
        nscount=0,
        arcount=1,  # one additional record (OPT) to be post‑patched
        qd=DNSQR(qname=target_domain, qtype="A", qclass="IN") /
           DNSQR(qname=target_domain, qtype="AAAA", qclass="IN"),
        # placeholder "additional" section; will be turned into OPT below
        ar=DNS(
            id=0,
            qr=0,
            opcode=0,
            aa=0,
            tc=0,
            rd=0,
            ra=0,
            z=0,
            rcode=0,
            qdcount=0,
            ancount=0,
            nscount=0,
            arcount=0,
        ),
    )

    # Convert to bytes and post‑patch the tail into a minimal EDNS0 OPT RR:
    # NAME  = 0x00 (root)
    # TYPE  = 0x0029 (41, OPT)
    # CLASS = 0x1000 (4096) advertised UDP payload size
    # TTL   = 0x00000000 (extended RCODE + flags)
    # RDLEN = 0x0000 (no options)
    pkt = bytearray(bytes(dns_layer))
    if len(pkt) >= 11:
        opt_start = len(pkt) - 11
        opt_rr = bytes.fromhex(
            "00"        # NAME = root
            "0029"      # TYPE = OPT
            "1000"      # CLASS = 4096 bytes UDP payload size
            "00000000"  # TTL / extended RCODE + flags
            "0000"      # RDLEN = 0 (no options)
        )
        pkt[opt_start:opt_start + 11] = opt_rr

    # Return raw UDP payload bytes
    return bytes(pkt)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
