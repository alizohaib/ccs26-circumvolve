# EVOLVE-BLOCK-START

from scapy.all import IP, UDP, DNS, DNSQR
import os

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload that is RFC‑compliant for real resolvers
    but slightly unusual to potentially confuse simplistic DPI.
    Args:
        target_domain (str): The domain name to resolve.
    """
    if target_domain is None:
        raise ValueError("target_domain must be provided")

    # Use a fixed, non‑zero transaction ID so the packet is stable but valid
    txid = 0x4242

    # Craft a query with:
    # - QR=0 (query), RD=1 (recursion desired)
    # - One question (A record, standard)
    # - One *additional* OPT (EDNS0) pseudo‑record
    #
    # Many DPI implementations focus only on the basic header + QNAME and may
    # mishandle or partially parse packets with EDNS0 present.
    dns_layer = DNS(
        id=txid,
        rd=1,
        qdcount=1,
        ancount=0,
        nscount=0,
        arcount=1,  # we will turn this into an OPT RR
        qd=DNSQR(qname=target_domain, qtype="A", qclass="IN"),
        # Placeholder additional section to be post‑patched into a valid OPT RR
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
            arcount=0
        )
    )

    pkt = bytearray(bytes(dns_layer))

    # Post‑patch the trailing bytes into a minimal EDNS0 OPT resource record:
    # NAME  = 0x00 (root)
    # TYPE  = 0x0029 (41, OPT)
    # CLASS = 0x1000 (4096) advertised UDP payload size
    # TTL   = 0x00000000 (extended RCODE + flags)
    # RDLEN = 0x0000 (no options)
    #
    # This preserves full RFC validity while being slightly unusual for DPI
    # that does not fully implement EDNS0 parsing.
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

    return bytes(pkt)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
