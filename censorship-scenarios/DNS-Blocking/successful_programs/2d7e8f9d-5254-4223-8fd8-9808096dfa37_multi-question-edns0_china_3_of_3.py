# EVOLVE-BLOCK-START

from scapy.all import IP, UDP, DNS, DNSQR
import os

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload that stays RFC‑compliant but uses
    multi‑question layout plus EDNS0, combining behaviors of top
    performers while remaining relatively simple.
    """
    if target_domain is None:
        raise ValueError("target_domain must be provided")

    # Keep a stable, known‑good transaction ID used in high‑scoring programs.
    txid = 0x4242

    # Two questions (A and AAAA) – this is known to be valid from Program 1/2
    # and increases complexity for DPI that assumes a single QNAME.
    dns_layer = DNS(
        id=txid,
        rd=1,
        qdcount=2,
        ancount=0,
        nscount=0,
        arcount=1,  # one additional record (to be turned into OPT)
        qd=DNSQR(qname=target_domain, qtype="A", qclass="IN") /
           DNSQR(qname=target_domain, qtype="AAAA", qclass="IN"),
        # placeholder "additional" section; will be converted into EDNS0 OPT
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

    # Post‑patch tail into a minimal EDNS0 OPT RR, as in previous variants.
    pkt = bytearray(bytes(dns_layer))

    # NAME=0 (root), TYPE=41 (OPT), CLASS=4096, TTL=0, RDLEN=0
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
