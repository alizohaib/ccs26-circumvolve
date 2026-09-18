# EVOLVE-BLOCK-START

from scapy.all import IP, UDP, DNS, DNSQR
import os

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with a minimally mutated but wire-valid query.
    We keep the message simple (no EDNS0 / OPT records) to improve validity,
    and explore DPI behavior by using a non-standard OpCode (IQUERY = 1)
    while still asking about the real target domain in the question section.
    """
    base_qname = target_domain if target_domain is not None else "client-cdn4.hola.org"

    dns_question = DNSQR(
        qname=base_qname,
        qtype="A",
        qclass="IN"  # standard IN class to keep resolvers happy
    )
 
    dns_layer = DNS(
        id=int.from_bytes(os.urandom(2), "big"),
        qr=0,          # query
        opcode=1,      # IQUERY (non-standard for typical use, but valid)
        aa=0,
        tc=0,
        rd=1,          # recursion desired
        ra=0,          # RA is meaningful in responses; keep 0 in query
        z=0,
        rcode=0,
        qd=dns_question
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
