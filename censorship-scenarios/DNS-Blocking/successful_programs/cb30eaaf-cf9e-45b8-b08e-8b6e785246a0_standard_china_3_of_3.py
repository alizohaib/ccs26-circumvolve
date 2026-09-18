from scapy.all import DNS, DNSQR, DNSRR
import os

# EVOLVE-BLOCK-START
def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload where the censored QNAME only appears in
    the answer section, while the header claim (ancount=0) and a benign
    question name may confuse DPI that only inspects the question.
    The resolver may still parse the extra bytes and use the embedded A RR.
    """
    if target_domain is None:
        target_domain = "example.com"

    txid = int.from_bytes(os.urandom(2), "big")

    # Benign/decoy name in the visible question; keep it simple and popular.
    decoy_name = "www.example.com"

    # Embed the real target domain in an A answer RR pointing to a dummy IP.
    answer_rr = DNSRR(rrname=target_domain, type="A", rclass="IN", ttl=1,
                      rdata="0.0.0.0")

    dns_layer = DNS(
        id=txid,
        qr=0,          # query
        opcode=0,
        aa=0,
        tc=0,
        rd=1,
        ra=0,
        z=0,
        ad=0,
        cd=0,
        # Header counts claim: 1 question, 0 answers
        qdcount=1,
        ancount=0,
        nscount=0,
        arcount=0,
        # Question uses the decoy name; answer carries the true QNAME
        qd=DNSQR(qname=decoy_name, qtype="A", qclass="IN"),
        an=answer_rr
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END

