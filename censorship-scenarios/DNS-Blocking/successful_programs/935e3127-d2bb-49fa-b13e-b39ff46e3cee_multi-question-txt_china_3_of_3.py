from scapy.all import DNS, DNSQR
import random

# EVOLVE-BLOCK-START
def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with two questions for the same QNAME:
    one A-record (required) and one TXT-record, plus perturbed header flags
    to change packet layout while remaining a valid query.
    """
    if target_domain is None:
        target_domain = "maps.google.sm"

    # Randomize transaction ID to vary bytes
    txid = random.randint(0, 0xFFFF)

    # Primary required A record question
    q_a = DNSQR(qname=target_domain, qtype="A", qclass="IN")

    # Secondary TXT question for same QNAME to change structure
    q_txt = DNSQR(qname=target_domain, qtype="TXT", qclass="IN")

    # Chain questions: scapy stores them via / operator
    questions = q_a / q_txt

    # Use slightly unusual but still query-valid header flags/opcode
    dns_layer = DNS(
        id=txid,
        qr=0,          # query
        opcode=0,      # standard query
        aa=0,
        tc=0,
        rd=1,
        ra=0,
        z=0,
        ad=0,
        cd=1,          # checking disabled
        rcode=0,
        qdcount=2,     # two questions in the section
        qd=questions
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())
# EVOLVE-BLOCK-END

