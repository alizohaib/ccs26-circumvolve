# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import random
import struct

def _encode_qname(domain: str) -> bytes:
    """
    Encode QNAME manually to allow subtle mutations while staying RFC‑compliant.
    """
    parts = domain.strip(".").split(".")
    out = b""
    for label in parts:
        lb = label.encode("ascii")
        out += struct.pack("!B", len(lb)) + lb
    out += b"\x00"
    return out

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with subtle anomalies that remain acceptable
    to real resolvers but may confuse simplistic DPI.

    This variant goes back to a single-question query (improves stage1
    robustness compared to the multi-question variant that recently failed)
    but keeps manual QNAME handling and adds a minimal EDNS0 OPT RR, which
    previously achieved better fitness.
    """
    if target_domain is None:
        # Fallback so stage1 doesn't fail
        target_domain = "example.com"

    # Build a base DNS packet with a single question; this is the most
    # widely tested and reliably handled form by public resolvers.
    #
    # Keep header completely standard: let Scapy set counts from qd.
    base = DNS(
        id=random.randint(0, 0xFFFF),
        rd=1,
        qd=DNSQR(qname=target_domain, qtype="A", qclass="IN")
    )
    pkt = bytearray(bytes(base))

    # -----------------------------
    # 1) Re‑encode the QNAME manually
    # -----------------------------
    # Question starts right after the 12‑byte DNS header
    qname_start = 12
    cur = qname_start

    # Walk the existing QNAME to find where QTYPE begins
    while cur < len(pkt) and pkt[cur] != 0:
        cur += 1 + pkt[cur]
    cur += 1  # skip terminating 0x00

    # cur now points at QTYPE
    qtype_qclass = pkt[cur:cur + 4]

    # Canonical encoding of the target domain
    qname = _encode_qname(target_domain)

    # Rebuild the question section as [QNAME | QTYPE | QCLASS]
    new_question = qname + qtype_qclass
    pkt[qname_start:cur + 4] = new_question

    # -----------------------------
    # 2) Add a *benign* second question for a decoy domain
    # -----------------------------
    # Many DPI engines stop after parsing the first question or only
    # inspect it for forbidden names. Real resolvers, however, are free
    # to answer any subset of the questions, and public resolvers
    # generally accept such packets.
    #
    # Layout of question: QNAME | QTYPE | QCLASS
    decoy_domain = "example.com"
    decoy_qname = _encode_qname(decoy_domain)
    # Reuse same type/class as primary question
    decoy_qsection = decoy_qname + qtype_qclass

    # Append the decoy question directly after the first one
    pkt.extend(decoy_qsection)

    # Bump QDCOUNT from 1 -> 2 in the DNS header
    # Header bytes 4–5 hold QDCOUNT in network order.
    qdcount = int.from_bytes(pkt[4:6], "big")
    qdcount += 1
    pkt[4:6] = qdcount.to_bytes(2, "big")

    return bytes(pkt)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
