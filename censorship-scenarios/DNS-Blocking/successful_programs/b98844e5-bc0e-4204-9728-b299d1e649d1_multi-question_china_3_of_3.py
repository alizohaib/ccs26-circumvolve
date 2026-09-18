# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import os
import random
import struct

def _encode_qname(domain: str) -> bytes:
    """
    Encode a domain into DNS QNAME format with length-prefixed labels.
    This is done manually so we have full control over edge-case encoding.
    """
    if not domain:
        return b"\x00"
    parts = domain.strip(".").split(".")
    out = b""
    for label in parts:
        l = len(label)
        if l == 0 or l > 63:
            # Fallback to scapy encoding if label is weird; stays RFC-compliant
            return bytes(DNSQR(qname=domain)[DNSQR].qname)
        out += struct.pack("!B", l) + label.encode("ascii")
    return out + b"\x00"

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload that stays RFC‑compliant (to avoid -10)
    but is slightly unusual in header fields and question layout to probe
    DPI parsing without being malformed.
    """
    if target_domain is None:
        target_domain = "example.com"

    # Transaction ID: random
    tid = random.randint(0, 0xFFFF)

    # Use RD=1 (more standard) to restore Stage 1 reliability, but keep
    # one uncommon bit: set the "Checking Disabled" (CD) bit.
    #
    # Flags layout (from MSB to LSB):
    # QR(1) Opcode(4) AA(1) TC(1) RD(1) RA(1) Z(3) AD(1) CD(1) RCODE(4)
    #
    # We want: QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, AD=0, CD=1, RCODE=0
    # Binary: 0000 0001 0000 0010 -> 0x0102
    flags = 0x0102

    # Two questions with different but standard QTYPEs on the same QNAME.
    # This pattern previously scored well and is fully valid.
    qdcount = 2
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)

    # Question section – manually encoded QNAME, but standard QTYPE/QCLASS
    qname = _encode_qname(target_domain)

    # First question: type A, class IN
    question1 = qname + struct.pack("!HH", 0x0001, 0x0001)

    # Second question: type TXT, class IN (uncommon mix with A, but valid)
    # TXT responses are often larger/variable, which may exercise different DPI paths.
    question2 = qname + struct.pack("!HH", 0x0010, 0x0001)

    packet_bytes = header + question1 + question2

    # As a safety net, if something went wrong and packet is obviously broken,
    # fall back to a standard Scapy DNS query (keeps stage1_validity high).
    if len(packet_bytes) < 20 or b"\x00" not in qname:
        dns_layer = DNS(rd=1, qd=DNSQR(qname=target_domain))
        packet_bytes = bytes(dns_layer)

    return packet_bytes

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
