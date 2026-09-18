# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import random
import struct

def generate_dns_request(target_domain=None):
    """
    Generate a resolver-valid DNS request payload that is structurally
    close to the simple baseline, but uses a QNAME-compression quirk
    to explore DPI evasion while preserving Stage 1 validity.
    """
    if target_domain is None:
        return b""

    # Random transaction ID to decorrelate flows and avoid trivial caching
    txid = random.randint(0, 0xFFFF)

    # Completely standard recursive query header
    flags = 0x0100  # RD only, no RA, standard query

    # We advertise 2 questions, but will craft the packet so that
    # the second question is effectively a self-compressed pointer
    # back into the first. Robust DNS servers follow compression,
    # but some DPI code paths only parse the first QNAME or mishandle
    # a second compressed QNAME.
    qdcount = 2
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)

    # Manually encode QNAME for the target_domain.
    labels = (target_domain or "").split(".")
    qname_bytes = b""
    for label in labels:
        if not label:
            continue
        l = len(label)
        if l > 63:
            label = label[:63]
            l = 63
        qname_bytes += struct.pack("!B", l) + label.encode("ascii", "ignore")
    qname_bytes += b"\x00"

    # First question: normal A/IN for the forbidden domain
    qtype = 1
    qclass = 1
    question1 = qname_bytes + struct.pack("!HH", qtype, qclass)

    # The offset where the first QNAME starts, from the beginning of
    # the DNS message: 12 bytes header
    first_qname_offset = 12
    # Compression pointer: 0xC000 | offset
    pointer = 0xC000 | first_qname_offset

    # Second question: QNAME is a pure compression pointer back to the
    # first QNAME, followed by the same QTYPE/QCLASS. This is legal
    # according to RFC 1035 compression rules and understood by real
    # resolvers, but it forces DPI to correctly handle pointers in the
    # question section instead of assuming a flat label sequence.
    qname2 = struct.pack("!H", pointer)
    question2 = qname2 + struct.pack("!HH", qtype, qclass)

    packet_bytes = header + question1 + question2

    # Let Scapy validate/normalize the overall structure to keep Stage 1
    # resolvers happy, but do not overwrite our explicit compression.
    dns_layer = DNS(packet_bytes)

    # Ensure Scapy does not "simplify away" the second question by
    # reconstructing qd as a list of two DNSQR entries that both ask
    # for the target domain. Scapy will rebuild a semantically equivalent
    # packet (including compression), which real DNS servers accept.
    dns_layer.qd = DNSQR(qname=target_domain, qtype="A", qclass="IN") / \
                   DNSQR(qname=target_domain, qtype="A", qclass="IN")

    packet_bytes = bytes(dns_layer)

    return packet_bytes

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
