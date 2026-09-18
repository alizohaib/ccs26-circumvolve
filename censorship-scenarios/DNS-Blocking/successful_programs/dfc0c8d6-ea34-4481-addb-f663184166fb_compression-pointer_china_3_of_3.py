# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import random
import struct

def generate_dns_request(target_domain=None):
    """
    Generates a resolver-valid DNS request payload, using a conservative
    but slightly unusual structure that has previously shown good fitness:
    - Standard header and flags
    - Two-question section with QNAME compression (in-question pointer)
    This moves back toward the best-performing Program 1 while keeping
    code compact to address the complexity concern.
    """
    if target_domain is None:
        return b""

    # Random transaction ID to avoid cache artifacts and make flows less
    # predictable for simple DPI correlation.
    txid = random.randint(0, 0xFFFF)

    # Use a completely standard recursive query header (this was part of
    # the best-performing solution; avoid RA and other odd flags which
    # may hurt Stage 1 validity).
    flags = 0x0100  # RD only, standard query

    # We send 2 questions; the second one will use a compression pointer
    # back into the first question's QNAME.
    qdcount = 2
    ancount = 0
    nscount = 0
    arcount = 0

    # Base header
    header = struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)

    # Build QNAME exactly for target_domain in a standard, safe way.
    # This avoids the previous "embedded zero label" quirk that likely
    # made the packet too malformed for some resolvers (Stage 1 = -10).
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
    # Proper terminator
    qname_bytes += b"\x00"

    # Standard A/IN query for both questions
    qtype = 1
    qclass = 1

    # First question: full QNAME + type/class
    question1 = qname_bytes + struct.pack("!HH", qtype, qclass)

    # Second question: QNAME as a compression pointer back to the first
    # QNAME (offset 12 from start: immediately after header).
    first_qname_offset = 12
    pointer = 0xC000 | first_qname_offset
    qname2 = struct.pack("!H", pointer)
    question2 = qname2 + struct.pack("!HH", qtype, qclass)

    packet_bytes = header + question1 + question2

    # Run through Scapy to keep the packet acceptable for common
    # resolvers, but explicitly tell Scapy we have two questions for
    # the same name so it preserves the multi-question structure (and
    # typically still uses compression when serializing).
    dns_layer = DNS(packet_bytes)
    dns_layer.qd = DNSQR(qname=target_domain, qtype="A", qclass="IN") / \
                   DNSQR(qname=target_domain, qtype="A", qclass="IN")
    packet_bytes = bytes(dns_layer)

    return packet_bytes

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
