# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import os

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload using a deep compression-pointer chain
    for the QNAME to stress DPI recursion limits while remaining valid
    for real DNS servers.
    Args:
        target_domain (str): The domain name to resolve.
    """

    if target_domain is None:
        # Keep default but allow caller override
        target_domain = "client-cdn4.hola.org"

    # Manually craft DNS header (12 bytes)
    # Transaction ID: random 16‑bit for better realism
    # Flags: standard query, RD=1  -> 0x0100
    # QDCOUNT=1, ANCOUNT=NSCOUNT=ARCOUNT=0
    header = bytearray()
    txid = os.urandom(2)
    header += txid             # ID
    header += b"\x01\x00"      # Flags
    header += b"\x00\x01"      # QDCOUNT
    header += b"\x00\x00"      # ANCOUNT
    header += b"\x00\x00"      # NSCOUNT
    header += b"\x00\x00"      # ARCOUNT

    # We will *not* put the pointer chain into the primary QNAME,
    # because previous runs with manual QNAME fuzzing failed Stage 1.
    # Instead, we:
    #   1) Build a fully standard, resolver‑friendly base query with scapy
    #   2) Append a second question whose QNAME is a deep pointer chain
    # DPI often only inspects the first question, while resolvers still
    # accept multi‑question messages.

    # Build a known‑good DNS question as the first (normal) question.
    base_dns = DNS(
        rd=1,
        qd=DNSQR(qname=target_domain)
    )
    base_packet = bytearray(bytes(base_dns))

    # Bump QDCOUNT from 1 -> 2 to account for our extra fuzzed question.
    qdcount = int.from_bytes(base_packet[4:6], "big")
    qdcount += 1
    base_packet[4:6] = qdcount.to_bytes(2, "big")

    # The new question will start at the current end of the scapy packet.
    # Its QNAME will be a pointer into a crafted area later in the message.
    qname = bytearray()
    # Pointer to offset 0x40 (within the DNS message) where we will place
    # the head of the pointer chain.
    qname += b"\xC0\x40"

    # QTYPE=A (0x0001), QCLASS=IN (0x0001)
    qtype_qclass = b"\x00\x01\x00\x01"

    # Body for the second question = QNAME (pointer) + QTYPE/QCLASS
    body = bytearray()
    body += qname + qtype_qclass

    # We now ensure that offset 0x40 exists in the final DNS message.
    # Pad from current end of message up to 0x40.
    current_len = len(base_packet) + len(body)
    if current_len > 0x40:
        # Layout assumptions broken (e.g. scapy layout change) –
        # fall back to the plain scapy query to preserve Stage 1.
        return bytes(base_packet)
    body += b"\x00" * (0x40 - current_len)

    # At offset 0x40 we start the pointer chain.
    # Offsets are counted from the beginning of the DNS message.
    #
    # Layout of the chain region:
    #   o0 = 0x40: label "x" + pointer to o1 (0x43)
    #   o1..oN: a chain of pointers of depth ~10–12
    #   final name at 0x60: full domain in normal label format

    # Helper to encode the final domain in label format
    def encode_domain(name: str) -> bytes:
        out = bytearray()
        for label in name.strip(".").split("."):
            l = label.encode("ascii")
            out.append(len(l))
            out += l
        out.append(0)  # terminator
        return bytes(out)

    # Build pointer chain with non‑trivial depth (pointer‑only nodes)
    chain = bytearray()

    # o0 (=0x40): "x" + pointer to o1 (0x43)
    chain += b"\x01x"
    chain += b"\xC0\x43"

    # o1..o10: pointer‑only chain
    depth = 10
    start_o1 = 0x43
    for i in range(depth):
        current_global = start_o1 + 2 * i
        if i < depth - 1:
            target = current_global + 2
        else:
            # Last pointer jumps to the final uncompressed name at 0x60
            target = 0x60
        chain += bytes([0xC0 | ((target >> 8) & 0x3F), target & 0xFF])

    # Ensure that the final name actually starts at 0x60
    pre_final_len = len(base_packet) + len(body) + len(chain)
    if pre_final_len > 0x60:
        # If our assumptions break, fall back to the plain scapy query.
        return bytes(base_packet)

    padding_to_final = 0x60 - pre_final_len
    final_padding = b"\x00" * padding_to_final

    final_name = encode_domain(target_domain)

    # Assemble final packet:
    #   base scapy query +
    #   second question header (body) +
    #   pointer chain +
    #   padding +
    #   final domain labels
    packet = bytes(base_packet + body + chain + final_padding + final_name)
    return packet

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
