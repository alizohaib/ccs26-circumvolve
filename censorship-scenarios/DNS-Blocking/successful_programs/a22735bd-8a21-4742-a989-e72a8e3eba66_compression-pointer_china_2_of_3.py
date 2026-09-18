from scapy.all import DNS, DNSQR
import os

# EVOLVE-BLOCK-START
def _compress_qname(domain: str) -> bytes:
    """
    Build a minimally valid DNS message where the QNAME uses a compression
    pointer instead of an explicit label sequence. This keeps the semantic
    QNAME (target_domain) but alters the raw on-wire layout drastically.
    """
    # Build a normal DNS query first to get a valid label sequence
    base = DNS(id=int.from_bytes(os.urandom(2), "big") or 1,
               rd=1,
               qd=DNSQR(qname=domain, qtype="A", qclass="IN"))
    raw = bytearray(bytes(base))

    # DNS header is 12 bytes; QNAME starts at offset 12. We will:
    # - Keep header as-is
    # - Replace the QNAME at offset 12 with a pointer to the original QNAME
    #   stored later in the packet body.
    header_len = 12

    # Find end of original QNAME (terminated by 0x00)
    i = header_len
    while i < len(raw) and raw[i] != 0:
        i += 1
    if i >= len(raw):
        return bytes(raw)

    qname_end = i + 1  # include the zero-length label

    # Preserve the original QNAME bytes after the current message,
    # and make the on-wire QNAME a 2-byte pointer to that copy.
    original_qname = raw[header_len:qname_end]

    # New message: header + pointer QNAME + rest of question
    # Compression pointer: 0xC0 | offset_high, offset_low
    # We place the original_qname immediately after the question,
    # and point to that location.
    # Current question section (QNAME + QTYPE + QCLASS):
    question_tail = raw[qname_end:qname_end + 4]
    base_msg = raw[:header_len] + b"\xc0\x20" + question_tail  # pointer to offset 0x20 (32)

    # Adjust: ensure the pointed-to offset 32 actually holds the original_qname.
    # Pad if needed.
    if len(base_msg) < 32:
        base_msg += b"\x00" * (32 - len(base_msg))
    compressed = base_msg + original_qname

    return bytes(compressed)


def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with a compressed-pointer QNAME.
    Keeps a single A-record question but encodes the QNAME via a label
    pointer to confuse naive DPI that parses only explicit labels.
    """
    if target_domain is None:
        raise ValueError("target_domain must not be None")

    return _compress_qname(target_domain)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END

