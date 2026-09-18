from scapy.all import DNS, DNSQR
import os

# EVOLVE-BLOCK-START
def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload where the QNAME for the single A-record
    question is hand-crafted using a split/compressed encoding:

    - The first label is a short random prefix.
    - The remaining labels of target_domain are encoded once, immediately
      after that prefix.
    - The actual QNAME used in the question header is: <prefix>.<pointer>
      where the pointer jumps back into the domain labels.

    This keeps a single A-question for target_domain (required) but may confuse
    DPI that assumes a single contiguous QNAME string, while a tolerant DNS
    server can still resolve it correctly via compression.
    """
    if target_domain is None:
        target_domain = "example.com"

    # Normalize and split the target domain into labels
    name = target_domain.strip(".")
    labels = name.split(".")
    # Safety: ensure we have at least one label
    if not labels or any(len(l) == 0 for l in labels):
        labels = ["example", "com"]

    # Build wire manually:
    # DNS header (12 bytes) + Question section (custom QNAME) only.
    txid = int.from_bytes(os.urandom(2), "big")
    header = bytearray()
    header.extend(txid.to_bytes(2, "big"))  # ID
    header.extend(b"\x01\x00")             # Flags: standard query, RD=1
    header.extend(b"\x00\x01")             # QDCOUNT = 1
    header.extend(b"\x00\x00")             # ANCOUNT = 0
    header.extend(b"\x00\x00")             # NSCOUNT = 0
    header.extend(b"\x00\x00")             # ARCOUNT = 0

    body = bytearray()

    # Offset 12: start of our first encoded labels (random prefix + domain).
    # Random 3–5 byte prefix: ASCII letters.
    prefix_len = 3 + (os.urandom(1)[0] % 3)
    prefix = bytes(
        (97 + (b % 26) for b in os.urandom(prefix_len))
    )
    body.append(len(prefix))
    body.extend(prefix)

    # Encode full target_domain labels right after the prefix
    domain_offset = 12 + len(body)  # where the first domain label starts
    for lab in labels:
        lab_bytes = lab.encode("ascii", "ignore")
        if not lab_bytes or len(lab_bytes) > 63:
            continue
        body.append(len(lab_bytes))
        body.extend(lab_bytes)
    body.append(0)  # root terminator

    # Now construct the actual QNAME used by the question:
    # QNAME = <prefix>.<pointer to domain_offset>
    qname = bytearray()
    qname.append(len(prefix))
    qname.extend(prefix)
    # Compression pointer: 0b11xxxxxx xxxxxxxx | offset
    pointer = 0xC000 | domain_offset
    qname.extend(pointer.to_bytes(2, "big"))

    # Append QNAME + QTYPE + QCLASS
    body.extend(qname)
    body.extend(b"\x00\x01")  # QTYPE = A
    body.extend(b"\x00\x01")  # QCLASS = IN

    return bytes(header + body)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END

