# EVOLVE-BLOCK-START

# NOTE: We intentionally avoid external dependencies like scapy and
# instead hand‑craft a DNS packet so we can precisely control the
# compression pointer chain used to obfuscate the QNAME from DPI.
import os
import struct

def _encode_labels(name: str) -> bytes:
    """
    Encode a domain name into DNS label format (no compression).
    Example: 'example.com' -> b'\\x07example\\x03com\\x00'
    """
    parts = name.strip(".").split(".")
    out = bytearray()
    for p in parts:
        b = p.encode("ascii")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with a deep compression‑pointer chain.
    The Question's QNAME is a pointer into the Answer section, which
    contains a sequence of 10 pointers ultimately resolving to the
    true target_domain. This should remain RFC‑compliant enough for
    major resolvers while stressing DPI recursion limits.
    """
    if target_domain is None:
        target_domain = "client-cdn4.hola.org"

    # --- DNS header ---
    tid = os.urandom(2)
    flags = 0x0100  # standard query, RD=1
    qdcount = 1
    ancount = 1  # we add a synthetic answer section to host the chain
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", int.from_bytes(tid, "big"),
                         flags, qdcount, ancount, nscount, arcount)

    # We will build the packet incrementally to know offsets.
    packet = bytearray(header)

    # Placeholder for Question.QNAME: use a 2‑byte compression pointer,
    # we will fill the offset later once we know where the chain starts.
    qname_pointer_offset = len(packet)
    packet.extend(b"\xc0\x00")  # 0xC0 | high bits, low byte to be patched

    # QTYPE=A, QCLASS=IN
    packet.extend(struct.pack("!HH", 1, 1))

    # Record where the Answer section will begin (this is the target of our pointer)
    answer_start_offset = len(packet)

    # --- Build a chain of compression pointers in the Answer section ---
    # We fabricate an A record whose NAME field is a pointer chain.
    # NAME will be a pointer (c0 xx) to label_1; label_1 will be a pointer
    # to label_2; ...; label_N will finally point to the real domain labels.

    # Use a deeper chain to better hit DPI recursion limits while
    # staying within what resolvers typically tolerate.
    chain_depth = 16  # between 10–20 as requested
    label_offsets = []

    # First, reserve space for NAME (pointer to first link)
    name_pointer_offset = len(packet)
    packet.extend(b"\xc0\x00")  # to be patched to first chain link

    # TYPE=A, CLASS=IN, TTL, RDLENGTH, RDATA (dummy)
    packet.extend(struct.pack("!HHI", 1, 1, 60))
    packet.extend(struct.pack("!H", 4))
    packet.extend(b"\x7f\x00\x00\x01")  # 127.0.0.1 dummy IP

    # After the fixed answer fields, we start placing our chain labels.
    # Each "label" in the chain is actually just a compression pointer.
    for _ in range(chain_depth):
        label_offsets.append(len(packet))
        # placeholder pointer; we'll patch the target later
        packet.extend(b"\xc0\x00")

    # Now append the real target_domain in uncompressed form and record its offset.
    real_name_offset = len(packet)
    packet.extend(_encode_labels(target_domain))

    # --- Patch the chain pointers ---
    # Last chain element points to the real_name_offset
    last_offset = real_name_offset
    for off in reversed(label_offsets):
        # pointer value is offset from start of DNS message
        ptr_val = 0xC000 | last_offset
        packet[off] = (ptr_val >> 8) & 0xFF
        packet[off + 1] = ptr_val & 0xFF
        last_offset = off  # previous element points to this one

    # Patch Answer.NAME to point to first chain element
    first_chain_offset = label_offsets[0]
    ptr_val = 0xC000 | first_chain_offset
    packet[name_pointer_offset] = (ptr_val >> 8) & 0xFF
    packet[name_pointer_offset + 1] = ptr_val & 0xFF

    # Patch Question.QNAME pointer to point to the start of the Answer NAME
    ptr_val = 0xC000 | answer_start_offset
    packet[qname_pointer_offset] = (ptr_val >> 8) & 0xFF
    packet[qname_pointer_offset + 1] = ptr_val & 0xFF

    return bytes(packet)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
