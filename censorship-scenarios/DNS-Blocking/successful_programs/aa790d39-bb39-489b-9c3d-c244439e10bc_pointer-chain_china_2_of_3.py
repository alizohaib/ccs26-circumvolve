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
    # Keep it a completely normal‑looking recursive query
    flags = 0x0100  # standard query, RD=1
    qdcount = 1
    ancount = 0  # make it look like a pure query (no answers)
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

    # Record where we will host the synthetic pointer chain (right after question)
    chain_host_offset = len(packet)

    # --- Build a chain of compression pointers in a "hidden" area ---
    # We do NOT declare any answers in the header; the chain lives after
    # the question and is only reachable via compression pointers. Many
    # DPIs stop parsing when ANCOUNT=0 but real resolvers still follow
    # pointers wherever they appear.

    chain_depth = 12  # still in the 10–20 range, but slightly deeper
    label_offsets = []

    # Place the chain pointers directly; no RR TYPE/CLASS/TLL/RDLENGTH here.
    for _ in range(chain_depth):
        label_offsets.append(len(packet))
        packet.extend(b"\xc0\x00")  # placeholder link

    # Now append the real target_domain in uncompressed form and record its offset.
    real_name_offset = len(packet)
    packet.extend(_encode_labels(target_domain))

    # --- Patch the chain pointers ---
    # Last chain element points to the real_name_offset
    last_offset = real_name_offset
    for off in reversed(label_offsets):
        ptr_val = 0xC000 | last_offset
        packet[off] = (ptr_val >> 8) & 0xFF
        packet[off + 1] = ptr_val & 0xFF
        last_offset = off  # previous element points to this one

    # Patch Question.QNAME pointer to point to the first element of the chain.
    # This keeps QDCOUNT=1 and structure valid, but requires multiple levels
    # of pointer dereference to find the real name.
    first_chain_offset = label_offsets[0]
    ptr_val = 0xC000 | first_chain_offset
    packet[qname_pointer_offset] = (ptr_val >> 8) & 0xFF
    packet[qname_pointer_offset + 1] = ptr_val & 0xFF

    return bytes(packet)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
