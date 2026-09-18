# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import os
import random
import struct

def _encode_qname(domain: str) -> bytes:
    """
    Encode QNAME manually to allow subtle mutations while staying RFC-compliant.
    """
    parts = domain.strip(".").split(".")
    out = bytearray()
    for label in parts:
        out.append(len(label))
        out.extend(label.encode("ascii"))
    out.append(0)
    return bytes(out)

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload that is RFC‑compliant but adds
    a subtle ambiguity around the QNAME using compression.

    New strategy (different from EDNS(0) and ghost‑question approaches):
    - Build a normal header and a single question (QDCOUNT=1).
    - Place the true QNAME only once, near the end of the packet.
    - In the Question section, use a compression pointer (0xC0xx) as QNAME
      that points to that later occurrence of the name.
    - Before that true QNAME, insert a short, innocuous owner name that
      looks like another label but is not referenced by any count field.

    Rationale:
    - Real DNS servers use the compression pointer to locate the QNAME and
      will parse the packet correctly.
    - Some DPI implementations assume the QNAME is laid out linearly
      immediately after the header, and may not follow pointers that
      point forward in the packet or that cross over “extra” bytes.
      That can cause them to miss the forbidden domain.
    """
    if target_domain is None:
        target_domain = "example.com"

    # --- Header construction ---
    txid = random.randint(0, 0xFFFF)
    # Standard recursive query
    flags = 0x0100

    qdcount = 1     # one real question
    ancount = 0
    nscount = 0
    arcount = 0     # keep it simple: no additional records

    header = struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)

    # We will build the body as:
    #   [Question with QNAME = compression pointer to true name]
    #   [A small "padding" owner name that DPI might misinterpret]
    #   [True QNAME bytes for target_domain]
    #
    # Question format:
    #   QNAME: 2‑byte compression pointer (0xC0 | offset)
    #   QTYPE: 2 bytes
    #   QCLASS: 2 bytes

    # Placeholder for question; pointer offset will depend on final length,
    # so we construct the trailing section first.

    # --- Padding owner name (benign label) ---
    # This is a short, valid label + root that is never referenced by QDCOUNT.
    # Example: 1-byte label "x" -> 0x01 'x' 0x00
    padding_name = b"\x01x\x00"

    # --- True QNAME for the target domain ---
    true_qname = _encode_qname(target_domain)

    # The "extra section" that follows the question:
    extra_section = padding_name + true_qname

    # Now compute where true_qname starts so we can point to it.
    # Packet layout so far at pointer resolution time:
    #   header (12 bytes)
    #   question:
    #       qname_pointer (2 bytes)
    #       qtype (2 bytes)
    #       qclass (2 bytes)
    #   extra_section (padding_name + true_qname)
    #
    # Offset of the first byte after header:
    base_after_header = len(header)
    # Offset of QNAME field in question relative to packet start:
    qname_field_offset = base_after_header
    # Size of the fixed part of the question:
    question_fixed_len = 2 + 2 + 2

    # Offset (from start of packet) where extra_section begins:
    extra_offset = base_after_header + question_fixed_len
    # Inside extra_section, true_qname starts after padding_name:
    true_qname_offset = extra_offset + len(padding_name)

    # Compression pointer to true_qname_offset
    # 0xC000 | offset encodes a pointer
    pointer_value = 0xC000 | true_qname_offset
    qname_pointer = struct.pack("!H", pointer_value)

    qtype = 1   # A
    qclass = 1  # IN
    question = qname_pointer + struct.pack("!HH", qtype, qclass)

    packet_bytes = header + question + extra_section
    return packet_bytes

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
