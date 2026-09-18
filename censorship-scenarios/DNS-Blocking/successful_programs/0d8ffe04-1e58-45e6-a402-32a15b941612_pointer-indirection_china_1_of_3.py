# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import os
import random
import struct

def _random_transaction_id():
    """Generate a random 16-bit transaction ID."""
    return random.randint(0, 0xFFFF)

def _build_dns_header(qdcount=1, rd=1):
    """
    Build a DNS header using random transaction ID and configurable flags.
    """
    # Transaction ID
    tid = _random_transaction_id()

    # Flags:
    # QR (1 bit)    = 0 (query)
    # OPCODE (4)    = 0 (standard)
    # AA (1)        = 0
    # TC (1)        = 0
    # RD (1)        = rd (recursion desired)
    # RA/Z/RCODE    = 0
    flags = (rd & 0x1) << 8  # RD is bit 8 of flags

    # Header counts
    ancount = 0
    nscount = 0
    arcount = 0

    # Pack according to DNS header format: !HHHHHH
    return struct.pack("!HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)

def _encode_qname(domain):
    """
    Encode a domain name into canonical DNS QNAME format.
    This is still used for "primary" encodings inside the packet.
    """
    if not domain:
        return b"\x00"
    labels = domain.strip(".").split(".")
    encoded = bytearray()
    for label in labels:
        length = len(label)
        if length > 63:
            raise ValueError("Label '{}' too long for DNS (max 63 chars)".format(label))
        encoded.append(length)
        encoded.extend(label.encode("ascii"))
    encoded.append(0)  # Terminating zero length
    return bytes(encoded)


def _build_pointer_split_qname(domain, base_offset):
    """
    Build a QNAME that uses a dummy leading label and then a compression pointer
    back into the earlier encoded domain at 'base_offset'.

    Wire layout:
        <len(dummy)><dummy-bytes><pointer-to-base-offset>

    Many DPI engines simply parse labels linearly and may not
    correctly follow pointers for inspection, while real DNS
    servers must handle this per RFC 1035.
    """
    dummy_label = "x"  # short, harmless dummy label
    if not (0 <= base_offset <= 0x3FFF):
        raise ValueError("base_offset out of pointer range")

    qname = bytearray()
    # Dummy label
    qname.append(len(dummy_label))
    qname.extend(dummy_label.encode("ascii"))

    # Compression pointer (two bytes, high bits 11)
    pointer_val = 0xC000 | base_offset
    qname.extend(struct.pack("!H", pointer_val))

    # Note: no terminating zero here; the pointer target must itself terminate.
    return bytes(qname)

def _build_question_section(base_offset, qtype=1, qclass=1):
    """
    Build the DNS question section for a single query.
    qtype 1 = A, qclass 1 = IN

    The QNAME here is *only* a dummy label followed by a compression
    pointer back to an earlier, canonical encoding of the forbidden
    domain at 'base_offset'. This keeps the packet structurally
    standard (one QNAME in the question) while still confusing
    naive DPI that does not follow pointers.
    """
    pointer_qname = _build_pointer_split_qname("ignored.example", base_offset)
    return pointer_qname + struct.pack("!HH", qtype, qclass)

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload for the forbidden domain using a
    pointer-only QNAME in the question section.

    Layout:
      [12-byte header]
      [additional RR with NAME = canonical_qname(target_domain)]
      [question section with QNAME = pointer into additional RR NAME]

    This keeps the packet valid while separating the "real" domain
    string from the question QNAME bytes that a censor might scan.
    """
    if target_domain is None:
        raise ValueError("target_domain must not be None")

    # First, build the canonical encoding of the target domain.
    canonical_qname = _encode_qname(target_domain)

    # We will place one additional RR immediately after the header.
    # So the canonical_qname (as the NAME of that RR) starts at offset 12.
    base_offset = 12

    # Build a header that announces 1 question and 1 additional RR.
    # We ignore rd flag tuning for now, keep it standard.
    # qdcount=1, rd=1
    tid = _random_transaction_id()
    flags = 1 << 8  # RD set
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 1
    header = struct.pack("!HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)

    # Build a minimal additional RR whose NAME is the canonical_qname.
    # TYPE=A(1), CLASS=IN(1), TTL=0, RDLENGTH=0, no RDATA.
    rr_name = canonical_qname
    rr_type = 1
    rr_class = 1
    rr_ttl = 0
    rr_rdlength = 0
    additional_rr = rr_name + struct.pack("!HHIH", rr_type, rr_class, rr_ttl, rr_rdlength)

    # Now build the question section, whose QNAME is a pointer back into rr_name.
    question = _build_question_section(base_offset=base_offset)

    # Final payload: header + additional RR + question
    payload = header + additional_rr + question
    return payload

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END