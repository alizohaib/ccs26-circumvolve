from scapy.all import IP, UDP, DNS, DNSQR
import os

# EVOLVE-BLOCK-START
import struct
import random

def _encode_qname(domain: str) -> bytes:
    labels = domain.strip(".").split(".")
    parts = []
    for label in labels:
        length = len(label)
        if length > 63:
            raise ValueError("Label too long in domain name.")
        parts.append(struct.pack("!B", length))
        parts.append(label.encode("ascii"))
    parts.append(b"\x00")
    return b"".join(parts)

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with:
    - nonzero Z bits in the header flags
    - EDNS0 OPT pseudo-record with padding
    - duplicated QNAME split across two identical questions
    This stays standards-compliant but may confuse simple DPI logic.
    """
    if target_domain is None:
        target_domain = ""

    # DNS Header:
    # ID (2 bytes), Flags (2 bytes), QDCOUNT (2), ANCOUNT (2), NSCOUNT (2), ARCOUNT (2)
    transaction_id = random.getrandbits(16)

    # Use unusual but valid flag combination:
    # QR=0 (query), OPCODE=0 (standard), AA=0, TC=0, RD=1, RA=0
    # Set Z bits (per RFC they must be zero, but many resolvers ignore this),
    # which may cause naive DPI implementations to mis-parse the header.
    rd = 1
    z_bits = random.randint(1, 7)  # at least one Z bit set
    flags = (rd << 8) | (z_bits << 4)

    # Two identical questions: both ask for A record of the same QNAME.
    # Some censors look only at the first or apply simplified QDCOUNT checks.
    qdcount = 2
    ancount = 0
    nscount = 0
    arcount = 1  # one EDNS0 OPT additional record

    header = struct.pack("!HHHHHH", transaction_id, flags, qdcount, ancount, nscount, arcount)

    # Question section: QNAME + QTYPE (A=1) + QCLASS (IN=1)
    qname = _encode_qname(target_domain)
    qtype = 1
    qclass = 1
    question = qname + struct.pack("!HH", qtype, qclass)

    # Duplicate question; QNAME must not be omitted and must match target domain.
    questions = question + question

    # Build a minimal EDNS0 OPT pseudo-record with padding option.
    # OPT name is root (0x00)
    opt_name = b"\x00"
    # TYPE = 41 (OPT)
    opt_type = 41
    # UDP payload size: pick a common non-default (e.g., 1232) to add diversity.
    udp_payload_size = 1232
    # EXTended RCODE + EDNS version + Z; we keep them zeroed for better compatibility.
    extended_rcode = 0
    edns_version = 0
    edns_z = 0
    # EDNS0 options: add a PADDING option (RFC 7830) with random length/content.
    # Option code 12 = PADDING
    pad_code = 12
    pad_length = random.randint(8, 32)
    pad_data = os.urandom(pad_length)
    opt_option = struct.pack("!HH", pad_code, pad_length) + pad_data
    opt_rdlength = len(opt_option)

    opt_header = struct.pack(
        "!BHHBBH",
        0,  # name already covered by opt_name (root)
        opt_type,
        udp_payload_size,
        extended_rcode,
        edns_version,
        edns_z,
    )
    # The above pack doesn't include RDLENGTH; append it and the options.
    opt_record = opt_name + struct.pack("!H", opt_type) + struct.pack("!H", udp_payload_size) + struct.pack("!B", extended_rcode) + struct.pack("!B", edns_version) + struct.pack("!H", edns_z) + struct.pack("!H", opt_rdlength) + opt_option

    return header + questions + opt_record

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END