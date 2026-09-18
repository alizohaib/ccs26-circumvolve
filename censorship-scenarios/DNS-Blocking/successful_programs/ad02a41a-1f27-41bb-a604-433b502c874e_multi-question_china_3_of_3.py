# EVOLVE-BLOCK-START

from scapy.all import DNS

def _encode_qname(name: str) -> bytes:
    labels = name.strip(".").split(".")
    return b"".join(bytes([len(l)]) + l.encode("utf-8") for l in labels if l) + b"\x00"

def generate_dns_request(target_domain=None):
    if target_domain is None:
        raise ValueError("target_domain must be provided")

    # Header: keep a single valid question in QD section, but lie about QDCOUNT=2
    header = b"\x1a\x2b"      # ID
    header += b"\x01\x00"     # standard query
    header += b"\x00\x02"     # QDCOUNT=2 (but we'll only include 1 well‑formed question)
    header += b"\x00\x00"     # ANCOUNT
    header += b"\x00\x00"     # NSCOUNT
    header += b"\x00\x00"     # ARCOUNT

    # First (real) question: regular A IN for the target
    qname_real = _encode_qname(target_domain)
    question_real = qname_real + b"\x00\x01" + b"\x00\x01"

    # Second "ghost" question: starts with a short label and then the full target_domain,
    # but we intentionally omit QTYPE/QCLASS so parsers may stop; DPI that scans only
    # the first question or expects strict QDCOUNT may mis-handle this.
    ghost_prefix = b"\x03pad"  # "pad" label
    ghost_qname = ghost_prefix + _encode_qname(target_domain)

    raw_dns = header + question_real + ghost_qname

    dns_layer = DNS(raw_dns)
    return bytes(dns_layer)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END