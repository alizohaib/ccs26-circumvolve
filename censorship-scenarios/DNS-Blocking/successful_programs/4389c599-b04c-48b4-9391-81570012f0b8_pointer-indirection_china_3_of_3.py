# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload that still queries the forbidden domain,
    but uses a second, pointer-only QNAME to perturb DPI parsing while
    remaining valid for real DNS servers.
    """
    if target_domain is None:
        raise ValueError("target_domain must not be None")

    # Ensure a plain, fully-qualified QNAME for the FIRST (canonical) question.
    # This keeps one question absolutely standard so real servers will answer it.
    if not target_domain.endswith("."):
        fqdn = target_domain + "."
    else:
        fqdn = target_domain

    # Primary, normal question for maps.google.sm.
    primary_q = DNSQR(qname=fqdn)
    raw_primary_qd = bytes(primary_q)

    # --- Header: 2 questions, no answers, no additional RRs ---
    # Keep flags exactly as in the best-valid previous program to regain stage1_validity:
    # ID:      0x0003  (non-zero, new ID to differ from earlier packets)
    # Flags:   0x0100  (standard query, recursion desired)
    # QDCOUNT: 0x0002  (two questions)
    # ANCOUNT: 0x0000
    # NSCOUNT: 0x0000
    # ARCOUNT: 0x0000
    header = b"\x00\x03"  # ID
    header += b"\x01\x00"  # Flags
    header += b"\x00\x02"  # QDCOUNT = 2
    header += b"\x00\x00"  # ANCOUNT
    header += b"\x00\x00"  # NSCOUNT
    header += b"\x00\x00"  # ARCOUNT

    # --- Second question: QNAME composed ONLY of compression pointers ---
    #
    # We exploit the known wire layout of the FIRST QNAME. For "maps.google.sm." the
    # on-the-wire encoding is:
    #   04 'm' 'a' 'p' 's'
    #   06 'g' 'o' 'o' 'g' 'l' 'e'
    #   02 's' 'm'
    #   00
    #
    # Header is 12 bytes, so:
    #   offset 12: length 4 ("maps")
    #   offset 17: length 6 ("google")
    #   offset 24: length 2 ("sm")
    #   offset 27: 0x00 end
    #
    # The second QNAME is built as a *sequence* of pointers:
    #   [ptr to "maps"] [ptr to "google"] [ptr to "sm"] [ptr to root]
    #
    # Most DPI engines don't expect a label sequence made entirely of pointers and
    # may mis-parse or stop early, while RFC-compliant name decompression can still
    # reconstruct an equivalent name chain referencing the same domain structure.
    #
    # Pointer syntax: 0xC0 | (offset >> 8), offset & 0xFF
    ptr_maps   = bytes([0xC0, 12])  # pointer to "maps"
    ptr_google = bytes([0xC0, 17])  # pointer to "google"
    ptr_sm     = bytes([0xC0, 24])  # pointer to "sm"
    ptr_root   = bytes([0xC0, 27])  # pointer to the terminating 0x00 (root)

    compressed_qname = ptr_maps + ptr_google + ptr_sm + ptr_root

    # QTYPE A, QCLASS IN for the second question as well.
    second_q = compressed_qname + b"\x00\x01" + b"\x00\x01"

    # Final packet: header + primary (standard) question + secondary (pointer-only) question
    return header + raw_primary_qd + second_q

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END