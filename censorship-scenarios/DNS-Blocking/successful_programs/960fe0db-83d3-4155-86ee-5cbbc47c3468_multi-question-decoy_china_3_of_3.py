# EVOLVE-BLOCK-START

import struct
import random

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload using manual byte construction.
    Args:
        target_domain (str): The domain name to resolve.
    """
    
    # Generate random transaction ID
    transaction_id = random.randint(0, 65535)
    
    # DNS Header fields
    # Flip TC bit (truncated on UDP) and set a non-zero Z bit to explore DPI vs. resolver parsing differences,
    # and allow up to 2 questions to introduce multi-question behavior for diversity.
    flags = 0x2300  # QR=0 | OPCODE=0 | AA=0 | TC=1 | RD=1 | RA=0 | Z=0b011 | RCODE=0
    qdcount = 2     # Number of questions (primary + secondary/decoy)
    ancount = 0     # Number of answers
    nscount = 0     # Number of authority records
    arcount = 0     # Number of additional records
    
    # Pack DNS header (12 bytes)
    header = struct.pack('>HHHHHH', 
                         transaction_id,
                         flags,
                         qdcount,
                         ancount,
                         nscount,
                         arcount)
    
    # Encode domain name in DNS format
    def encode_domain(domain):
        encoded = b''
        for label in domain.split('.'):
            # Basic safety: clamp label length to DNS max 63 to avoid wire-illegal names
            lab = label.encode('ascii')
            if len(lab) > 63:
                lab = lab[:63]
            encoded += bytes([len(lab)]) + lab
        encoded += b'\x00'  # Null terminator
        return encoded

    # Primary (target) QNAME
    qname_primary = encode_domain(target_domain)

    # Secondary "decoy" QNAME: benign domain with different length/labels to diversify parsing paths
    decoy_domain = "example.com"
    qname_decoy = encode_domain(decoy_domain)

    # Question section: each question is QNAME + QTYPE (A=1) + QCLASS (IN=1)
    qtype = 1   # A record
    qclass = 1  # IN (Internet)
    question_primary = qname_primary + struct.pack('>HH', qtype, qclass)
    question_decoy = qname_decoy + struct.pack('>HH', qtype, qclass)

    question = question_primary + question_decoy

    return header + question

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END