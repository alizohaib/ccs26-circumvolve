# EVOLVE-BLOCK-START
# Strategy: Use DNS compression pointer indirection to hide the QNAME from DPI.
# Place actual domain in Additional section, reference via pointer in Question.
# DPI often skips pointer dereferencing; resolvers handle it correctly per RFC 1035.

import struct
import random

def generate_dns_request(target_domain=None):
    """
    Generates an evasive DNS request using compression pointer obfuscation.
    The real domain is encoded later in the packet; Question uses a pointer.
    """
    
    transaction_id = random.randint(0, 65535)
    
    # Flags: standard query with recursion desired
    flags = 0x0100
    
    # 1 Question, 0 Answers, 0 Authority, 1 Additional (for EDNS0 OPT + hidden domain)
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 1
    
    header = struct.pack('>HHHHHH', 
                         transaction_id, 
                         flags, 
                         qdcount, 
                         ancount, 
                         nscount, 
                         arcount)
    
    def encode_domain(domain):
        encoded = b''
        labels = domain.split('.')
        for label in labels:
            encoded += struct.pack('B', len(label)) + label.encode('ascii')
        encoded += b'\x00'
        return encoded
    
    # Header is 12 bytes. Question section starts at offset 12.
    # We'll place a compression pointer in Question that points to Additional section.
    
    # Question section: use pointer to domain in Additional (calculated below)
    # Pointer format: 2 bytes, first 2 bits = 11, remaining 14 bits = offset
    
    # Build Additional section first to calculate offset
    # Additional will contain: encoded domain + OPT pseudo-RR
    domain_encoded = encode_domain(target_domain)
    
    # Question with direct pointer to Additional section's domain
    # Header(12) + Question_pointer(2) + QTYPE(2) + QCLASS(2) = 18 bytes before Additional
    # So domain in Additional starts at offset 18
    domain_offset = 18
    pointer = 0xC000 | domain_offset  # Compression pointer
    
    question = struct.pack('>H', pointer) + struct.pack('>HH', 1, 1)  # QTYPE=A, QCLASS=IN
    
    # Additional section: the actual domain followed by OPT record
    # Domain name (will be pointed to) + OPT RR for EDNS0
    # OPT RR: NAME=0x00 (root), TYPE=41, UDP_SIZE=4096, RCODE_EXT=0, VERSION=0, FLAGS=0, RDLEN=0
    opt_record = b'\x00' + struct.pack('>HHIH', 41, 4096, 0, 0)
    
    additional = domain_encoded + opt_record
    
    return header + question + additional

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    random.seed(0)
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END