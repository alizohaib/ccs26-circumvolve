# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import os
import struct

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload.
    Args:
        target_domain (str): The domain name to resolve.
    """

    if not target_domain:
        return b""

    # Manually encode domain into DNS label format: len(label) + label + ... + 0x00
    # Additionally, we randomize case to make simple DPI string-matching harder.
    def encode_domain(domain: str) -> bytes:
        parts = domain.strip(".").split(".")
        encoded = bytearray()
        for part in parts:
            # Mixed-case label encoding: DNS is case-insensitive, but DPI
            # might look for fixed "client-cdn4.hola.org" byte patterns.
            randomized = bytearray()
            for ch in part.encode("ascii"):
                # Randomly flip case for alphabetic characters
                if 65 <= ch <= 90 or 97 <= ch <= 122:
                    if os.urandom(1)[0] & 1:
                        # toggle case bit
                        ch ^= 0x20
                randomized.append(ch)
            encoded.append(len(randomized))
            encoded.extend(randomized)
        encoded.append(0)
        return bytes(encoded)

    # DNS header fields:
    # ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    # Using a random ID for variability
    transaction_id = os.urandom(2)
    flags = 0x0100  # standard query, recursion desired

    # We will send two questions for the same forbidden domain:
    #  - Q1: normal, fully encoded QNAME
    #  - Q2: QNAME as a compression pointer back to Q1
    #
    # Some on-path injectors have simplistic QNAME parsing that assumes
    # a single question and/or no name compression; this layout may
    # cause them to mis-parse while the real DNS server still accepts it.
    qdcount = 2
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!2sHHHHH", transaction_id, flags, qdcount, ancount, nscount, arcount)

    # First question: explicit QNAME for the forbidden domain
    qname1 = encode_domain(target_domain)
    qtype = 1   # A record
    qclass = 1  # IN
    question1 = qname1 + struct.pack("!HH", qtype, qclass)

    # Second question: QNAME is a compression pointer back to the first QNAME.
    # In a DNS message, the header is 12 bytes. We place QNAME1 immediately
    # after the header, so its start offset is 12 (0x000c). The pointer form
    # is two bytes: 11xxxxxx xxxxxxxx, where lower 14 bits are the offset.
    pointer_offset = 12
    compressed_qname = struct.pack("!H", 0xC000 | pointer_offset)
    question2 = compressed_qname + struct.pack("!HH", qtype, qclass)

    return header + question1 + question2

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END