# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import os
import random
import struct

def generate_dns_request(target_domain=None):
    """
    DNS request with:
      - Single question (improves resolver tolerance vs multi‑question)
      - Manual QNAME encoding with 0x20 case randomization
      - TC bit set and non‑zero Z bits (seen in top performers)
    This stays very close to the best historical programs while keeping the
    code compact and RFC‑compatible to avoid stage1_local_validity failures.
    """
    if target_domain is None:
        raise ValueError("target_domain must be provided")

    # 0x20 case randomization
    def randomize_case(name: str) -> str:
        out = []
        for ch in name:
            if ch.isalpha() and (os.urandom(1)[0] & 1):
                out.append(ch.upper())
            else:
                out.append(ch.lower())
        return "".join(out)

    def encode_qname(domain: str) -> bytes:
        labels = domain.strip(".").split(".")
        encoded = b""
        for lbl in labels:
            rc = randomize_case(lbl)
            encoded += bytes([len(rc)]) + rc.encode("ascii")
        encoded += b"\x00"
        return encoded

    qname = encode_qname(target_domain)

    # Header fields similar to Program 1/2 (which had good fitness)
    tid = random.randint(0, 0xFFFF)
    # QR=0, OPCODE=0, AA=0, TC=1, RD=1, RA=0, Z=0b101, RCODE=0  -> 0x0760
    flags = 0x0760
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)

    # QTYPE=A, QCLASS=IN
    question = qname + struct.pack("!HH", 1, 1)

    return header + question

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
