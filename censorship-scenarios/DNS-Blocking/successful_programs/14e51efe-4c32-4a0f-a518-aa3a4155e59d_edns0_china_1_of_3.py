from scapy.all import IP, UDP, DNS, DNSQR, DNSRROPT
import os

# EVOLVE-BLOCK-START
def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload.
    Args:
        target_domain (str): The domain name to resolve.
    """
    # Use a fixed but non-zero ID and uncommon combination of flags
    # QR=0 (query), OPCODE=0 (standard), AA=0, TC=0, RD=1, RA=0, Z=1 (non-zero), AD=0, CD=1
    # This changes the header bit pattern without changing semantics for most servers.
    dns_layer = DNS(
        id=0x1234,
        qr=0,
        opcode=0,
        aa=0,
        tc=0,
        rd=1,
        ra=0,
        z=1,      # non-standard Z bit
        ad=0,
        cd=1,     # checking disabled
        qd=DNSQR(qname=target_domain, qtype="A", qclass="IN"),
        # Add an EDNS0 OPT RR in the additional section with padding.
        ar=DNSRROPT(
            rclass=4096,   # UDP payload size
            extrcode=0,
            version=0,
            z=0,
            rdlen=16,      # length of option data
            rdata=b"\x00" * 16  # simple padding; alters packet size/layout
        )
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END

