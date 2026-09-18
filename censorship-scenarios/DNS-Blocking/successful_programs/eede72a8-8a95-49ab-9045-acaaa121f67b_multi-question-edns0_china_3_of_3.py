# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR
import random

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload.
    Args:
        target_domain (str): The domain name to resolve.
    """
    # Keep the packet fully RFC-normal on the wire but introduce a *layout*
    # oddity that some DPI stacks mishandle: put a harmless EDNS(0) OPT
    # pseudo‑RR in the additional section while keeping the question itself
    # completely standard.
    #
    # Rationale:
    #   - Stage 1: Real resolvers see a normal IN/A question; EDNS(0) is
    #     widely supported and safely ignored if not understood.
    #   - Stage 2: Many on‑path injectors have simplified DNS parsers that
    #     either:
    #       * bail out early when ARCOUNT != 0, or
    #       * mis-parse QNAME when an OPT RR is present.
    #
    # We deliberately *avoid* multi‑question trickery here and instead probe
    # the "additional + EDNS" edge‑case while keeping QTYPE/QCLASS fixed.

    if target_domain is None:
        return b""

    # Primary, fully normal question: IN / A
    primary_qd = DNSQR(qname=target_domain, qtype=1, qclass=1)

    # Introduce diversity in a *second* question and in EDNS(0) usage.
    # This probes:
    #   - QTYPE diversification (AAAA / ANY / CNAME)
    #   - QCLASS mutation (CH / HS)
    #   - Presence/absence of EDNS(0) OPT RR
    #
    # Many DPIs are tuned to:
    #   * Assume a single IN/A question.
    #   * Only parse the first question.
    #   * Or only parse when no additional records are present.
    #
    # We keep the first question completely standard to preserve Stage 1
    # validity, and only make the "weird" changes in secondary/question
    # and additional sections.

    # Decide whether to attach a secondary, "odd" question
    include_second_q = random.random() < 0.5

    if include_second_q:
        # QTYPE exploration for the second question: AAAA, ANY, CNAME
        secondary_qtypes = [28, 255, 5]  # AAAA, ANY, CNAME
        secondary_qtype = random.choice(secondary_qtypes)

        # QCLASS exploration: CH / HS
        secondary_qclasses = [3, 4]      # CH, HS
        secondary_qclass = random.choice(secondary_qclasses)

        secondary_qd = DNSQR(
            qname=target_domain,
            qtype=secondary_qtype,
            qclass=secondary_qclass,
        )
        qd_section = primary_qd / secondary_qd
        qdcount = 2
    else:
        qd_section = primary_qd
        qdcount = 1

    # Decide independently whether to include an EDNS(0) OPT RR
    include_opt = random.random() < 0.5

    if include_opt:
        # Build a minimal EDNS(0) OPT RR manually in the "raw" section so Scapy
        # doesn't try to be smart about it. This ends up as:
        #   NAME  = root (0x00)
        #   TYPE  = OPT (0x0029)
        #   UDP   = 1232 bytes payload size (0x04d0)
        #   EXT RCODE + VERSION = 0x0000
        #   Z     = 0x0000
        #   RDLEN = 0x0000 (no EDNS options)
        opt_rr = b"\x00"        # root label
        opt_rr += b"\x00\x29"   # TYPE=41 (OPT)
        opt_rr += b"\x04\xd0"   # UDP payload size = 1232
        opt_rr += b"\x00"       # extended RCODE
        opt_rr += b"\x00"       # EDNS version
        opt_rr += b"\x00\x00"   # Z flags
        opt_rr += b"\x00\x00"   # RDLEN = 0

        arcount = 1
        dns_layer = DNS(
            id=random.getrandbits(16),
            qr=0,
            opcode=0,
            aa=0,
            tc=0,
            rd=1,
            ra=0,
            z=0,
            ad=0,
            cd=0,
            qdcount=qdcount,
            ancount=0,
            nscount=0,
            arcount=arcount,
            qd=qd_section,
        ) / opt_rr
    else:
        # No additional records, completely standard header layout, but
        # possibly with a second, odd question.
        arcount = 0
        dns_layer = DNS(
            id=random.getrandbits(16),
            qr=0,
            opcode=0,
            aa=0,
            tc=0,
            rd=1,
            ra=0,
            z=0,
            ad=0,
            cd=0,
            qdcount=qdcount,
            ancount=0,
            nscount=0,
            arcount=arcount,
            qd=qd_section,
        )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "client-cdn4.hola.org"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END
