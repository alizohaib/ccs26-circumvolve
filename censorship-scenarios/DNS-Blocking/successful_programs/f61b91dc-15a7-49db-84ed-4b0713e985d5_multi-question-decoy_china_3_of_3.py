# EVOLVE-BLOCK-START

from scapy.all import DNS, DNSQR

def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload with a fragmented/duplicated QNAME
    layout to confuse DPI while still including the target domain and
    using an A-record query.
    """
    if target_domain is None:
        target_domain = "maps.google.sm"

    # Construct a slightly altered view of the QNAME for the main question
    # (still contains the full target domain string)
    main_qname = target_domain + "."
    # Add a misleading second question that also embeds the target domain
    # in a different label layout to perturb DPI heuristics.
    decoy_qname = "x-" + target_domain.replace(".", "-") + ".example.net"

    dns_layer = DNS(
        id=0x1234,
        rd=1,
        qdcount=2,
        qd=DNSQR(qname=main_qname, qtype="A", qclass="IN") /
           DNSQR(qname=decoy_qname, qtype="A", qclass="IN")
    )

    return bytes(dns_layer)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END

