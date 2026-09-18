from scapy.all import DNS, DNSQR

# EVOLVE-BLOCK-START
def generate_dns_request(target_domain=None):
    """
    Generates a DNS request payload that embeds the target A query as a
    secondary question, with a TXT query placed first to change layout.
    The QNAME is unchanged and appears in both questions.
    """
    if target_domain is None:
        target_domain = "example.com"

    # Primary question: TXT (unusual for censored domains)
    primary_q = DNSQR(qname=target_domain, qtype="TXT")
    # Secondary question: the actual A query
    secondary_q = DNSQR(qname=target_domain, qtype="A")

    dns_layer = DNS(
        rd=1,
        qdcount=2,
        qd=primary_q / secondary_q
    )
    return bytes(dns_layer)

if __name__ == "__main__":
    target = "maps.google.sm"
    payload = generate_dns_request(target_domain=target)
    print(payload.hex())

# EVOLVE-BLOCK-END

