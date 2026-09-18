# EVOLVE-BLOCK-START
"""
T3_02_host_obs_fold_tabcont_min - Minimal Host header with HT-based obsolete line folding.
"""


def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    """
    Minimal HTTP/1.1 request using obsolete line folding in the Host header.
    """
    # Anomaly: split Host header across two lines using obs-fold,
    # but use a horizontal TAB (0x09) as the leading whitespace on the continuation line.
    request = (
        f"GET {path} HTTP/1.1\r\n"
        "Host:\r\n"
        f"\t{host}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    return request.encode("ascii")


if __name__ == "__main__":
    # Target domain 
    target_host = "pornhub.com"
    
    # Generate the HTTP request
    payload = generate_http_request(host=target_host, path="/")
    
    # Output as hex string (required format for the evaluator)
    print(payload.hex())

# EVOLVE-BLOCK-END
