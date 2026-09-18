# EVOLVE-BLOCK-START
"""
Protocol Versioning + Host LWS Padding - Uses a non-standard HTTP version (HTTP/1.2) and injects extra spaces around the Host value so middleboxes that tokenize strictly on SP may miss the forbidden hostname while tolerant servers trim LWS.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    # Non-standard, but usually loosely parsed, version "1.2"
    request_line = f"GET {path} HTTP/1.2\r\n"

    # Add leading/trailing spaces around host to stress Host-value parsing
    obf_host = f"Host:  {host}  \r\n"
    conn_hdr = "Connection: close\r\n\r\n"

    request = request_line + obf_host + conn_hdr
    return request.encode("ascii", "strict")

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    # Print the raw bytes as hexadecimal for direct injection
    print(payload.hex())
# EVOLVE-BLOCK-END
