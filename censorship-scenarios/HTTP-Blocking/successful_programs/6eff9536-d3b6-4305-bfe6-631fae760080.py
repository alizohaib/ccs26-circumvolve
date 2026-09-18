# EVOLVE-BLOCK-START
"""
LF-only Request-Line Variant + Plain Host:
Use the previously successful HTTP/1.1␠\n request line while keeping a simple Host header to avoid server-side parsing issues.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    # Slightly noncanonical request line (extra space before LF) that many servers accept
    request_line = f"GET {path} HTTP/1.1 \n"

    # Keep Host simple and explicit; rely on LF-only semantics for desync instead
    headers = [
        f"Host: {host}",
        "Connection: close"
    ]

    request = request_line + "\n".join(headers) + "\n\n"
    return request.encode("utf-8")

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
