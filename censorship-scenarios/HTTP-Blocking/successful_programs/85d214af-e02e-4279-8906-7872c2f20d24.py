# EVOLVE-BLOCK-START
"""
Request-Line Version Anomaly + LF-only Delimiters –
Use a slightly malformed HTTP/1.0-style request line with LF-only terminators
to confuse strict HTTP/1.1-oriented DPI while keeping servers tolerant.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    # Double space before HTTP version but keep an HTTP/1.0 request for better server compatibility
    request_line = f"GET {path}  HTTP/1.0\n"

    headers = [
        f"Host: {host}",
        "Connection: close",
    ]

    request = request_line + "\n".join(headers) + "\n\n"
    return request.encode("utf-8")

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
