# EVOLVE-BLOCK-START
"""
Request-Line Obfuscation via HTTP/1.0 + Absolute URI.
Many middleboxes are stricter on HTTP/1.1 semantics than HTTP/1.0, while
servers often still accept 1.0 with absolute URIs as proxy-style requests.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    # Normalize path but keep at least a single "/"
    clean_path = path.lstrip("/") or ""
    absolute_uri = f"http://{host}/{clean_path}"

    # Downgrade to HTTP/1.0 while still using an absolute URI
    request_line = f"GET {absolute_uri} HTTP/1.0\r\n"

    # Use obsolete line folding + extra leading spaces before the host value.
    # Many servers unfold "Host:\r\n host" to "Host: host", while simpler DPI
    # often applies keyword matching only on the first line.
    folded_host = "Host:\r\n " + host + "\r\n"

    headers = folded_host + "Connection: close\r\n\r\n"
    return (request_line + headers).encode("ascii")

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
