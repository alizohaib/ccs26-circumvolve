# EVOLVE-BLOCK-START
"""
HTTP/1.0 Absolute-Form with Simple Host - Uses HTTP/1.0 plus an
absolute-form request target so middleboxes focused on HTTP/1.1 Host
semantics may under-inspect it while origin servers still respond.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    clean_path = path.lstrip("/")
    absolute_uri = f"http://{host}/{clean_path}"
    # Use HTTP/1.0 with an absolute URI (proxy style) in the request line.
    request_line = f"GET {absolute_uri} HTTP/1.0\r\n"

    # Keep a straightforward Host header for compatibility; many servers
    # treat it as advisory in 1.0 while still returning a valid response.
    headers = [
        f"Host: {host}",
        "Connection: close"
    ]

    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    return request.encode("utf-8")

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
