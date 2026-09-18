# EVOLVE-BLOCK-START
"""
Absolute-Form HTTP/1.0 - Uses an HTTP/1.0 request line with an absolute
URI so some DPI that focus on HTTP/1.1 Host semantics under-inspect it,
while typical servers still accept and route the request correctly.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    clean_path = path.lstrip("/")
    absolute_uri = f"http://{host}/{clean_path}"
    # Downgrade to HTTP/1.0 but keep absolute-form target (proxy-style path)
    request_line = f"GET {absolute_uri} HTTP/1.0\r\n"
    # Simple Host header; many servers ignore it for 1.0 but still accept it
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
