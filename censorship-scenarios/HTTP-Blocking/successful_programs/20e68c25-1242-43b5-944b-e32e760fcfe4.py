# EVOLVE-BLOCK-START
"""
CRLF vs LF Header Boundary Desync - Mixes CRLF and bare LF as line terminators,
hoping the DPI treats LFs as delimiters while a tolerant server still parses
the request as a valid HTTP/1.1 message.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    # Standard request line with CRLF
    request_line = f"GET {path} HTTP/1.1\r\n"
    # Use CRLF after Host, then only LF after Connection, then final CRLF terminator
    headers = [
        f"Host: {host}\r\n",
        "Connection: close\n"
    ]
    request = request_line + "".join(headers) + "\r\n"
    return request.encode("utf-8")

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END	
