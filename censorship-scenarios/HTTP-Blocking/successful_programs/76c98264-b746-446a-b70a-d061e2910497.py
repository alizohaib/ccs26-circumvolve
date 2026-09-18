# EVOLVE-BLOCK-START
"""
State Desync - Prepends a CRLF (\r\n) before the Request Line.
Intended to flush/reset the DPI parser state or desynchronize traffic analysis.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    request_line = f"GET {path} HTTP/1.1\r\n"
    
    headers = [
        f"Host: {host}",
        "Connection: close"
    ]
    
    # Prepend \r\n to the entire payload
    request = "\r\n" + request_line + "\r\n".join(headers) + "\r\n\r\n"
    
    return request.encode('utf-8')

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
