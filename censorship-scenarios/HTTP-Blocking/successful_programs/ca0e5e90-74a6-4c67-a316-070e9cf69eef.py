# EVOLVE-BLOCK-START
"""
Line Delimiter Confusion - Replaces standard CRLF (\r\n) with LF (\n).
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    # Use \n instead of \r\n
    request_line = f"GET {path} HTTP/1.1\n"
    
    headers = [
        f"Host: {host}",
        "Connection: close"
    ]
    
    # Join with only \n, end with \n\n
    request = request_line + "\n".join(headers) + "\n\n"
    
    return request.encode('utf-8')

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
