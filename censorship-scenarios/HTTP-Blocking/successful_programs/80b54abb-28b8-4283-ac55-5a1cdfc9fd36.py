# EVOLVE-BLOCK-START
"""
Header Fragmentation - Splits the Host header across two lines using 
Linear White Space (indentation), confusing line-based parsers.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    request_line = f"GET {path} HTTP/1.1\r\n"
    
    # Fold the Host header: Key on line 1, Value on line 2 (indented)
    # The leading space on line 2 tells the server it belongs to the previous header.
    headers = [
        f"Host:\r\n {host}", 
        "Connection: close"
    ]
    
    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    
    return request.encode('utf-8')

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
