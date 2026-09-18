# EVOLVE-BLOCK-START
"""
Protocol Compliance Exploit - Sends an Absolute URI in the Request Line
and OMITS the Host header entirely (or uses a dummy).
Bypasses Host-based filtering completely.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    # 1. Construct Absolute URI
    absolute_uri = f"http://{host}{path}"
    
    # 2. Use it in Request Line
    request_line = f"GET {absolute_uri} HTTP/1.1\r\n"
    
    # 3. Headers - NO Host header for the blocked site.
    # Some strict servers require *a* Host header for syntax, 
    # so we provide a safe one which the server is supposed to ignore 
    # in favor of the absolute URI.
    headers = [
        "Host: google.com", # Decoy. Server should ignore this.
        "Connection: close"
    ]
    
    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    
    return request.encode('utf-8')

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
