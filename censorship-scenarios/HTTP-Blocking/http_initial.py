# EVOLVE-BLOCK-START
"""
Standard HTTP GET - Baseline HTTP/1.1 GET request with standard headers.
"""


def generate_http_request(host: str = "blocked.com", path: str = "/") -> bytes:
    """
    Generate a standard HTTP/1.1 GET request.
    
    Args:
        host: Target host for the Host header
        path: URL path to request
    
    Returns:
        Raw HTTP request bytes
    """
    # Standard HTTP/1.1 GET request
    request_line = f"GET {path} HTTP/1.1\r\n"
    
    # Standard headers
    headers = [
        f"Host: {host}",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language: en-US,en;q=0.9",
        "Accept-Encoding: gzip, deflate",
        "Connection: close",
    ]
    
    # Combine into full request
    # HTTP requests end with double CRLF
    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    
    return request.encode('utf-8')


if __name__ == "__main__":
    # Target domain 
    target_host = "blocked.com"
    
    # Generate the HTTP request
    payload = generate_http_request(host=target_host, path="/")
    
    # Output as hex string (required format for the evaluator)
    print(payload.hex())

# EVOLVE-BLOCK-END


