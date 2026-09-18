# EVOLVE-BLOCK-START
"""
Host Header Obfuscation - Insert multiple spaces after 'Host:' to evade strict DPIs
while relying on tolerant server header parsing.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    request_line = f"GET {path} HTTP/1.1\r\n"
    
    # Use multiple spaces after 'Host:' to break rigid DPI tokenization
    headers = [
        f"Host:   {host}",
        "Connection: close"
    ]
    
    # Keep the leading CRLF state-desync behavior for now, but overall code is concise
    request = "\r\n" + request_line + "\r\n".join(headers) + "\r\n\r\n"
    
    return request.encode("ascii")

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    # Print raw byte stream as hexadecimal
    print(payload.hex())
# EVOLVE-BLOCK-END
