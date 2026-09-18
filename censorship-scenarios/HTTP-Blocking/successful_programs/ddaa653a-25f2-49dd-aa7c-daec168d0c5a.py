# EVOLVE-BLOCK-START
"""
Host Name Obfuscation with Decoy Header - Sends a harmless-looking pseudo-Host header first and the real Host header later, hoping DPI only inspects the first while the server honors the last valid Host.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    request_line = f"GET {path} HTTP/1.1\r\n"

    # First, a decoy header that looks similar to Host but is not semantically Host
    decoy = "Host-Alt: example.com\r\n"

    # Second, the real Host header with the forbidden name
    real_host = f"Host: {host}\r\n"

    headers = decoy + real_host + "Connection: close\r\n\r\n"
    request = request_line + headers
    return request.encode("ascii", "strict")

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
