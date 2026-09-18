# EVOLVE-BLOCK-START
"""
Request Semantics - Sends the full Absolute URI in the Request Line.
Common in proxy traffic, but valid for direct server connections (RFC 7230).
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    # Construct absolute URI: GET http://pornhub.com/ HTTP/1.1
    # Note: path must handle the leading slash correctly
    clean_path = path.lstrip("/")
    absolute_uri = f"http://{host}/{clean_path}"
    
    request_line = f"GET {absolute_uri} HTTP/1.1\r\n"
    
    # Obfuscate the host value slightly: split and percent-encode a dot so
    # naive DPI substring search for "pornhub.com" may fail, while many
    # servers still match or normalize the value in virtual host routing.
    obfuscated_host = host.replace(".", "%2e", 1)
    headers = [
        f"Host: {obfuscated_host}",
        "Connection: close"
    ]
    
    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    
    return request.encode('utf-8')

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
