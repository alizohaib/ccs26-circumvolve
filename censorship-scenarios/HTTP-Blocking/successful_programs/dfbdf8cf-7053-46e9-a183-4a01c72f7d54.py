# EVOLVE-BLOCK-START
"""
Header Value LWS Obfuscation - Splits the forbidden hostname across linear whitespace in the Host value to confuse DPI tokenization while remaining acceptable to tolerant servers.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    # Use OPTIONS * which some DPIs don't associate with Host-based filtering
    request_line = "OPTIONS * HTTP/1.1\r\n"

    # Prepend linear whitespace to the host value itself: "Host:  \tpornhub.com"
    # Some DPIs won't normalize this fully, while servers commonly do.
    obfuscated_host_value = " \t" + host
    host_header = f"Host: {obfuscated_host_value}\r\n"

    headers = host_header + "Connection: close\r\n\r\n"
    request = request_line + headers
    return request.encode("ascii")

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
