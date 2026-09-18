# EVOLVE-BLOCK-START
"""
Host Header Folding with OWS - Uses a tab after the colon plus obsolete
line folding so the middlebox may see a mangled Host value while the
server unfolds it into a normal single-line header.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    # Standard request line to keep servers happy
    request_line = f"GET {path} HTTP/1.1\r\n"

    # Obsolete line folding: DPI might tokenize per-line and miss continuation
    # while many servers unfold to "Host: <host>"
    host_header = f"Host:\t\r\n {host}"

    headers = [
        host_header,
        "Connection: close"
    ]

    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    return request.encode("utf-8")

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
