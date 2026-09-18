# EVOLVE-BLOCK-START
"""
Header Syntax Divergence via Duplicate Host and Conflicting Values.
Some DPI engines trust the first simple Host header, while origin servers
honor the last one when duplicates exist, per common header overwrite rules.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    clean_path = path.lstrip("/") or ""
    absolute_uri = f"http://{host}/{clean_path}"
    request_line = f"GET {absolute_uri} HTTP/1.0\r\n"

    # First Host: benign domain to satisfy naive DPI
    h1 = "Host: ignored.example\r\n"
    # Second Host: real forbidden domain, preceded by an extra space to
    # confuse simpler parsers but still accepted by tolerant servers.
    h2 = " Host: " + host + "\r\n"

    headers = h1 + h2 + "Connection: close\r\n\r\n"
    return (request_line + headers).encode("ascii")

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
