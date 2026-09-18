# EVOLVE-BLOCK-START
"""
Method Line + Header Reordering Anomaly with LF-only delimiters.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    # Use HTTP/1.0 with an extra space to slightly perturb the request line parser
    request_line = f"GET {path}  HTTP/1.0\n"  # double space before HTTP/1.0

    # Put Connection before Host to change header layout seen by simple DPIs
    headers = [
        "Connection: close",
        f"Host: {host}",
    ]

    # LF-only terminators (no CR) preserved
    request = request_line + "\n".join(headers) + "\n\n"
    return request.encode("utf-8")

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
