# EVOLVE-BLOCK-START
"""
Minimal HTTP/1.0 absolute-form request with downgrade-friendly semantics.

Hypothesis: A DPI keyed on Host and HTTP/1.1 framing may ignore an HTTP/1.0
absolute-form request without any Host header, while origin servers still reply.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    # Use HTTP/1.0 to keep servers happy but still avoid any Host header.
    # Absolute-form URI carries the forbidden hostname outside of Host.
    absolute_uri = f"http://{host}{path}"
    request_line = f"GET {absolute_uri} HTTP/1.0\r\n"

    # Keep headers minimal and generic to reduce anomaly-triggering features.
    headers = [
        "User-Agent: curl/8.0",
        "Connection: close",
    ]

    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    return request.encode("ascii", errors="strict")

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
