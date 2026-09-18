# EVOLVE-BLOCK-START
"""
Request-Line vs Host Mismatch - Place the forbidden hostname only in the absolute-form
request-target while sending a benign Host header that middleboxes key on.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    # Put the censored domain into the absolute URI so a DPI that only inspects
    # the Host header misses it, while origin routing uses the benign Host.
    bad_host = host
    request_line = f"GET http://{bad_host}{path} HTTP/1.1\r\n"

    # Use a harmless-looking hostname in the Host header
    headers = [
        "Host: example.com",
        "Connection: close"
    ]

    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    return request.encode("utf-8")

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    # Print the raw bytes as a hexadecimal string
    print(payload.hex())
# EVOLVE-BLOCK-END
