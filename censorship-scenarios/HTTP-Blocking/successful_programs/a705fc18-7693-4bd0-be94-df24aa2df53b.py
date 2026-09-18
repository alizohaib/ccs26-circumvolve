# EVOLVE-BLOCK-START
"""
[Category: Request-Line Anomalies] - Absolute-URL + Host Mismatch
Use an absolute-form request-line with the forbidden domain while giving
the Host header a benign value, relying on origin servers to trust Host
and naïve DPI to key off the request-line URL.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    # HTTP/1.1 allows absolute-form in proxies; many origin servers still accept it.
    # Put the censored domain only in the request-line, not in the Host header.
    request_line = f"GET http://{host}{path} HTTP/1.1\r\n"

    # Safe-looking host for the Host header (what the server will actually route on)
    benign_host = "safe-cdn.local"

    headers = [
        f"Host: {benign_host}",
        "Connection: close"
    ]

    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    return request.encode("ascii")

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
