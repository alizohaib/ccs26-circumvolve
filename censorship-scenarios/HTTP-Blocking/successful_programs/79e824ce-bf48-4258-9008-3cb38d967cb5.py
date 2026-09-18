# EVOLVE-BLOCK-START
"""
Header Layout Anomaly - Adds irregular spacing after 'Host:' and around the value.
Intended to confuse simplistic DPI tokenization of the Host header while remaining HTTP/1.1 compliant.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    # Standard request line, keep it simple/valid
    request_line = f"GET {path} HTTP/1.1\r\n"

    # Introduce abnormal spacing in Host header while remaining parseable:
    # - Extra spaces after colon
    # - Surround host with spaces (trimmed by many servers)
    host_header = f"Host:   {host}   "

    headers = [
        host_header,
        "Connection: close"
    ]

    # Keep the leading CRLF state-desync behavior from the previous best program
    request = "\r\n" + request_line + "\r\n".join(headers) + "\r\n\r\n"
    return request.encode("utf-8")

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
