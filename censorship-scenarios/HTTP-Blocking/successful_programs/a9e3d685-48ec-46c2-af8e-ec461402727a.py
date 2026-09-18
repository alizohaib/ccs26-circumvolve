# EVOLVE-BLOCK-START
"""
HOST_LWS_TRAILING_HT - Append HT to end of Host header value.
Hypothesis: some DPI matchers use strict Host value comparisons, while origin servers tolerate/trim trailing LWS.
"""


def generate_http_request(host: str = "blocked.com", path: str = "/") -> bytes:
    """
    Generate HTTP request with tab character at end of Host value.
    
    Args:
        host: Target host for the Host header
        path: URL path to request
    
    Returns:
        Raw HTTP request bytes
    """
    # Keep request-line strictly standard to avoid 400s from strict parsers.
    request_line = f"GET {path} HTTP/1.1\r\n"

    # Keep headers minimal to reduce rejection risk and meet <500 char hint.
    # Also keep forbidden keyword visible in raw bytes (Host contains it).
    ht = "\t"
    headers = [
        f"Host: {host}{ht}",  # LWS at end of value
        "Connection: close",
    ]
    
    # Combine into full request
    # HTTP requests end with double CRLF
    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    
    # latin-1 preserves raw control bytes 0x00-0xff exactly
    return request.encode('latin-1')


if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com", path="/")
    print(payload.hex())

# EVOLVE-BLOCK-END
