# EVOLVE-BLOCK-START
"""
Method-Token Layout Anomaly - Adds extra spaces after the HTTP method token (e.g., 'GET  /')
to desynchronize middleboxes that strictly tokenize methods while remaining acceptable to tolerant servers.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    # Use a slightly malformed but widely accepted request line: double space after method
    request_line = f"GET  {path} HTTP/1.1\r\n"

    # Keep a simple Host header using the forbidden hostname directly, with spacing anomaly
    host_header = f"Host:   {host}"

    headers = [host_header, "Connection: close"]

    # Preserve leading CRLF for parser state desync
    request = "\r\n" + request_line + "\r\n".join(headers) + "\r\n\r\n"
    return request.encode("utf-8")

if __name__ == "__main__":
    print(generate_http_request("pornhub.com").hex())
# EVOLVE-BLOCK-END
