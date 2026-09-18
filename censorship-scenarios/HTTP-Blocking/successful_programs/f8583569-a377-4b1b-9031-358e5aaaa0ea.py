# EVOLVE-BLOCK-START
"""
Case-Obfuscated + Folded Host – Use non‑canonical casing for the Host field-name and
obsolete line folding so tolerant servers still parse it while simple DPI that
look for 'Host:' on one line miss the forbidden hostname.
"""

def generate_http_request(host: str = "pornhub.com", path: str = "/") -> bytes:
    # Simple relative-form target; origin must consult the (folded) Host header.
    request_line = f"GET {path} HTTP/1.1\r\n"
    # Non-standard casing for 'Host' plus obsolete folding with the value on the next indented line.
    headers = [
        "HoSt:\r\n " + host,
        "Connection: close"
    ]
    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    return request.encode("ascii")

if __name__ == "__main__":
    payload = generate_http_request(host="pornhub.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
