# EVOLVE-BLOCK-START
"""
Strategy: OVERSIZE_RECORDS with late SNI placement.
Create a single, very large TLS record so the SNI appears later in the record
(and likely in a later TCP segment), while keeping a valid TLS 1.3-style ClientHello.
"""

def build_packet(hostname) -> bytes:
    def _ext(ext_type: int, body: bytes) -> bytes:
        return ext_type.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body

    content_type = b"\x16"
    tls_outer_version = b"\x03\x03"         # Use TLS 1.2 outer record version (common in TLS 1.3)
    handshake_type = b"\x01"               # client_hello
    legacy_version = b"\x03\x03"           # TLS 1.2 in ClientHello
    random_bytes = bytes(range(32))
    session_id = b""
    cipher_suites = [0x1301]
    cipher_suite_bytes = b"".join(cs.to_bytes(2, "big") for cs in cipher_suites)
    compression_methods = b"\x01\x00"

    extensions = []

    # 1. Oversize padding extension placed BEFORE SNI.
    #    Large but modest (~8 KB) to ensure it fits in a single record and is accepted.
    oversize_len = 8192
    padding_body = b"\x00" * oversize_len
    extensions.append(_ext(0x0015, padding_body))  # extension_type = padding (21)

    # 2. SNI extension after the large padding.
    server_name = b"\x00" + len(hostname).to_bytes(2, "big") + bytes(hostname, "utf-8")
    server_name_list = len(server_name).to_bytes(2, "big") + server_name
    extensions.append(_ext(0x0000, server_name_list))

    # 3. Mandatory TLS 1.3-related extensions.
    # supported_groups
    extensions.append(_ext(0x000A, b"\x00\x02\x00\x1D"))
    # signature_algorithms
    extensions.append(_ext(0x000D, b"\x00\x02\x04\x03"))
    # supported_versions (TLS 1.3)
    extensions.append(_ext(0x002B, b"\x02\x03\x04"))
    # key_share
    share_data = b"\x00\x1D\x00\x20" + bytes([0xEE] * 32)
    extensions.append(_ext(0x0033, len(share_data).to_bytes(2, "big") + share_data))

    extensions_bytes = b"".join(extensions)
    extensions_length = len(extensions_bytes).to_bytes(2, "big")

    client_hello_body = (
        legacy_version
        + random_bytes
        + len(session_id).to_bytes(1, "big") + session_id
        + len(cipher_suite_bytes).to_bytes(2, "big") + cipher_suite_bytes
        + compression_methods
        + extensions_length + extensions_bytes
    )

    body_len = len(client_hello_body).to_bytes(3, "big")
    full_msg = handshake_type + body_len + client_hello_body

    # Single oversized record containing the whole ClientHello.
    record = content_type + tls_outer_version + len(full_msg).to_bytes(2, "big") + full_msg
    return record

if __name__ == '__main__':
    hostname = "cloudflare.com"
    packet = build_packet(hostname)
    print(packet.hex())
# EVOLVE-BLOCK-END
