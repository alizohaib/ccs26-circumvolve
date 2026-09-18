# EVOLVE-BLOCK-START
"""
Strategy: TLS Record Fragmentation (Corrected).
Ensures the internal Handshake message is valid (with KeyShare/Versions) 
before splitting it into two records.
"""

def build_packet(hostname) -> bytes:
    def _ext(ext_type: int, body: bytes) -> bytes:
        return ext_type.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body

    content_type = b"\x16"
    # Use a more typical outer record version (03 03) while keeping the anomaly
    tls_outer_version = b"\x03\x03"
    handshake_type = b"\x01"
    legacy_version = b"\x03\x03"
    random_bytes = bytes(range(32))
    session_id = b""
    cipher_suites = [0x1301]
    cipher_suite_bytes = b"".join(cs.to_bytes(2, "big") for cs in cipher_suites)
    compression_methods = b"\x01\x00"

    extensions = []
    
    # 1. SNI
    # host = "cloudflare.com"
    server_name = b"\x00" + len(hostname).to_bytes(2, "big") + bytes(hostname, "utf-8")
    server_name_list = len(server_name).to_bytes(2, "big") + server_name
    extensions.append(_ext(0x0000, server_name_list))

    # 2. Mandatory Extensions
    extensions.append(_ext(0x000A, b"\x00\x02\x00\x1D")) 
    extensions.append(_ext(0x000D, b"\x00\x02\x04\x03"))
    extensions.append(_ext(0x002B, b"\x02\x03\x04"))
    
    # 3. Key Share
    share_data = b"\x00\x1D\x00\x20" + bytes([0xEE]*32)
    extensions.append(_ext(0x0033, len(share_data).to_bytes(2, "big") + share_data))

    extensions_bytes = b"".join(extensions)
    extensions_length = len(extensions_bytes).to_bytes(2, "big")

    client_hello_body = (
        legacy_version + random_bytes + len(session_id).to_bytes(1, "big") + session_id
        + len(cipher_suite_bytes).to_bytes(2, "big") + cipher_suite_bytes
        + compression_methods + extensions_length + extensions_bytes
    )
    
    body_len = len(client_hello_body).to_bytes(3, "big")
    full_msg = handshake_type + body_len + client_hello_body

    # [INNOVATION] Fragmentation with structurally aligned split:
    # Put the ClientHello header and cipher_suites in the first record,
    # and move the extensions (including SNI) to the second record.
    #
    # Layout of client_hello_body:
    #   legacy_version (2)
    #   random (32)
    #   session_id_len (1) + session_id (0)
    #   cipher_suites_len (2) + cipher_suites (len(cipher_suite_bytes))
    #   compression_methods (2)
    #   extensions_length (2) + extensions_bytes (...)
    #
    # We compute the offset right before extensions_length and split there.
    base = 2 + 32 + 1  # legacy_version + random + session_id_len (session_id is empty)
    cs_section = 2 + len(cipher_suite_bytes)  # cipher_suites_len + cipher_suites
    compression_len = 2  # compression_methods
    header_without_ext = base + cs_section + compression_len

    # full_msg = handshake_type (1) + body_len (3) + client_hello_body
    # So extensions start at offset: 1 + 3 + header_without_ext
    split_point = 1 + 3 + header_without_ext

    part1 = full_msg[:split_point]
    part2 = full_msg[split_point:]

    record1 = content_type + tls_outer_version + len(part1).to_bytes(2, "big") + part1
    record2 = content_type + tls_outer_version + len(part2).to_bytes(2, "big") + part2

    return record1 + record2

if __name__ == '__main__':
    hostname = "cloudflare.com"
    packet = build_packet(hostname)
    print(packet.hex())
# EVOLVE-BLOCK-END
