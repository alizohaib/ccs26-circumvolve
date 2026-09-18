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
    tls_outer_version = b"\x03\x01"
    handshake_type = b"\x01"
    legacy_version = b"\x03\x03"
    random_bytes = bytes(range(32))
    session_id = b""
    cipher_suites = [0x1301]
    cipher_suite_bytes = b"".join(cs.to_bytes(2, "big") for cs in cipher_suites)
    compression_methods = b"\x01\x00"

    extensions = []
    
    # 1. SNI
    # host = "blocked.com"
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

    # [INNOVATION] Split logic
    # Split middle of cipher suites or extensions
    split_point = 50 
    
    part1 = full_msg[:split_point]
    part2 = full_msg[split_point:]

    record1 = content_type + tls_outer_version + len(part1).to_bytes(2, "big") + part1
    record2 = content_type + tls_outer_version + len(part2).to_bytes(2, "big") + part2

    return record1 + record2

if __name__ == '__main__':
    hostname = "blocked.com"
    packet = build_packet(hostname)
    print(packet.hex())
# EVOLVE-BLOCK-END
