# EVOLVE-BLOCK-START
"""
Strategy: Fake Session Resumption (Corrected).
Includes PSK Key Exchange Modes and Key Share to be valid TLS 1.3.
"""

def build_packet(hostname) -> bytes:
    def _ext(ext_type: int, body: bytes) -> bytes:
        return ext_type.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body

    content_type = b"\x16"
    tls_outer_version = b"\x03\x01"
    handshake_type = b"\x01"
    legacy_version = b"\x03\x03"
    random_bytes = bytes(range(32))
    
    # 1. [INNOVATION] Fake Session ID (32 bytes)
    # Makes it look like resumption
    session_id = b"\xBB" * 32
    
    cipher_suites = [0x1301, 0x1302]
    cipher_suite_bytes = b"".join(cs.to_bytes(2, "big") for cs in cipher_suites)
    compression_methods = b"\x01\x00"

    extensions = []

    # 2. SNI
    # host = "blocked.com"
    server_name = b"\x00" + len(hostname).to_bytes(2, "big") + bytes(hostname, "utf-8")
    server_name_list = len(server_name).to_bytes(2, "big") + server_name
    extensions.append(_ext(0x0000, server_name_list))

    # 3. Standard 1.3 extensions
    extensions.append(_ext(0x000A, b"\x00\x02\x00\x1D")) # Groups: x25519
    extensions.append(_ext(0x000D, b"\x00\x02\x04\x03")) # Sigs: ecdsa_secp256r1
    extensions.append(_ext(0x002B, b"\x02\x03\x04"))     # Versions: 1.3

    # 4. PSK Key Exchange Modes (Type 45 / 0x2D)
    # Required when offering resumption capability
    # 0x01 (PskKeMode) -> 0x01 (psk_dhe_ke)
    extensions.append(_ext(0x002D, b"\x01\x01"))

    # 5. Key Share
    share_data = b"\x00\x1D\x00\x20" + bytes([0xCC]*32)
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

    return content_type + tls_outer_version + len(full_msg).to_bytes(2, "big") + full_msg

if __name__ == '__main__':
    hostname = "blocked.com"
    packet = build_packet(hostname)
    print(packet.hex())
# EVOLVE-BLOCK-END
