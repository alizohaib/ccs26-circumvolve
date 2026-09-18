# EVOLVE-BLOCK-START
"""
Strategy: Buffer Exhaustion via RFC 7685 Padding (Corrected).
Includes all mandatory TLS 1.3 extensions to ensure the server accepts the handshake
after parsing the massive padding.
"""

def build_packet(hostname) -> bytes:
    def _ext(ext_type: int, body: bytes) -> bytes:
        return ext_type.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body

    # Header constants
    content_type = b"\x16"
    tls_outer_version = b"\x03\x01" # Legacy 1.0 for compatibility
    handshake_type = b"\x01" 
    legacy_version = b"\x03\x03"    # Legacy 1.2
    random_bytes = bytes(range(32))
    session_id = b""
    cipher_suites = [0x1302, 0x1301, 0x1303] # TLS_AES_256_GCM_SHA384 first
    cipher_suite_bytes = b"".join(cs.to_bytes(2, "big") for cs in cipher_suites)
    compression_methods = b"\x01\x00"

    extensions = []

    # 1. [INNOVATION] Massive Padding (Type 21)
    # 2500 bytes of zeros to flush the DPI buffer
    extensions.append(_ext(0x0015, b"\x00" * 2500))

    # 2. Server Name Indication (SNI)
    server_name = b"\x00" + len(hostname).to_bytes(2, "big") + bytes(hostname, "utf-8")
    server_name_list = len(server_name).to_bytes(2, "big") + server_name
    extensions.append(_ext(0x0000, server_name_list))

    # 3. Supported Groups (Curve25519, etc.)
    groups = [0x001d, 0x0017, 0x0018]
    group_bytes = b"".join(group.to_bytes(2, "big") for group in groups)
    extensions.append(_ext(0x000A, len(group_bytes).to_bytes(2, "big") + group_bytes))

    # 4. Signature Algorithms (RSA-PSS, ECDSA)
    sigs = [0x0403, 0x0804, 0x0401, 0x0503]
    sig_bytes = b"".join(s.to_bytes(2, "big") for s in sigs)
    extensions.append(_ext(0x000D, len(sig_bytes).to_bytes(2, "big") + sig_bytes))

    # 5. Supported Versions (TLS 1.3 only)
    extensions.append(_ext(0x002B, b"\x02\x03\x04"))
    
    # 6. Key Share (Crucial for TLS 1.3)
    # Sending a dummy X25519 public key (32 bytes)
    dummy_key = bytes([0xAA] * 32)
    # Group: x25519 (0x001D) | Len: 32 | Key...
    share_data = b"\x00\x1D\x00\x20" + dummy_key
    extensions.append(_ext(0x0033, len(share_data).to_bytes(2, "big") + share_data))

    # Build Body
    extensions_bytes = b"".join(extensions)
    extensions_length = len(extensions_bytes).to_bytes(2, "big")

    client_hello_body = (
        legacy_version + random_bytes + len(session_id).to_bytes(1, "big") + session_id
        + len(cipher_suite_bytes).to_bytes(2, "big") + cipher_suite_bytes
        + compression_methods + extensions_length + extensions_bytes
    )

    body_length = len(client_hello_body).to_bytes(3, "big")
    full_msg = handshake_type + body_length + client_hello_body

    return content_type + tls_outer_version + len(full_msg).to_bytes(2, "big") + full_msg

if __name__ == '__main__':
    hostname = "blocked.com"
    packet = build_packet(hostname)
    print(packet.hex())
# EVOLVE-BLOCK-END
