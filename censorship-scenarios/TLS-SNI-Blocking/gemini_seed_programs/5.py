# EVOLVE-BLOCK-START
"""
Strategy: Extension Re-Ordering.
Moves the SNI extension to the very end of the list (just before PSK would be).
Places Key Share, Groups, and Sigs FIRST.
Exploits lazy DPI parsers that expect SNI to be the first extension.
"""

def build_packet(hostname) -> bytes:
    def _ext(ext_type: int, body: bytes) -> bytes:
        return ext_type.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body

    content_type = b"\x16"
    tls_outer_version = b"\x03\x01"
    handshake_type = b"\x01" 
    legacy_version = b"\x03\x03"
    import os
    random_bytes = os.urandom(32)
    session_id = os.urandom(32)
    
    cipher_suites = [0x1301, 0x1302, 0x1303]
    cipher_suite_bytes = b"".join(cs.to_bytes(2, "big") for cs in cipher_suites)
    compression_methods = b"\x01\x00"

    extensions = []

    # 1. Put Bulky Extensions FIRST
    
    # Supported Groups
    extensions.append(_ext(0x000A, b"\x00\x02\x00\x1D")) 
    
    # Key Share (Valid Key)
    valid_pub_key = bytes.fromhex("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")
    share_data = b"\x00\x1D\x00\x20" + valid_pub_key
    extensions.append(_ext(0x0033, len(share_data).to_bytes(2, "big") + share_data))

    # Supported Versions
    extensions.append(_ext(0x002B, b"\x02\x03\x04"))
    
    # Signature Algos
    extensions.append(_ext(0x000D, b"\x00\x02\x04\x03"))
    
    # PSK Modes
    extensions.append(_ext(0x002D, b"\x01\x01"))

    # 2. Finally, put SNI LAST
    # host = "blocked.com"
    server_name = b"\x00" + len(hostname).to_bytes(2, "big") + bytes(hostname, "utf-8")
    server_name_list = len(server_name).to_bytes(2, "big") + server_name
    extensions.append(_ext(0x0000, server_name_list))

    # Build
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
