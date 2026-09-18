# EVOLVE-BLOCK-START
"""
Strategy: GREASE & Chrome Mimicry.
Injects reserved 'GREASE' values (0x?A?A) into Ciphers, Groups, and Extensions.
This makes the fingerprint look like a real Chrome browser, forcing DPIs 
to apply 'safe' whitelisting logic.
Includes a VALID X25519 Public Key to prevent Handshake Failure.
"""

def build_packet(hostname) -> bytes:
    def _ext(ext_type: int, body: bytes) -> bytes:
        return ext_type.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body

    # --- Header ---
    content_type = b"\x16"
    tls_outer_version = b"\x03\x01" # TLS 1.0 record (standard for 1.3)
    handshake_type = b"\x01"
    legacy_version = b"\x03\x03"    # TLS 1.2
    
    # Random (standard)
    import os
    random_bytes = os.urandom(32)
    
    # Session ID (32 bytes required for middlebox compatibility)
    session_id = os.urandom(32)

    # --- Cipher Suites (With GREASE) ---
    # 0x1A1A is a GREASE value. 0x1301/02/03 are standard TLS 1.3
    cipher_suites = [0x1A1A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]
    cipher_suite_bytes = b"".join(cs.to_bytes(2, "big") for cs in cipher_suites)
    compression_methods = b"\x01\x00"

    extensions = []

    # 1. GREASE Extension (0x1A1A) - Empty body
    extensions.append(_ext(0x1A1A, b""))

    # 2. Server Name Indication (SNI)
    # host = "blocked.com"
    server_name = b"\x00" + len(hostname).to_bytes(2, "big") + bytes(hostname, "utf-8")
    server_name_list = len(server_name).to_bytes(2, "big") + server_name
    extensions.append(_ext(0x0000, server_name_list))

    # 3. Supported Groups (With GREASE 0x1A1A)
    # 0x001D = X25519, 0x0017 = secp256r1
    groups = [0x1A1A, 0x001D, 0x0017]
    group_bytes = b"".join(g.to_bytes(2, "big") for g in groups)
    extensions.append(_ext(0x000A, len(group_bytes).to_bytes(2, "big") + group_bytes))

    # 4. Signature Algorithms
    sigs = [0x0403, 0x0804, 0x0401, 0x0503]
    sig_bytes = b"".join(s.to_bytes(2, "big") for s in sigs)
    extensions.append(_ext(0x000D, len(sig_bytes).to_bytes(2, "big") + sig_bytes))

    # 5. Supported Versions (TLS 1.3)
    extensions.append(_ext(0x002B, b"\x02\x03\x04"))

    # 6. Key Share (CRITICAL: MUST BE VALID KEY)
    # This is a pre-calculated valid X25519 public key.
    # If this is random garbage, the server rejects the handshake.
    valid_pub_key = bytes.fromhex("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")
    
    # Group: x25519 (0x001D) | Len: 32 | Key...
    # Note: We also inject a GREASE key share (0x1A1A) to match Chrome
    share_data = (
        b"\x1A\x1A\x00\x01\x00" + # GREASE Key Share
        b"\x00\x1D\x00\x20" + valid_pub_key # Real Key Share
    )
    extensions.append(_ext(0x0033, len(share_data).to_bytes(2, "big") + share_data))
    
    # 7. PSK Key Exchange Modes (Required for 1.3)
    extensions.append(_ext(0x002D, b"\x01\x01"))

    # Compile
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
