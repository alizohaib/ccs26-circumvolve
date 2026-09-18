# EVOLVE-BLOCK-START
"""
Strategy: Case-Permuted SNI (Corrected).
Includes Key Share and Supported Groups.
"""
import random

def build_packet(hostname) -> bytes:
    def _ext(ext_type: int, body: bytes) -> bytes:
        return ext_type.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body

    content_type = b"\x16"
    tls_outer_version = b"\x03\x01"
    handshake_type = b"\x01"
    legacy_version = b"\x03\x03"
    random_bytes = bytes(range(32))
    session_id = b""
    cipher_suites = [0x1301, 0x1302]
    cipher_suite_bytes = b"".join(cs.to_bytes(2, "big") for cs in cipher_suites)
    compression_methods = b"\x01\x00"

    extensions = []

    # 1. [INNOVATION] Case Permutation
    # target_host = "blocked.com"
    random.seed(42)
    mixed_case = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in hostname)
    
    server_name = b"\x00" + len(mixed_case).to_bytes(2, "big") + bytes(mixed_case, "utf-8")
    server_name_list = len(server_name).to_bytes(2, "big") + server_name
    extensions.append(_ext(0x0000, server_name_list))

    # 2. Supported Groups
    groups = [0x001d, 0x0017] 
    group_bytes = b"".join(g.to_bytes(2, "big") for g in groups)
    extensions.append(_ext(0x000A, len(group_bytes).to_bytes(2, "big") + group_bytes))

    # 3. Signature Algorithms
    sigs = [0x0403, 0x0804]
    sig_bytes = b"".join(s.to_bytes(2, "big") for s in sigs)
    extensions.append(_ext(0x000D, len(sig_bytes).to_bytes(2, "big") + sig_bytes))

    # 4. Supported Versions (TLS 1.3)
    extensions.append(_ext(0x002B, b"\x02\x03\x04"))

    # 5. Key Share (Dummy x25519)
    share_data = b"\x00\x1D\x00\x20" + bytes([0xAB]*32)
    extensions.append(_ext(0x0033, len(share_data).to_bytes(2, "big") + share_data))

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
