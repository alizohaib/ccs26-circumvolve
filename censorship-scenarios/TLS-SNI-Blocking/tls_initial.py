# EVOLVE-BLOCK-START
"""
Utility module for crafting TLS Client Hello packets.
"""


def build_packet(hostname) -> bytes:
    """Construct a deterministic TLS 1.3 ClientHello message."""

    def _ext(ext_type: int, body: bytes) -> bytes:
        return ext_type.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body

    content_type = b"\x16"  # Handshake
    tls_outer_version = b"\x03\x01"  # TLS 1.0 for compatibility
    handshake_type = b"\x01"  # Client Hello

    legacy_version = b"\x03\x03"
    random = bytes(range(32))
    session_id = b""
    cipher_suites = [
        0x1301,  # TLS_AES_128_GCM_SHA256
        0x1302,  # TLS_AES_256_GCM_SHA384
        0x1303,  # TLS_CHACHA20_POLY1305_SHA256
    ]
    cipher_suite_bytes = b"".join(cs.to_bytes(2, "big") for cs in cipher_suites)
    compression_methods = b"\x01\x00"  # null compression only

    # TLS extensions
    extensions = []

    # Server Name Indication
    # host_name = "blocked.com" # Blocked domain
    server_name = b"\x00" + len(hostname).to_bytes(2, "big") + bytes(hostname, "utf-8")
    server_name_list = len(server_name).to_bytes(2, "big") + server_name
    extensions.append(_ext(0x0000, server_name_list))

    # Supported Groups (elliptic curves)
    groups = [0x001d, 0x0017, 0x0018]  # x25519, secp256r1, secp384r1
    group_bytes = b"".join(group.to_bytes(2, "big") for group in groups)
    extensions.append(_ext(0x000A, len(group_bytes).to_bytes(2, "big") + group_bytes))

    # Signature Algorithms
    signature_algorithms = [
        0x0403,  # ecdsa_secp256r1_sha256
        0x0804,  # rsa_pss_pss_sha256
        0x0805,  # rsa_pss_pss_sha384
        0x0806,  # rsa_pss_pss_sha512
        0x0503,  # rsa_pss_rsae_sha256
        0x0603,  # rsa_pss_rsae_sha384
    ]
    sig_alg_bytes = b"".join(sa.to_bytes(2, "big") for sa in signature_algorithms)
    extensions.append(
        _ext(0x000D, len(sig_alg_bytes).to_bytes(2, "big") + sig_alg_bytes)
    )

    # Supported Versions (TLS 1.3)
    extensions.append(_ext(0x002B, b"\x02\x03\x04"))

    # PSK Key Exchange Modes (psk_dhe_ke)
    extensions.append(_ext(0x002D, b"\x01\x01"))

    # Key Share (x25519 with deterministic key material)
    key_exchange = bytes(
        [
            0x3a,
            0xde,
            0x68,
            0xec,
            0xf9,
            0x12,
            0x9e,
            0x0a,
            0x9c,
            0x21,
            0x68,
            0xe3,
            0x9a,
            0x27,
            0x24,
            0x44,
            0x0c,
            0xcb,
            0x0c,
            0x8f,
            0x13,
            0x4c,
            0x5e,
            0xf3,
            0xdb,
            0x37,
            0xb2,
            0x8b,
            0xf1,
            0xc1,
            0x68,
            0x11,
        ]
    )
    share_entry = (
        0x001D.to_bytes(2, "big")
        + len(key_exchange).to_bytes(2, "big")
        + key_exchange
    )
    extensions.append(
        _ext(0x0033, len(share_entry).to_bytes(2, "big") + share_entry)
    )

    # Application Layer Protocol Negotiation (HTTP/2)
    alpn_protocols = b"\x02h2"
    extensions.append(
        _ext(0x0010, len(alpn_protocols).to_bytes(2, "big") + alpn_protocols)
    )

    extensions_bytes = b"".join(extensions)
    extensions_length = len(extensions_bytes).to_bytes(2, "big")

    client_hello_body = (
        legacy_version
        + random
        + len(session_id).to_bytes(1, "big")
        + session_id
        + len(cipher_suite_bytes).to_bytes(2, "big")
        + cipher_suite_bytes
        + compression_methods
        + extensions_length
        + extensions_bytes
    )

    body_length = len(client_hello_body).to_bytes(3, "big")

    return content_type + tls_outer_version + len(handshake_type + body_length + client_hello_body).to_bytes(2, "big") + handshake_type + body_length + client_hello_body


def run() -> bytes:
    hostname = "blocked.com"
    packet = build_packet(hostname)

    print(packet.hex())
    return packet


if __name__ == '__main__':
    run()

# EVOLVE-BLOCK-END
