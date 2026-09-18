# EVOLVE-BLOCK-START
"""
Strategy: Fake TLS 1.3 Resumption (PSK Spoofing).
Appends a 'pre_shared_key' extension (Type 41) with garbage data at the end of the ClientHello.
1. DPI sees Type 41 -> Assumes Session Resumption -> Skips SNI check.
2. Server fails to decrypt fake ticket -> Falls back to Full Handshake (RFC 8446) -> Connection Succeeds.
"""
import os
import struct

def build_packet(hostname) -> bytes:
    def _ext(ext_type: int, body: bytes) -> bytes:
        return ext_type.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body

    # --- Header ---
    content_type = b"\x16"
    tls_outer_version = b"\x03\x01" 
    handshake_type = b"\x01"
    legacy_version = b"\x03\x03"    
    random_bytes = os.urandom(32)
    session_id = os.urandom(32) # Legacy Session ID (random)

    cipher_suites = [0x1301, 0x1302, 0x1303]
    cipher_suite_bytes = b"".join(cs.to_bytes(2, "big") for cs in cipher_suites)
    compression_methods = b"\x01\x00"

    extensions = []

    # 1. Server Name Indication
    # host = "blocked.com"
    server_name = b"\x00" + len(hostname).to_bytes(2, "big") + bytes(hostname, "utf-8")
    server_name_list = len(server_name).to_bytes(2, "big") + server_name
    extensions.append(_ext(0x0000, server_name_list))

    # 2. Mandatory Extensions
    extensions.append(_ext(0x000A, b"\x00\x02\x00\x1D")) # Groups (x25519)
    extensions.append(_ext(0x000D, b"\x00\x02\x04\x03")) # Sigs (ecdsa_secp256r1_sha256)
    extensions.append(_ext(0x002B, b"\x02\x03\x04"))     # Versions (1.3)
    extensions.append(_ext(0x002D, b"\x01\x01"))         # PSK Modes (psk_dhe_ke)

    # 3. Key Share (Valid Key - Essential for Fallback)
    # We must provide a valid key so when the server falls back, it can negotiate.
    valid_pub_key = bytes.fromhex("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")
    share_data = b"\x00\x1D\x00\x20" + valid_pub_key
    extensions.append(_ext(0x0033, len(share_data).to_bytes(2, "big") + share_data))

    # 4. [INNOVATION] Fake Pre-Shared Key (Type 41)
    # This extension MUST be the last one in the ClientHello.
    # Structure:
    #   Identity List Length (2 bytes)
    #     Identity 1:
    #       Length (2 bytes) | Ticket Data (opaque) | Obfuscated Ticket Age (4 bytes)
    #   Binder List Length (2 bytes)
    #     Binder 1:
    #       Length (1 byte) | HMAC (opaque)
    
    # Construct Fake Identity (The "Ticket")
    fake_ticket = os.urandom(128) # 128 bytes of garbage
    ticket_age = struct.pack(">I", 123456) # Random age
    
    identity_entry = len(fake_ticket).to_bytes(2, "big") + fake_ticket + ticket_age
    identities_list = len(identity_entry).to_bytes(2, "big") + identity_entry
    
    # Construct Fake Binder (The "Hash")
    # Usually SHA-256 (32 bytes)
    fake_binder = os.urandom(32)
    binder_entry = len(fake_binder).to_bytes(1, "big") + fake_binder
    binders_list = len(binder_entry).to_bytes(2, "big") + binder_entry
    
    psk_body = identities_list + binders_list
    extensions.append(_ext(0x0029, psk_body))

    # --- Compile ---
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
