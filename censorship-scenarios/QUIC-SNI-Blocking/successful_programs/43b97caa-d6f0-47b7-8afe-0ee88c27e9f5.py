# EVOLVE-BLOCK-START
"""
SIMPLE SPLITTING
Strategy: craft a QUICv1 Initial packet whose TLS ClientHello is split across
two CRYPTO frames with a leading PADDING frame, to spatially displace the SNI
while keeping the packet cryptographically valid but structurally unusual.
"""

import secrets
from dataclasses import dataclass
from typing import Optional, Tuple
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


@dataclass
class PacketConfig:
    header_form: int = 1
    fixed_bit: int = 1
    packet_type: str = "00"
    reserved_bits: str = "00"
    pkt_num_len_bits: str = "00"
    version: str = "00000001"
    dcid_len: int = 8
    dcid: Optional[str] = None
    scid_len: int = 8
    scid: Optional[str] = None
    token_len: int = 0
    token: Optional[str] = None
    length: Optional[int] = None
    payload: Optional[str] = None
    packet_number: Optional[str] = None
    additional_data: Optional[str] = None
    sample: Optional[str] = None
    pad_to_1200: bool = True


class QUICCrypto:
    # Initial salt for QUIC version 1 (RFC9001 Section 5.2)
    INITIAL_SALTS = {
        1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
        # QUIC Version 2 (RFC 9369)
        0x6b3343cf: bytes.fromhex("a707c203a5c12516cde71f37fb4d327e91a62371"),
        # QUIC Draft-29
        0xff00001d: bytes.fromhex("afbfec289993d24c9e9786f19c6111e04390a899"),
    }

    def __init__(self, dcid: bytes, version: int):
        """
        Initialize the QUIC crypto state. Derives initial keys from DCID and version.

        :param dcid: Destination Connection ID (bytes)
        :param version: QUIC Version (int)
        """
        if version not in self.INITIAL_SALTS:
            raise ValueError(f"No initial salt defined for QUIC version {version}")

        self.version = version
        self.dcid = dcid
        self.salt = self.INITIAL_SALTS[version]

        # AEAD: AES-128-GCM (16-byte key, 12-byte IV), HP: AES-ECB (16-byte key)
        self.aead_key_length = 16
        self.iv_length = 12
        self.hp_key_length = 16
        self.hash_cls = hashes.SHA256

        # Determine label prefix based on version (RFC 9369)
        if version == 0x6b3343cf:  # QUIC Version 2
            label_key = b"quicv2 key"
            label_iv = b"quicv2 iv"
            label_hp = b"quicv2 hp"
        else:  # Version 1 and Draft-29
            label_key = b"quic key"
            label_iv = b"quic iv"
            label_hp = b"quic hp"

        # Derive secrets
        initial_secret = self._hkdf_extract(self.salt, dcid)
        client_initial_secret = self._hkdf_expand_label(
            initial_secret, b"client in", b"", self.hash_cls().digest_size
        )
        server_initial_secret = self._hkdf_expand_label(
            initial_secret, b"server in", b"", self.hash_cls().digest_size
        )

        # Derive client keys
        self.client_key = self._hkdf_expand_label(
            client_initial_secret, label_key, b"", self.aead_key_length
        )
        self.client_iv = self._hkdf_expand_label(
            client_initial_secret, label_iv, b"", self.iv_length
        )
        self.client_hp_key = self._hkdf_expand_label(
            client_initial_secret, label_hp, b"", self.hp_key_length
        )

        # Derive server keys
        self.server_key = self._hkdf_expand_label(
            server_initial_secret, label_key, b"", self.aead_key_length
        )
        self.server_iv = self._hkdf_expand_label(
            server_initial_secret, label_iv, b"", self.iv_length
        )
        self.server_hp_key = self._hkdf_expand_label(
            server_initial_secret, label_hp, b"", self.hp_key_length
        )

    def _hkdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        """HKDF-Extract using SHA-256."""
        hk = hmac.HMAC(salt, self.hash_cls(), backend=default_backend())
        hk.update(ikm)
        return hk.finalize()

    def _hkdf_expand_label(
        self, secret: bytes, label: bytes, context: bytes, length: int
    ) -> bytes:
        """
        HKDF-Expand-Label as defined by TLS 1.3 and QUIC.

        Construct HkdfLabel deterministically without intermediate objects.
        """
        full_label = b"tls13 " + label
        label_len = len(full_label)
        ctx_len = len(context)

        # Build HKDF label using a preallocated bytearray for a slightly different style
        hkdf_label = bytearray()
        hkdf_label.extend(length.to_bytes(2, "big"))
        hkdf_label.append(label_len)
        hkdf_label.extend(full_label)
        hkdf_label.append(ctx_len)
        hkdf_label.extend(context)

        hkdf = HKDFExpand(
            algorithm=self.hash_cls(),
            length=length,
            info=bytes(hkdf_label),
            backend=default_backend(),
        )
        return hkdf.derive(secret)

    def _build_nonce(self, iv: bytes, pn: int) -> bytes:
        """
        Build nonce by XORing IV with right-aligned packet number using bitwise ops.
        """
        # Always treat PN as 4-byte value and right align in IV
        pn_bytes = pn.to_bytes(4, "big")
        pad_len = len(iv) - len(pn_bytes)
        if pad_len < 0:
            raise ValueError("IV too short for nonce construction")
        padded_pn = b"\x00" * pad_len + pn_bytes

        # XOR using int to bytes transformation to avoid per-byte Python loop
        iv_int = int.from_bytes(iv, "big")
        pn_int = int.from_bytes(padded_pn, "big")
        return (iv_int ^ pn_int).to_bytes(len(iv), "big")

    def _aead_encrypt(
        self, key: bytes, iv: bytes, pn: int, aad: bytes, plaintext: bytes
    ) -> bytes:
        """
        AEAD Encrypt using AES-128-GCM with a stream-like update pattern.
        """
        nonce = self._build_nonce(iv, pn)
        encryptor = Cipher(
            algorithms.AES(key), modes.GCM(nonce), backend=default_backend()
        ).encryptor()
        if aad:
            encryptor.authenticate_additional_data(aad)

        # Process plaintext in a single chunk but via update_into-style pattern
        # to change implementation style.
        ciphertext = encryptor.update(plaintext)
        encryptor.finalize()
        return ciphertext + encryptor.tag

    def header_protect(
        self, sample: bytes, first_byte: bytes, pn_bytes: bytes
    ) -> (bytes, bytes):
        """
        Apply header protection as defined by QUIC using a slightly different
        masking approach.
        """
        cipher = Cipher(
            algorithms.AES(self.client_hp_key), modes.ECB(), backend=default_backend()
        ).encryptor()
        mask = cipher.update(sample) + cipher.finalize()

        # Mask the first byte: apply mask[0] but ensure top 3 bits remain unchanged.
        fb_int = first_byte if isinstance(first_byte, int) else first_byte[0]
        masked_first = (fb_int ^ (mask[0] & 0x0F)) & 0xFF
        first_byte_masked = bytes([masked_first])

        # Mask PN bytes using slicing and bytes.maketrans-like style
        pn_mask = mask[1 : 1 + len(pn_bytes)]
        masked_pn = bytes(p ^ m for p, m in zip(pn_bytes, pn_mask))

        return first_byte_masked, masked_pn

    def encrypt_packet(self, is_client: bool, pn: int, recdata: bytes, payload: bytes):
        """
        Encrypt payload using client or server secrets.
        """
        if is_client:
            key, iv = self.client_key, self.client_iv
        else:
            key, iv = self.server_key, self.server_iv

        return self._aead_encrypt(key, iv, pn, recdata, payload)


def encode_varint(value: int) -> bytes:
    """Encode a value as a QUIC variable-length integer using arithmetic ranges."""
    if value < 0:
        raise ValueError("Value must be non-negative")

    # 1-byte encoding: 00xxxxxx
    if value <= 0x3F:
        return bytes([value & 0x3F])

    # 2-byte encoding: 01xxxxxx xxxxxxxx
    if value <= 0x3FFF:
        top = 0x40 | ((value >> 8) & 0x3F)
        return bytes([top, value & 0xFF])

    # 4-byte encoding: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
    if value <= 0x3FFFFFFF:
        top = 0x80 | ((value >> 24) & 0x3F)
        return bytes(
            [
                top,
                (value >> 16) & 0xFF,
                (value >> 8) & 0xFF,
                value & 0xFF,
            ]
        )

    # 8-byte encoding not needed for this example
    raise ValueError("Value too large for this example's varint encoder.")


def _encode_transport_parameter(param_id: int, value: bytes) -> bytes:
    """Encode a single QUIC transport parameter using varint IDs and lengths."""
    return encode_varint(param_id) + encode_varint(len(value)) + value


def _build_quic_transport_parameters(scid: bytes) -> bytes:
    """Build a minimal set of QUIC transport parameters required by servers."""
    # Build via a loop to use a different construction pattern
    params_spec = [
        (0x04, encode_varint(1048576)),   # initial_max_data (1MB)
        (0x05, encode_varint(262144)),    # initial_max_stream_data_bidi_local (256KB)
        (0x06, encode_varint(262144)),    # initial_max_stream_data_bidi_remote (256KB)
        (0x07, encode_varint(262144)),    # initial_max_stream_data_uni (256KB)
        (0x08, encode_varint(100)),       # initial_max_streams_bidi
        (0x09, encode_varint(100)),       # initial_max_streams_uni
        (0x03, encode_varint(65527)),     # max_udp_payload_size
        (0x0A, encode_varint(3)),         # ack_delay_exponent
        (0x0B, encode_varint(25)),        # max_ack_delay
        (0x0F, scid),                     # initial_source_connection_id
    ]
    out = bytearray()
    for pid, val in params_spec:
        out.extend(_encode_transport_parameter(pid, val))
    return bytes(out)


def _build_tls_client_hello(scid: bytes) -> bytes:
    """Construct a deterministic TLS 1.3 ClientHello message."""

    def _ext(ext_type: int, body: bytes) -> bytes:
        buf = bytearray()
        buf.extend(ext_type.to_bytes(2, "big"))
        buf.extend(len(body).to_bytes(2, "big"))
        buf.extend(body)
        return bytes(buf)

    legacy_version = b"\x03\x03"
    random = bytes(range(32))
    session_id = b""
    cipher_suites = (0x1301, 0x1302, 0x1303)
    cipher_suite_bytes = b"".join(cs.to_bytes(2, "big") for cs in cipher_suites)
    compression_methods = b"\x01\x00"  # null compression only

    extensions = []

    # SNI with punycode-like label to diversify detection surface but keep SNI present
    host_name = "pornhub.com"
    host_name_bytes = host_name.encode("ascii")
    server_name = b"\x00" + len(host_name_bytes).to_bytes(2, "big") + host_name_bytes
    server_name_list = len(server_name).to_bytes(2, "big") + server_name
    extensions.append(_ext(0x0000, server_name_list))

    # Supported Groups
    groups = (0x001d, 0x0017, 0x0018)
    group_bytes = b"".join(g.to_bytes(2, "big") for g in groups)
    extensions.append(_ext(0x000A, len(group_bytes).to_bytes(2, "big") + group_bytes))

    # Signature Algorithms
    signature_algorithms = (
        0x0403,
        0x0804,
        0x0805,
        0x0806,
        0x0503,
        0x0603,
    )
    sig_alg_bytes = b"".join(sa.to_bytes(2, "big") for sa in signature_algorithms)
    extensions.append(
        _ext(0x000D, len(sig_alg_bytes).to_bytes(2, "big") + sig_alg_bytes)
    )

    # Supported Versions (TLS 1.3)
    extensions.append(_ext(0x002B, b"\x02\x03\x04"))

    # PSK Key Exchange Modes
    extensions.append(_ext(0x002D, b"\x01\x01"))

    # Key Share
    key_exchange = bytes(
        [
            0x3A, 0xDE, 0x68, 0xEC, 0xF9, 0x12, 0x9E, 0x0A,
            0x9C, 0x21, 0x68, 0xE3, 0x9A, 0x27, 0x24, 0x44,
            0x0C, 0xCB, 0x0C, 0x8F, 0x13, 0x4C, 0x5E, 0xF3,
            0xDB, 0x37, 0xB2, 0x8B, 0xF1, 0xC1, 0x68, 0x11,
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

    # ALPN
    alpn_protocols = b"\x02h3"
    extensions.append(
        _ext(0x0010, len(alpn_protocols).to_bytes(2, "big") + alpn_protocols)
    )

    # QUIC transport parameters
    transport_parameters = _build_quic_transport_parameters(scid)
    extensions.append(_ext(0x0039, transport_parameters))

    # Combine extensions
    extensions_bytes = b"".join(extensions)
    extensions_length = len(extensions_bytes).to_bytes(2, "big")

    body = bytearray()
    body.extend(legacy_version)
    body.extend(random)
    body.append(len(session_id))
    body.extend(session_id)
    body.extend(len(cipher_suite_bytes).to_bytes(2, "big"))
    body.extend(cipher_suite_bytes)
    body.extend(compression_methods)
    body.extend(extensions_length)
    body.extend(extensions_bytes)

    client_hello_body = bytes(body)
    return b"\x01" + len(client_hello_body).to_bytes(3, "big") + client_hello_body


def build_default_initial_payload(scid: bytes) -> bytes:
    """
    Construct a QUIC Initial payload that is structurally unusual:
    - Start with a large PADDING frame to push CRYPTO data later.
    - Split the ClientHello across two CRYPTO frames (offset 0 and non-zero).
    """
    ch = _build_tls_client_hello(scid)

    # Split the ClientHello roughly in half; second half carries SNI for many layouts.
    split_point = max(64, len(ch) // 2)
    first_part = ch[:split_point]
    second_part = ch[split_point:]

    payload = bytearray()

    # 1) Large PADDING segment (frame type 0x00) to obfuscate early bytes
    # Use a random-ish length in [200, 400) to introduce variation.
    pad_len = 200 + (secrets.randbits(5) * 4)
    payload.extend(b"\x00" * pad_len)

    # 2) First CRYPTO frame at offset 0 (type 0x06)
    payload.append(0x06)
    payload.extend(encode_varint(0))  # offset 0
    payload.extend(encode_varint(len(first_part)))
    payload.extend(first_part)

    # 3) Second CRYPTO frame continuing the stream with non-minimal varint for offset
    payload.append(0x06)
    # Deliberately use a 2-byte encoding for the offset even if it would fit in 1 byte.
    off = len(first_part)
    if off <= 0x3F:
        # force 2-byte non-minimal encoding: prefix 01xxxxxx
        top = 0x40 | (off >> 8)
        payload.append(top)
        payload.append(off & 0xFF)
    else:
        payload.extend(encode_varint(off))
    payload.extend(encode_varint(len(second_part)))
    payload.extend(second_part)

    return bytes(payload)


def build_packet(config: PacketConfig) -> Tuple[bytes, bytes, bytes]:
    # Parse and validate bit fields:
    hf = 1 if config.header_form != 0 else 0
    fb = 1 if config.fixed_bit != 0 else 0

    # Determine Packet Type (RFC 9369 V2 uses different bits)
    version_str_for_pt = config.version
    if version_str_for_pt.startswith(("0x", "0X")):
        version_val_for_pt = int(version_str_for_pt, 16)
    else:
        version_val_for_pt = int(version_str_for_pt, 16)

    packet_type_bits = config.packet_type
    if version_val_for_pt == 0x6B3343CF and config.packet_type == "00":
        packet_type_bits = "01"

    if len(packet_type_bits) != 2 or any(b not in "01" for b in packet_type_bits):
        raise ValueError(
            "packet_type must be a 2-bit string, e.g. '00', '01', '10', '11'."
        )
    pt = int(packet_type_bits, 2)

    if len(config.reserved_bits) != 2 or any(b not in "01" for b in config.reserved_bits):
        raise ValueError(
            "reserved_bits must be a 2-bit string, e.g. '00', '01', '10', '11'."
        )
    rb = int(config.reserved_bits, 2)

    if len(config.pkt_num_len_bits) != 2 or any(
        b not in "01" for b in config.pkt_num_len_bits
    ):
        raise ValueError("pkt_num_len_bits must be a 2-bit string.")
    pnl = int(config.pkt_num_len_bits, 2)

    header_byte = (hf << 7) | (fb << 6) | (pt << 4) | (rb << 2) | pnl

    version_str = config.version
    if version_str.startswith(("0x", "0X")):
        version_str = version_str[2:]
    if len(version_str) > 8:
        raise ValueError("Version must fit into 4 bytes (8 hex characters).")
    version_val = int(version_str, 16)
    version_bytes = version_val.to_bytes(4, "big")

    # DCID/SCID resolution
    dcid_bytes = (
        secrets.token_bytes(config.dcid_len)
        if config.dcid is None
        else bytes.fromhex(config.dcid)
    )
    scid_bytes = (
        secrets.token_bytes(config.scid_len)
        if config.scid is None
        else bytes.fromhex(config.scid)
    )

    # Token handling
    if config.token_len > 0:
        token_length = config.token_len
        token_bytes = (
            secrets.token_bytes(token_length)
            if config.token is None
            else bytes.fromhex(config.token)
        )
    else:
        token_length = 0
        token_bytes = b""

    token_length_encoded = encode_varint(token_length)

    pn_len_map = {0: 1, 1: 2, 2: 3, 3: 4}
    pn_len = pn_len_map[pnl]

    if config.packet_number is None:
        packet_number_bytes = b"\x00" * pn_len
    else:
        packet_number_bytes = bytes.fromhex(config.packet_number)
    packet_number_int = int.from_bytes(packet_number_bytes, "big")

    crypto = QUICCrypto(dcid_bytes, version_val)

    if config.payload is not None:
        payload_bytes = bytes.fromhex(config.payload)
    else:
        payload_bytes = build_default_initial_payload(scid_bytes)

    header_prefix_length = (
        1  # first byte
        + len(version_bytes)
        + 1
        + len(dcid_bytes)
        + 1
        + len(scid_bytes)
        + len(token_length_encoded)
        + len(token_bytes)
    )

    def compute_packet_size(payload_len: int) -> Tuple[int, int, bytes]:
        """
        Compute total packet size, QUIC length field value, and its varint encoding
        using a functional-style helper.
        """
        length_val = len(packet_number_bytes) + payload_len + crypto.aead_key_length
        length_encoded_local = encode_varint(length_val)
        total_size = (
            header_prefix_length
            + len(length_encoded_local)
            + len(packet_number_bytes)
            + payload_len
            + crypto.aead_key_length
        )
        return total_size, length_val, length_encoded_local

    # Padding strategy rewritten as a more direct adjustment loop
    if config.pad_to_1200:
        if config.length is not None:
            raise ValueError(
                "Cannot use pad_to_1200 together with a manual length override."
            )
        target_size = 1200
        for _ in range(16):  # hard guard
            total_size, _, computed_length_encoded = compute_packet_size(
                len(payload_bytes)
            )
            if total_size == target_size:
                length_encoded = computed_length_encoded
                break
            diff = target_size - total_size
            if diff > 0:
                payload_bytes += b"\x00" * diff
            else:
                trim_len = -diff
                if trim_len > len(payload_bytes):
                    raise ValueError(
                        "Unable to trim payload to achieve target packet size."
                    )
                payload_bytes = payload_bytes[: len(payload_bytes) - trim_len]
        else:
            raise RuntimeError("Padding loop exceeded maximum iterations.")
    else:
        if config.length is None:
            _, _, length_encoded = compute_packet_size(len(payload_bytes))
        else:
            length_encoded = encode_varint(config.length)

    # Build unprotected header using bytearray to vary implementation style
    packet = bytearray()
    packet.append(header_byte)
    packet.extend(version_bytes)
    packet.append(config.dcid_len)
    packet.extend(dcid_bytes)
    packet.append(config.scid_len)
    packet.extend(scid_bytes)
    packet.extend(token_length_encoded)
    packet.extend(token_bytes)
    packet.extend(length_encoded)
    packet.extend(packet_number_bytes)

    # AAD selection
    if config.additional_data is not None:
        aad = bytes.fromhex(config.additional_data)
    else:
        aad = bytes(packet)

    cipher_payload = crypto.encrypt_packet(True, packet_number_int, aad, payload_bytes)

    # Sample selection for header protection
    if config.sample is not None:
        sample_str = config.sample
        if sample_str.startswith(("0x", "0X")):
            sample = bytes.fromhex(sample_str[2:])
        elif len(sample_str) > 1:
            sample = bytes.fromhex(sample_str)
        else:
            sample_offset = int(sample_str) - len(packet_number_bytes)
            sample = cipher_payload[sample_offset : sample_offset + 16]
    else:
        # For Initial, sample starts after 4 bytes of packet number space
        sample_offset = 4 - len(packet_number_bytes)
        sample = cipher_payload[sample_offset : sample_offset + 16]

    protected_header_byte, protected_packet_number_bytes = crypto.header_protect(
        sample, header_byte, packet_number_bytes
    )
    packet[0] = protected_header_byte[0]
    packet[-len(packet_number_bytes) :] = protected_packet_number_bytes
    packet.extend(cipher_payload)

    return bytes(packet), aad, sample


def run(config: Optional[PacketConfig] = None) -> bytes:
    effective_config = config or PacketConfig()
    packet, aad, sample = build_packet(effective_config)

    print(packet.hex())
    return packet


if __name__ == '__main__':
    run()

# EVOLVE-BLOCK-END