# EVOLVE-BLOCK-START
"""
Utility module for crafting QUIC long-header packets.
Uses a configurable `PacketConfig` to describe header, connection ID, token,
and payload settings, derives the QUIC Initial secrets, encrypts the payload,
and applies header protection before emitting hex-encoded output or debugging data.
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

        # The AEAD for initial keys is AES-128-GCM, and QUIC uses 16-byte keys, 12-byte IVs
        # The header protection uses AES-ECB with a 16-byte key
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
        # HKDF-Extract is essentially HMAC with salt
        hk = hmac.HMAC(salt, self.hash_cls(), backend=default_backend())
        hk.update(ikm)
        return hk.finalize()

    def _hkdf_expand_label(
        self, secret: bytes, label: bytes, context: bytes, length: int
    ) -> bytes:
        """
        HKDF-Expand-Label as defined by TLS 1.3 and QUIC.

        HKDF-Expand-Label(Secret, Label, Context, Length) =
            HKDF-Expand(Secret, HkdfLabel, Length)

        Where HkdfLabel = length(Label) + Label + length(Context) + Context
        """
        full_label = b"tls13 " + label

        # The "HkdfLabel" structure in TLS 1.3 for QUIC:
        # struct {
        #   uint16 length = Length;
        #   opaque label<0..255> = "quic " + Label;
        #   opaque context<0..255> = Context;
        # } HkdfLabel;
        #
        # length is a 2-byte integer
        # Then a single-byte length for label and context each, followed by label and context bytes
        hkdf_label = (
            length.to_bytes(2, "big")
            + bytes([len(full_label)])
            + full_label
            + bytes([len(context)])
            + context
        )

        hkdf = HKDFExpand(
            algorithm=self.hash_cls(),
            length=length,
            info=hkdf_label,
            backend=default_backend(),
        )
        return hkdf.derive(secret)

    def _aead_encrypt(
        self, key: bytes, iv: bytes, pn: int, aad: bytes, plaintext: bytes
    ) -> bytes:
        """
        AEAD Encrypt using AES-128-GCM.

        :param key: The AEAD key
        :param iv: The AEAD IV
        :param pn: Packet number (for nonce construction)
        :param aad: Additional authenticated data
        :param plaintext: The data to encrypt
        :return: ciphertext including authentication tag
        """
        nonce = self._build_nonce(iv, pn)
        encryptor = Cipher(
            algorithms.AES(key), modes.GCM(nonce), backend=default_backend()
        ).encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext + encryptor.tag

    def _build_nonce(self, iv: bytes, pn: int) -> bytes:
        """
        QUIC constructs the nonce by XORing the packet number with the IV.
        The IV length is 12 bytes, and the PN is encoded in a variable-length manner.
        """
        pn_bytes = pn.to_bytes(4, "big")
        # IV length is 12, PN length might be shorter. Right-align PN in the IV.
        padded_pn = (b"\x00" * (len(iv) - len(pn_bytes))) + pn_bytes
        return bytes(a ^ b for a, b in zip(iv, padded_pn))

    def header_protect(
        self, sample: bytes, first_byte: bytes, pn_bytes: bytes
    ) -> (bytes, bytes):
        """
        Apply header protection as defined by QUIC.

        The header protection key is used to create a mask by encrypting a sample of ciphertext.
        The first protected byte (one byte from the flags) and the PN bytes are XORed with parts of this mask.

        :param hp_key: the header protection key
        :param sample: 16-byte sample from the ciphertext after the header
        :param first_byte: the first header byte to protect/unprotect
        :param pn_bytes: the packet number bytes to protect/unprotect
        :return: (modified_first_byte, modified_pn_bytes)
        """
        # QUIC header protection uses AES-ECB for generating a mask.
        cipher = Cipher(
            algorithms.AES(self.client_hp_key), modes.ECB(), backend=default_backend()
        ).encryptor()
        mask = cipher.update(sample) + cipher.finalize()

        # Mask the first byte (only the lower 5 bits are protected)
        first_byte_masked = bytes([(first_byte ^ (mask[0] & 0x0F))])

        # Mask the PN bytes
        masked_pn = bytes(p ^ m for p, m in zip(pn_bytes, mask[1 : 1 + len(pn_bytes)]))

        return first_byte_masked, masked_pn

    def encrypt_packet(self, is_client: bool, pn: int, recdata: bytes, payload: bytes):
        """
        :param is_client: True if sender is client, else server
        :param pn: packet number
        :param recdata: The QUIC header bytes (unprotected)
        :param payload: The plaintext payload
        :return: encrypted packet (header + ciphertext)
        """
        key = self.client_key if is_client else self.server_key
        iv = self.client_iv if is_client else self.server_iv

        ciphertext_with_tag = self._aead_encrypt(key, iv, pn, recdata, payload)

        return ciphertext_with_tag

def encode_varint(value):
    """Encode a value as a QUIC variable-length integer."""
    # For simplicity, only handle up to 4-byte encodings in this example.
    # Extend as needed for larger values.
    if value <= 63:
        # Fits in 6 bits
        return bytes([(value & 0x3f)])  # 00xxxxxx
    elif value <= 16383:
        # Fits in 14 bits
        # 01xxxxxx xxxxxxxx
        return bytes([
            0x40 | ((value >> 8) & 0x3f),
            value & 0xff
        ])
    elif value <= 1073741823:
        # Fits in 30 bits
        # 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        return bytes([
            0x80 | ((value >> 24) & 0x3f),
            (value >> 16) & 0xff,
            (value >> 8) & 0xff,
            value & 0xff
        ])
    else:
        # For completeness, handle larger values:
        # 11xxxxxx [8-byte total]
        # However, this is not expected for small test values.
        # Raise an error or implement as needed.
        raise ValueError("Value too large for this example's varint encoder.")


def _encode_transport_parameter(param_id: int, value: bytes) -> bytes:
    """Encode a single QUIC transport parameter using varint IDs and lengths."""
    return encode_varint(param_id) + encode_varint(len(value)) + value


def _build_quic_transport_parameters(scid: bytes) -> bytes:
    """Build a minimal set of QUIC transport parameters required by servers."""
    parameters = [
        _encode_transport_parameter(0x04, encode_varint(1048576)),    # initial_max_data (1MB)
        _encode_transport_parameter(0x05, encode_varint(262144)),     # initial_max_stream_data_bidi_local (256KB)
        _encode_transport_parameter(0x06, encode_varint(262144)),     # initial_max_stream_data_bidi_remote (256KB)
        _encode_transport_parameter(0x07, encode_varint(262144)),     # initial_max_stream_data_uni (256KB)
        _encode_transport_parameter(0x08, encode_varint(100)),        # initial_max_streams_bidi
        _encode_transport_parameter(0x09, encode_varint(100)),        # initial_max_streams_uni
        _encode_transport_parameter(0x03, encode_varint(65527)),      # max_udp_payload_size
        _encode_transport_parameter(0x0A, encode_varint(3)),          # ack_delay_exponent
        _encode_transport_parameter(0x0B, encode_varint(25)),         # max_ack_delay
        _encode_transport_parameter(0x0F, scid),                      # initial_source_connection_id
    ]
    return b"".join(parameters)


def _build_tls_client_hello(scid: bytes) -> bytes:
    """Construct a deterministic TLS 1.3 ClientHello message."""

    def _ext(ext_type: int, body: bytes) -> bytes:
        return ext_type.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body

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
    host_name = "blocked.com" # Blocked domain
    if isinstance(host_name, str):
        host_name = host_name.encode("ascii")
    server_name = b"\x00" + len(host_name).to_bytes(2, "big") + host_name
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

    # Application Layer Protocol Negotiation (HTTP/3)
    alpn_protocols = b"\x02h3"
    extensions.append(
        _ext(0x0010, len(alpn_protocols).to_bytes(2, "big") + alpn_protocols)
    )

    transport_parameters = _build_quic_transport_parameters(scid)
    extensions.append(_ext(0x0039, transport_parameters))

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

    return b"\x01" + len(client_hello_body).to_bytes(3, "big") + client_hello_body


def build_default_initial_payload(scid: bytes) -> bytes:
    """
    Construct a QUIC Initial payload containing a CRYPTO frame that carries
    a deterministic TLS 1.3 ClientHello.
    """
    client_hello = _build_tls_client_hello(scid)
    frame_type = b"\x06"  # CRYPTO frame
    offset = encode_varint(0)
    crypto_length = encode_varint(len(client_hello))
    return frame_type + offset + crypto_length + client_hello


def build_packet(config: PacketConfig) -> Tuple[bytes, bytes, bytes]:
    # Parse and validate bit fields:
    hf = 1 if config.header_form != 0 else 0
    fb = 1 if config.fixed_bit != 0 else 0

    # Determine Packet Type (RFC 9369 V2 uses different bits)
    # If user hasn't manually overridden the default "00", adapt it for V2.
    version_val = int(config.version, 16) if not config.version.startswith('0x') else int(config.version, 16)
    
    packet_type_bits = config.packet_type
    if version_val == 0x6b3343cf and config.packet_type == "00":
        # V2 Initial Packet is type 0x1 (binary 01)
        packet_type_bits = "01"

    if len(packet_type_bits) != 2 or any(b not in '01' for b in packet_type_bits):
        raise ValueError("packet_type must be a 2-bit string, e.g. '00', '01', '10', '11'.")
    pt = int(packet_type_bits, 2)

    if len(config.reserved_bits) != 2 or any(b not in '01' for b in config.reserved_bits):
        raise ValueError("reserved_bits must be a 2-bit string, e.g. '00', '01', '10', '11'.")
    rb = int(config.reserved_bits, 2)

    if len(config.pkt_num_len_bits) != 2 or any(b not in '01' for b in config.pkt_num_len_bits):
        raise ValueError("pkt_num_len_bits must be a 2-bit string.")
    pnl = int(config.pkt_num_len_bits, 2)

    header_byte = (hf << 7) | (fb << 6) | (pt << 4) | (rb << 2) | pnl

    version_str = config.version
    if version_str.startswith(('0x', '0X')):
        version_str = version_str[2:]
    if len(version_str) > 8:
        raise ValueError("Version must fit into 4 bytes (8 hex characters).")
    version_val = int(version_str, 16)
    version_bytes = version_val.to_bytes(4, 'big')

    if config.dcid is None:
        dcid_bytes = secrets.token_bytes(config.dcid_len)
    else:
        dcid_bytes = bytes.fromhex(config.dcid)

    if config.scid is None:
        scid_bytes = secrets.token_bytes(config.scid_len)
    else:
        scid_bytes = bytes.fromhex(config.scid)

    if config.token_len > 0:
        token_length = config.token_len
        if config.token is None:
            token_bytes = secrets.token_bytes(token_length)
        else:
            token_bytes = bytes.fromhex(config.token)
    else:
        token_length = 0
        token_bytes = b''

    token_length_encoded = encode_varint(token_length)

    pn_len_map = {0: 1, 1: 2, 2: 3, 3: 4}
    pn_len = pn_len_map[pnl]

    if config.packet_number is None:
        packet_number_bytes = b'\x00' * pn_len
    else:
        packet_number_bytes = bytes.fromhex(config.packet_number)
    packet_number_int = int.from_bytes(packet_number_bytes, 'big')

    crypto = QUICCrypto(dcid_bytes, version_val)

    if config.payload is not None:
        payload_bytes = bytes.fromhex(config.payload)
    else:
        payload_bytes = build_default_initial_payload(scid_bytes)

    header_prefix_length = (
        1
        + len(version_bytes)
        + 1
        + len(dcid_bytes)
        + 1
        + len(scid_bytes)
        + len(token_length_encoded)
        + len(token_bytes)
    )

    def calculate_sizes(payload_len: int):
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

    if config.pad_to_1200:
        if config.length is not None:
            raise ValueError('Cannot use pad_to_1200 together with a manual length override.')
        target_size = 1200
        iteration_guard = 0
        while True:
            iteration_guard += 1
            if iteration_guard > 10:
                raise RuntimeError('Padding loop exceeded maximum iterations.')
            total_size, _, computed_length_encoded = calculate_sizes(len(payload_bytes))
            if total_size == target_size:
                length_encoded = computed_length_encoded
                break
            if total_size < target_size:
                payload_bytes += b'\x00' * (target_size - total_size)
            else:
                trim_len = total_size - target_size
                if trim_len > len(payload_bytes):
                    raise ValueError('Unable to trim payload to achieve target packet size.')
                payload_bytes = payload_bytes[:-trim_len]
    else:
        if config.length is None:
            _, _, length_encoded = calculate_sizes(len(payload_bytes))
        else:
            length_encoded = encode_varint(config.length)

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

    if config.additional_data is not None:
        aad = bytes.fromhex(config.additional_data)
    else:
        aad = bytes(packet)

    cipher_payload = crypto.encrypt_packet(True, packet_number_int, aad, payload_bytes)

    if config.sample is not None:
        sample_str = config.sample
        if sample_str.startswith(('0x', '0X')):
            sample = bytes.fromhex(sample_str[2:])
        elif len(sample_str) > 1:
            sample = bytes.fromhex(sample_str)
        else:
            sample_offset = int(sample_str) - len(packet_number_bytes)
            sample = cipher_payload[sample_offset:sample_offset + 16]
    else:
        sample_offset = 4 - len(packet_number_bytes)
        sample = cipher_payload[sample_offset:sample_offset + 16]

    protected_header_byte, protected_packet_number_bytes = crypto.header_protect(sample, header_byte, packet_number_bytes)
    packet[0] = protected_header_byte[0]
    packet[-len(packet_number_bytes):] = protected_packet_number_bytes
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
