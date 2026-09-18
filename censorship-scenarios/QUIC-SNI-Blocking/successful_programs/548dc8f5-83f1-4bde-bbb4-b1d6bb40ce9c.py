# EVOLVE-BLOCK-START
"""
RESERVED BITS
Utility module for crafting QUIC long-header packets.
Current strategy: keep a *valid but minimally exotic* QUICv1 Initial that already
achieves evasion_success=1.0, and introduce only tiny structural quirks
(length varint over-encoding, reserved bits) to add diversity without breaking it.
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
    # Keep using an Initial-type long header, but allow experimenting with other types.
    packet_type: str = "00"
    # Flip reserved bits to "11" by default to introduce a benign anomaly.
    reserved_bits: str = "11"
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

        # Use a helper to avoid repetition for client/server derivations
        self.client_key, self.client_iv, self.client_hp_key = self._derive_role_keys(
            initial_secret, b"client in", label_key, label_iv, label_hp
        )
        self.server_key, self.server_iv, self.server_hp_key = self._derive_role_keys(
            initial_secret, b"server in", label_key, label_iv, label_hp
        )

    def _derive_role_keys(
        self, initial_secret: bytes, role_label: bytes, label_key: bytes, label_iv: bytes, label_hp: bytes
    ):
        """Derive AEAD key, IV and header protection key for a given role."""
        role_secret = self._hkdf_expand_label(
            initial_secret, role_label, b"", self.hash_cls().digest_size
        )
        key = self._hkdf_expand_label(role_secret, label_key, b"", self.aead_key_length)
        iv = self._hkdf_expand_label(role_secret, label_iv, b"", self.iv_length)
        hp_key = self._hkdf_expand_label(role_secret, label_hp, b"", self.hp_key_length)
        return key, iv, hp_key

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

        HKDF-Expand-Label(Secret, Label, Context, Length) =
            HKDF-Expand(Secret, HkdfLabel, Length)
        """
        full_label = b"tls13 " + label

        # Build the HKDF label using a small bytearray to reduce temporary objects.
        hkdf_label = bytearray()
        hkdf_label.extend(length.to_bytes(2, "big"))
        hkdf_label.append(len(full_label))
        hkdf_label.extend(full_label)
        hkdf_label.append(len(context))
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
        QUIC constructs the nonce by XORing the packet number with the IV.
        The IV length is 12 bytes, and the PN is encoded in a variable-length manner.
        """
        pn_bytes = pn.to_bytes(4, "big")
        padded_pn = b"\x00" * (len(iv) - len(pn_bytes)) + pn_bytes
        # Use XOR via bytes + int.from_bytes to avoid a Python-level loop
        iv_int = int.from_bytes(iv, "big")
        pn_int = int.from_bytes(padded_pn, "big")
        nonce_int = iv_int ^ pn_int
        return nonce_int.to_bytes(len(iv), "big")

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
        # Stream encrypt in a single shot but via memoryview to avoid copies
        view = memoryview(plaintext)
        ciphertext = encryptor.update(view) + encryptor.finalize()
        return ciphertext + encryptor.tag

    def header_protect(
        self, sample: bytes, first_byte: bytes, pn_bytes: bytes
    ) -> (bytes, bytes):
        """
        Apply header protection as defined by QUIC.
        """
        cipher = Cipher(
            algorithms.AES(self.client_hp_key), modes.ECB(), backend=default_backend()
        ).encryptor()
        mask = cipher.update(sample) + cipher.finalize()

        fb_masked = bytes([(first_byte ^ (mask[0] & 0x0F))])
        # Use slice XOR via int conversion to get a different algorithmic strategy
        pn_len = len(pn_bytes)
        if pn_len:
            pn_int = int.from_bytes(pn_bytes, "big")
            mask_int = int.from_bytes(mask[1 : 1 + pn_len], "big")
            masked_pn_int = pn_int ^ mask_int
            masked_pn = masked_pn_int.to_bytes(pn_len, "big")
        else:
            masked_pn = b""

        return fb_masked, masked_pn

    def encrypt_packet(self, is_client: bool, pn: int, recdata: bytes, payload: bytes):
        """
        :param is_client: True if sender is client, else server
        :param pn: packet number
        :param recdata: The QUIC header bytes (unprotected)
        :param payload: The plaintext payload
        :return: encrypted packet (header + ciphertext)
        """
        if is_client:
            key, iv = self.client_key, self.client_iv
        else:
            key, iv = self.server_key, self.server_iv

        return self._aead_encrypt(key, iv, pn, recdata, payload)


def encode_varint(value):
    """
    Encode a value as a QUIC variable-length integer.

    We intentionally use non-minimal encodings where possible to slightly diverge
    from "typical" clients while remaining fully standards-compliant, increasing
    structural diversity for the fuzzer.
    """
    # Use 2-byte encoding for small values when it still represents the same integer.
    if value <= 63:
        # Encode in 2-byte form instead of the 1-byte minimal form.
        # First two bits 01, remaining 14 bits hold the value.
        high = 0x40 | ((value >> 8) & 0x3F)
        low = value & 0xFF
        return bytes((high, low))
    if value <= 16383:
        high = 0x40 | ((value >> 8) & 0x3F)
        low = value & 0xFF
        return bytes((high, low))
    if value <= 1073741823:
        b0 = 0x80 | ((value >> 24) & 0x3F)
        b1 = (value >> 16) & 0xFF
        b2 = (value >> 8) & 0xFF
        b3 = value & 0xFF
        return bytes((b0, b1, b2, b3))
    raise ValueError("Value too large for this example's varint encoder.")


def _encode_transport_parameter(param_id: int, value: bytes) -> bytes:
    """Encode a single QUIC transport parameter using varint IDs and lengths."""
    pid = encode_varint(param_id)
    vlen = encode_varint(len(value))
    return pid + vlen + value


def _build_quic_transport_parameters(scid: bytes) -> bytes:
    """Build a minimal set of QUIC transport parameters required by servers."""
    params = bytearray()

    params.extend(_encode_transport_parameter(0x03, encode_varint(65527)))  # max_udp_payload_size
    params.extend(_encode_transport_parameter(0x0A, encode_varint(3)))      # ack_delay_exponent
    params.extend(_encode_transport_parameter(0x0B, encode_varint(25)))     # max_ack_delay
    params.extend(_encode_transport_parameter(0x0F, scid))                  # initial_source_connection_id

    return bytes(params)


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
    cs_buf = bytearray()
    for cs in cipher_suites:
        cs_buf.extend(cs.to_bytes(2, "big"))
    cipher_suite_bytes = bytes(cs_buf)
    compression_methods = b"\x01\x00"

    extensions = []

    # Server Name Indication
    host_name = "google.com"
    if isinstance(host_name, str):
        host_name = host_name.encode("ascii")
    sni = bytearray()
    sni.append(0x00)
    sni.extend(len(host_name).to_bytes(2, "big"))
    sni.extend(host_name)
    sni_list = len(sni).to_bytes(2, "big") + bytes(sni)
    extensions.append(_ext(0x0000, sni_list))

    # Supported Groups
    groups = (0x001d, 0x0017, 0x0018)
    grp_buf = bytearray()
    for g in groups:
        grp_buf.extend(g.to_bytes(2, "big"))
    grp_body = len(grp_buf).to_bytes(2, "big") + bytes(grp_buf)
    extensions.append(_ext(0x000A, grp_body))

    # Signature Algorithms
    sig_algs = (0x0403, 0x0804, 0x0805, 0x0806, 0x0503, 0x0603)
    sa_buf = bytearray()
    for sa in sig_algs:
        sa_buf.extend(sa.to_bytes(2, "big"))
    sa_body = len(sa_buf).to_bytes(2, "big") + bytes(sa_buf)
    extensions.append(_ext(0x000D, sa_body))

    # Supported Versions
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
    ks_body = len(share_entry).to_bytes(2, "big") + share_entry
    extensions.append(_ext(0x0033, ks_body))

    # ALPN
    alpn_protocols = b"\x02h3"
    alpn_body = len(alpn_protocols).to_bytes(2, "big") + alpn_protocols
    extensions.append(_ext(0x0010, alpn_body))

    # QUIC Transport Parameters
    tparams = _build_quic_transport_parameters(scid)
    extensions.append(_ext(0x0039, tparams))

    ext_bytes = b"".join(extensions)
    ext_len = len(ext_bytes).to_bytes(2, "big")

    ch_body = bytearray()
    ch_body.extend(legacy_version)
    ch_body.extend(random)
    ch_body.extend(len(session_id).to_bytes(1, "big"))
    ch_body.extend(session_id)
    ch_body.extend(len(cipher_suite_bytes).to_bytes(2, "big"))
    ch_body.extend(cipher_suite_bytes)
    ch_body.extend(compression_methods)
    ch_body.extend(ext_len)
    ch_body.extend(ext_bytes)

    body_bytes = bytes(ch_body)
    result = bytearray()
    result.append(0x01)
    result.extend(len(body_bytes).to_bytes(3, "big"))
    result.extend(body_bytes)
    return bytes(result)


def build_default_initial_payload(scid: bytes) -> bytes:
    """
    Construct a QUIC Initial payload containing a CRYPTO frame that carries
    a deterministic TLS 1.3 ClientHello.
    """
    client_hello = _build_tls_client_hello(scid)
    frame = bytearray()
    frame.append(0x06)  # CRYPTO frame
    frame.extend(encode_varint(0))
    frame.extend(encode_varint(len(client_hello)))
    frame.extend(client_hello)
    return bytes(frame)


def _parse_version(version_str: str) -> int:
    """Parse the version string into an int, accepting optional 0x prefix."""
    if version_str.startswith(("0x", "0X")):
        version_str = version_str[2:]
    if len(version_str) > 8:
        raise ValueError("Version must fit into 4 bytes (8 hex characters).")
    return int(version_str, 16)


def _compute_header_byte(config: PacketConfig, version_val: int) -> Tuple[int, int]:
    """Compute the first header byte and packet number length index."""
    hf = 1 if config.header_form != 0 else 0
    fb = 1 if config.fixed_bit != 0 else 0

    packet_type_bits = config.packet_type
    if version_val == 0x6b3343cf and config.packet_type == "00":
        packet_type_bits = "01"

    if len(packet_type_bits) != 2 or any(b not in "01" for b in packet_type_bits):
        raise ValueError("packet_type must be a 2-bit string, e.g. '00', '01', '10', '11'.")
    pt = int(packet_type_bits, 2)

    if len(config.reserved_bits) != 2 or any(b not in "01" for b in config.reserved_bits):
        raise ValueError("reserved_bits must be a 2-bit string, e.g. '00', '01', '10', '11'.")
    rb = int(config.reserved_bits, 2)

    if len(config.pkt_num_len_bits) != 2 or any(b not in "01" for b in config.pkt_num_len_bits):
        raise ValueError("pkt_num_len_bits must be a 2-bit string.")
    pnl = int(config.pkt_num_len_bits, 2)

    header_byte = (hf << 7) | (fb << 6) | (pt << 4) | (rb << 2) | pnl
    return header_byte, pnl


def _build_connection_ids(config: PacketConfig) -> Tuple[bytes, bytes]:
    """Build DCID and SCID as bytes from config."""
    if config.dcid is None:
        dcid_bytes = secrets.token_bytes(config.dcid_len)
    else:
        dcid_bytes = bytes.fromhex(config.dcid)

    if config.scid is None:
        scid_bytes = secrets.token_bytes(config.scid_len)
    else:
        scid_bytes = bytes.fromhex(config.scid)

    return dcid_bytes, scid_bytes


def _build_token(config: PacketConfig) -> Tuple[int, bytes, bytes]:
    """Build token length, token bytes and encoded varint length."""
    if config.token_len > 0:
        token_length = config.token_len
        if config.token is None:
            token_bytes = secrets.token_bytes(token_length)
        else:
            token_bytes = bytes.fromhex(config.token)
    else:
        token_length = 0
        token_bytes = b""

    token_length_encoded = encode_varint(token_length)
    return token_length, token_bytes, token_length_encoded


def _determine_packet_number(config: PacketConfig, pnl: int) -> Tuple[bytes, int]:
    pn_len_map = {0: 1, 1: 2, 2: 3, 3: 4}
    pn_len = pn_len_map[pnl]

    if config.packet_number is None:
        pn_bytes = b"\x00" * pn_len
    else:
        pn_bytes = bytes.fromhex(config.packet_number)
    pn_int = int.from_bytes(pn_bytes, "big")
    return pn_bytes, pn_int


def _calculate_length_and_padding(
    crypto: QUICCrypto,
    header_prefix_length: int,
    packet_number_len: int,
    payload_bytes: bytes,
    pad_to_1200: bool,
    manual_length: Optional[int],
) -> Tuple[bytes, bytes]:
    """
    Compute encoded length and padded payload using a closed-form size adjustment
    instead of an iterative loop.
    """
    aead_tag_len = crypto.aead_key_length

    def encoded_len_for_payload(plen: int) -> Tuple[int, bytes]:
        total_payload_len = packet_number_len + plen + aead_tag_len
        length_encoded = encode_varint(total_payload_len)
        total_size = header_prefix_length + len(length_encoded) + total_payload_len
        return total_size, length_encoded

    payload = payload_bytes
    if pad_to_1200:
        if manual_length is not None:
            raise ValueError("Cannot use pad_to_1200 together with a manual length override.")

        current_total, length_encoded = encoded_len_for_payload(len(payload))
        target = 1200
        if current_total < target:
            # Pad directly to reach exactly 1200 bytes
            pad_len = target - current_total
            payload = payload + (b"\x00" * pad_len)
            current_total, length_encoded = encoded_len_for_payload(len(payload))
            if current_total != target:
                raise RuntimeError("Padding calculation did not reach target size.")
        elif current_total > target:
            # Trim any excess without looping
            excess = current_total - target
            if excess > len(payload):
                raise ValueError("Unable to trim payload to achieve target packet size.")
            payload = payload[:-excess]
            current_total, length_encoded = encoded_len_for_payload(len(payload))
            if current_total != target:
                raise RuntimeError("Trimming calculation did not reach target size.")
        return length_encoded, payload
    else:
        if manual_length is None:
            _, length_encoded = encoded_len_for_payload(len(payload))
        else:
            length_encoded = encode_varint(manual_length)
        return length_encoded, payload


def build_packet(config: PacketConfig) -> Tuple[bytes, bytes, bytes]:
    header_byte, pnl = _compute_header_byte(config, _parse_version(config.version))
    version_val = _parse_version(config.version)
    version_bytes = version_val.to_bytes(4, "big")

    dcid_bytes, scid_bytes = _build_connection_ids(config)
    token_length, token_bytes, token_length_encoded = _build_token(config)
    pn_bytes, pn_int = _determine_packet_number(config, pnl)

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

    length_encoded, payload_bytes = _calculate_length_and_padding(
        crypto,
        header_prefix_length,
        len(pn_bytes),
        payload_bytes,
        config.pad_to_1200,
        config.length,
    )

    # Build header using a bytearray for efficiency
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
    packet.extend(pn_bytes)

    if config.additional_data is not None:
        aad = bytes.fromhex(config.additional_data)
    else:
        aad = bytes(packet)

    cipher_payload = crypto.encrypt_packet(True, pn_int, aad, payload_bytes)

    # Determine sample
    if config.sample is not None:
        sample_str = config.sample
        if sample_str.startswith(("0x", "0X")):
            sample = bytes.fromhex(sample_str[2:])
        elif len(sample_str) > 1:
            sample = bytes.fromhex(sample_str)
        else:
            offset = int(sample_str) - len(pn_bytes)
            sample = cipher_payload[offset : offset + 16]
    else:
        # Follow QUIC recommendation: sample starts 4 bytes after PN field begins
        offset = 4 - len(pn_bytes)
        sample = cipher_payload[offset : offset + 16]

    protected_header_byte, protected_pn_bytes = crypto.header_protect(
        sample, header_byte, pn_bytes
    )
    packet[0] = protected_header_byte[0]
    packet[-len(pn_bytes) :] = protected_pn_bytes
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