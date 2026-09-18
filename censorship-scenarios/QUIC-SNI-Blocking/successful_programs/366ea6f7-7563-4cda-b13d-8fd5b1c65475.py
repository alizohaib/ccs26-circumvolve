# EVOLVE-BLOCK-START
"""
PUNYCODE
Craft a single QUIC Initial packet with a cryptographically valid layout.
Strategy v4 (orthogonal to pure SNI-encoding tricks): keep the punycode SNI but also
embed a decoy cleartext "cloudflare.com" in a GREASE-like TLS extension that does not
affect server processing. This explores DPI behaviors that latch onto the first or
most obvious hostname-looking ASCII, while the real SNI remains the xn-- label.
The frame layout stays conventional (single CRYPTO frame) to preserve server compatibility.
"""

import secrets
from dataclasses import dataclass
from typing import Optional, Tuple

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

        self.aead_key_length = 16
        self.iv_length = 12
        self.hp_key_length = 16
        self.hash_cls = hashes.SHA256

        if version == 0x6b3343cf:  # QUIC Version 2
            label_key = b"quicv2 key"
            label_iv = b"quicv2 iv"
            label_hp = b"quicv2 hp"
        else:  # Version 1 and Draft-29
            label_key = b"quic key"
            label_iv = b"quic iv"
            label_hp = b"quic hp"

        initial_secret = self._hkdf_extract(self.salt, dcid)

        def derive_role_secrets(role_label: bytes):
            role_secret = self._hkdf_expand_label(
                initial_secret, role_label, b"", self.hash_cls().digest_size
            )
            key = self._hkdf_expand_label(role_secret, label_key, b"", self.aead_key_length)
            iv = self._hkdf_expand_label(role_secret, label_iv, b"", self.iv_length)
            hp_key = self._hkdf_expand_label(role_secret, label_hp, b"", self.hp_key_length)
            return key, iv, hp_key

        self.client_key, self.client_iv, self.client_hp_key = derive_role_secrets(b"client in")
        self.server_key, self.server_iv, self.server_hp_key = derive_role_secrets(b"server in")

    def _hkdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        hk = hmac.HMAC(salt, self.hash_cls(), backend=default_backend())
        hk.update(ikm)
        return hk.finalize()

    def _hkdf_expand_label(
        self, secret: bytes, label: bytes, context: bytes, length: int
    ) -> bytes:
        full_label = b"tls13 " + label

        info = bytearray()
        info.extend(length.to_bytes(2, "big"))
        info.append(len(full_label))
        info.extend(full_label)
        info.append(len(context))
        info.extend(context)

        hkdf = HKDFExpand(
            algorithm=self.hash_cls(),
            length=length,
            info=bytes(info),
            backend=default_backend(),
        )
        return hkdf.derive(secret)

    def _build_nonce(self, iv: bytes, pn: int) -> bytes:
        pn_bytes = pn.to_bytes(4, "big")
        padded = bytearray(len(iv))
        pn_offset = len(iv) - len(pn_bytes)
        for i, b in enumerate(iv):
            if i >= pn_offset:
                padded[i] = b ^ pn_bytes[i - pn_offset]
            else:
                padded[i] = b
        return bytes(padded)

    def _aead_encrypt(
        self, key: bytes, iv: bytes, pn: int, aad: bytes, plaintext: bytes
    ) -> bytes:
        nonce = self._build_nonce(iv, pn)
        encryptor = Cipher(
            algorithms.AES(key), modes.GCM(nonce), backend=default_backend()
        ).encryptor()
        encryptor.authenticate_additional_data(aad)
        out = encryptor.update(plaintext)
        out += encryptor.finalize()
        return out + encryptor.tag

    def header_protect(
        self, sample: bytes, first_byte: bytes, pn_bytes: bytes
    ) -> (bytes, bytes):
        cipher = Cipher(
            algorithms.AES(self.client_hp_key), modes.ECB(), backend=default_backend()
        ).encryptor()
        mask = cipher.update(sample) + cipher.finalize()

        fb_mask = mask[0] & 0x0F
        first_byte_masked = bytes([first_byte ^ fb_mask])

        pn_mask = mask[1 : 1 + len(pn_bytes)]
        masked_pn = bytes(p ^ m for p, m in zip(pn_bytes, pn_mask))

        return first_byte_masked, masked_pn

    def encrypt_packet(self, is_client: bool, pn: int, recdata: bytes, payload: bytes):
        key = self.client_key if is_client else self.server_key
        iv = self.client_iv if is_client else self.server_iv
        return self._aead_encrypt(key, iv, pn, recdata, payload)


def encode_varint(value):
    """Encode a value as a QUIC variable-length integer."""
    if value <= 63:
        return bytes([value & 0x3F])
    if value <= 16383:
        hi = 0x40 | ((value >> 8) & 0x3F)
        lo = value & 0xFF
        return bytes([hi, lo])
    if value <= 1073741823:
        return bytes(
            [
                0x80 | ((value >> 24) & 0x3F),
                (value >> 16) & 0xFF,
                (value >> 8) & 0xFF,
                value & 0xFF,
            ]
        )
    raise ValueError("Value too large for this example's varint encoder.")


def _encode_transport_parameter(param_id: int, value: bytes) -> bytes:
    return encode_varint(param_id) + encode_varint(len(value)) + value


def _build_quic_transport_parameters(scid: bytes) -> bytes:
    params = (
        _encode_transport_parameter(0x04, encode_varint(1048576))  # initial_max_data
        + _encode_transport_parameter(0x05, encode_varint(262144))  # initial_max_stream_data_bidi_local
        + _encode_transport_parameter(0x06, encode_varint(262144))  # initial_max_stream_data_bidi_remote
        + _encode_transport_parameter(0x07, encode_varint(262144))  # initial_max_stream_data_uni
        + _encode_transport_parameter(0x08, encode_varint(100))  # initial_max_streams_bidi
        + _encode_transport_parameter(0x09, encode_varint(100))  # initial_max_streams_uni
        + _encode_transport_parameter(0x03, encode_varint(65527))  # max_udp_payload_size
        + _encode_transport_parameter(0x0A, encode_varint(3))  # ack_delay_exponent
        + _encode_transport_parameter(0x0B, encode_varint(25))  # max_ack_delay
        + _encode_transport_parameter(0x0F, scid)  # initial_source_connection_id
    )
    return params


def _split_bytes(data: bytes, first_len: int) -> Tuple[bytes, bytes]:
    """
    Deterministically split data into two chunks: first_len bytes and the rest.
    If first_len is out of range, fall back to a near-middle split.
    """
    n = len(data)
    if first_len <= 0 or first_len >= n:
        first_len = n // 2
    return data[:first_len], data[first_len:]


def _build_tls_client_hello(scid: bytes) -> bytes:
    """
    Build a minimally "normal-looking" TLS 1.3 ClientHello, but with:
      * the real SNI encoded as an xn-- punycode-like label, and
      * a decoy extension that contains the literal "cloudflare.com" string
        in a context most servers will ignore (non-standard/unknown type).
    This probes DPI that either trusts the first hostname-looking bytes or
    only parses the standard SNI extension.
    """
    def _ext(ext_type: int, body: bytes) -> bytes:
        return ext_type.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body

    legacy_version = b"\x03\x03"
    random = bytes(range(32))
    session_id = b""

    cipher_suites = (0x1301, 0x1302, 0x1303)
    cipher_suite_bytes = b"".join(cs.to_bytes(2, "big") for cs in cipher_suites)

    compression_methods = b"\x01\x00"

    extensions = []

    # Decoy extension that explicitly contains the forbidden domain as ASCII.
    # Use a private/unknown extension type (0xAAAA) so endpoints ignore it,
    # but a naive DPI that just scans all extension payloads might hit this.
    decoy_host = b"cloudflare.com"
    decoy_body = encode_varint(len(decoy_host)) + decoy_host
    extensions.append(_ext(0xAAAA, decoy_body))

    # Real SNI uses an xn-- punycode-style label (same as previous best performers).
    host_name = b"xn--cloudflare-9z0a.com"
    server_name = b"\x00" + len(host_name).to_bytes(2, "big") + host_name
    server_name_list = len(server_name).to_bytes(2, "big") + server_name
    extensions.append(_ext(0x0000, server_name_list))

    groups = (0x001d, 0x0017, 0x0018)
    group_bytes = b"".join(g.to_bytes(2, "big") for g in groups)
    extensions.append(_ext(0x000A, len(group_bytes).to_bytes(2, "big") + group_bytes))

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

    extensions.append(_ext(0x002B, b"\x02\x03\x04"))
    extensions.append(_ext(0x002D, b"\x01\x01"))

    key_exchange = bytes(
        [
            0x3A,
            0xDE,
            0x68,
            0xEC,
            0xF9,
            0x12,
            0x9E,
            0x0A,
            0x9C,
            0x21,
            0x68,
            0xE3,
            0x9A,
            0x27,
            0x24,
            0x44,
            0x0C,
            0xCB,
            0x0C,
            0x8F,
            0x13,
            0x4C,
            0x5E,
            0xF3,
            0xDB,
            0x37,
            0xB2,
            0x8B,
            0xF1,
            0xC1,
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

    alpn_protocols = b"\x02h3"
    extensions.append(
        _ext(0x0010, len(alpn_protocols).to_bytes(2, "big") + alpn_protocols)
    )

    transport_parameters = _build_quic_transport_parameters(scid)
    extensions.append(_ext(0x0039, transport_parameters))

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

    return b"\x01" + len(body).to_bytes(3, "big") + bytes(body)


def build_default_initial_payload(scid: bytes) -> bytes:
    """
    Build a more conventional QUIC Initial payload:
      * no unknown frames, no CRYPTO fragmentation tricks,
      * a single CRYPTO frame starting at offset 0 carrying the full ClientHello.
    This focuses experimentation on the SNI encoding rather than frame layout,
    which might improve the chance the server responds while still confusing DPI.
    """
    client_hello = _build_tls_client_hello(scid)

    frame_type = b"\x06"
    offset = encode_varint(0)
    crypto_length = encode_varint(len(client_hello))
    crypto_frame = frame_type + offset + crypto_length + client_hello

    # Minimal padding to help shape packet size; padding will be adjusted later
    # by build_packet()'s pad_to_1200 logic.
    padding = b"\x00" * 8

    return padding + crypto_frame


def build_packet(config: PacketConfig) -> Tuple[bytes, bytes, bytes]:
    hf = 1 if config.header_form != 0 else 0
    fb = 1 if config.fixed_bit != 0 else 0

    version_str = config.version
    if version_str.startswith(("0x", "0X")):
        version_str = version_str[2:]
    if len(version_str) > 8:
        raise ValueError("Version must fit into 4 bytes (8 hex characters).")
    version_val = int(version_str, 16)
    version_bytes = version_val.to_bytes(4, "big")

    packet_type_bits = config.packet_type
    if version_val == 0x6B3343CF and config.packet_type == "00":
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

    if len(config.pkt_num_len_bits) != 2 or any(b not in "01" for b in config.pkt_num_len_bits):
        raise ValueError("pkt_num_len_bits must be a 2-bit string.")
    pnl = int(config.pkt_num_len_bits, 2)

    header_byte = (hf << 7) | (fb << 6) | (pt << 4) | (rb << 2) | pnl

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
        token_bytes = (
            secrets.token_bytes(token_length)
            if config.token is None
            else bytes.fromhex(config.token)
        )
    else:
        token_length = 0
        token_bytes = b""

    token_length_encoded = encode_varint(token_length)

    pn_len_map = (1, 2, 3, 4)
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
        1
        + len(version_bytes)
        + 1
        + len(dcid_bytes)
        + 1
        + len(scid_bytes)
        + len(token_length_encoded)
        + len(token_bytes)
    )

    def compute_frame_size(payload_len: int):
        length_val = len(packet_number_bytes) + payload_len + crypto.aead_key_length
        length_encoded_local = encode_varint(length_val)
        total = (
            header_prefix_length
            + len(length_encoded_local)
            + len(packet_number_bytes)
            + payload_len
            + crypto.aead_key_length
        )
        return total, length_val, length_encoded_local

    if config.pad_to_1200:
        if config.length is not None:
            raise ValueError(
                "Cannot use pad_to_1200 together with a manual length override."
            )
        target_size = 1200
        total, _, length_encoded = compute_frame_size(len(payload_bytes))
        if total < target_size:
            # single-step padding instead of iterative loop
            pad_needed = target_size - total
            payload_bytes += b"\x00" * pad_needed
            total, _, length_encoded = compute_frame_size(len(payload_bytes))
        elif total > target_size:
            trim = total - target_size
            if trim > len(payload_bytes):
                raise ValueError(
                    "Unable to trim payload to achieve target packet size."
                )
            payload_bytes = payload_bytes[:-trim]
            total, _, length_encoded = compute_frame_size(len(payload_bytes))
        # at this point total should equal target_size, or be as close as possible
    else:
        if config.length is None:
            _, _, length_encoded = compute_frame_size(len(payload_bytes))
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
        if sample_str.startswith(("0x", "0X")):
            sample = bytes.fromhex(sample_str[2:])
        elif len(sample_str) > 1:
            sample = bytes.fromhex(sample_str)
        else:
            sample_offset = int(sample_str) - len(packet_number_bytes)
            sample = cipher_payload[sample_offset : sample_offset + 16]
    else:
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