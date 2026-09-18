import struct
from hpack import Encoder

CONN_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

def h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    length = len(payload)
    header = struct.pack("!I", length)[1:] + bytes([frame_type, flags]) + struct.pack("!I", stream_id & 0x7FFFFFFF)
    return header + payload

def generate_h2c_raw_hex(host: str = "pornhub.com", path: str = "/") -> bytes:
    enc = Encoder()
    headers = [
        (':method', 'GET'),
        (':scheme', 'http'),
        (':path', path),
        # Force :authority to be encoded as a literal header name/value with no indexing
        (b':authority', host),
        ('user-agent', 'netcat-h2c/1.0'),
    ]
    header_block = enc.encode(headers)

    settings_payload = b""  # empty SETTINGS payload is valid (no-op)
    settings_frame = h2_frame(frame_type=0x4, flags=0x0, stream_id=0, payload=settings_payload)
    headers_frame = h2_frame(frame_type=0x1, flags=0x5, stream_id=1, payload=header_block)

    return CONN_PREFACE + settings_frame + headers_frame

if __name__ == "__main__":
    target_host = "pornhub.com"
    payload = generate_h2c_raw_hex(host=target_host, path="/")
    print(payload.hex())