import struct
from pro.protocol import HEADER_FORMAT, HEADER_SIZE, MAGIC_HEADER

def parse_header(data):
    return struct.unpack(HEADER_FORMAT, data)

def build_response_header(version, request_id, status_code, payload_len):
    return struct.pack(
        HEADER_FORMAT,
        MAGIC_HEADER,
        version,
        0,  # flags
        request_id,
        status_code,
        payload_len,
        0
    )
