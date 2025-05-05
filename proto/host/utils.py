import struct
from pro.protocol import HEADER_FORMAT, MAGIC_HEADER

def build_request_header(version, req_id, cmd_code, payload_len):
    return struct.pack(
        HEADER_FORMAT,
        MAGIC_HEADER,
        version,
        0,  # flags
        req_id,
        cmd_code,
        payload_len,
        0
    )
