"""Small, whole images built by hand, so tests need no imaging library.

ImageVerifier reads a size only from a container that parses (GHSA-vch3), so
a test that needs an image of a given size needs a real one, not a signature
followed by two numbers.
"""

import functools
import struct
import zlib


def png_chunk(kind: bytes, body: bytes) -> bytes:
    """One PNG chunk: length, type, data and CRC."""
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)


@functools.lru_cache(maxsize=None)
def gif_lzw(pixels: int, code_size: int = 2) -> bytes:
    """GIF image data (the code size, sub-blocks and terminator) for *pixels*
    pixels of colour 0: a clear code, one literal code per pixel and the end
    code, the code width growing as a decoder's table does."""
    clear = 1 << code_size
    width, next_code = code_size + 1, clear + 2
    acc = bits = 0
    out = bytearray()

    def put(code):
        nonlocal acc, bits
        acc |= code << bits
        bits += width
        while bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            bits -= 8

    put(clear)
    first = True
    for _ in range(pixels):
        if next_code == 4096:
            put(clear)
            width, next_code, first = code_size + 1, clear + 2, True
        put(0)
        if not first:
            next_code += 1
            if next_code == 1 << width and width < 12:
                width += 1
        first = False
    put(clear + 1)
    if bits:
        out.append(acc & 0xFF)
    blocks = b"".join(bytes([len(out[i:i + 255])]) + bytes(out[i:i + 255]) for i in range(0, len(out), 255))
    return bytes([code_size]) + blocks + b"\x00"


def png(width: int, height: int, text: bytes = b"") -> bytes:
    """A whole black-and-white PNG of *width* by *height*; *text*, if given,
    goes in a tEXt chunk, so two images of one size can differ."""
    header = struct.pack(">IIBBBBB", width, height, 1, 0, 0, 0, 0)
    rows = b"".join(b"\x00" + b"\x00" * ((width + 7) // 8) for _ in range(height))
    chunks = [(b"IHDR", header)]
    if text:
        chunks.append((b"tEXt", b"Comment\x00" + text))
    chunks += [(b"IDAT", zlib.compress(rows)), (b"IEND", b"")]
    return b"\x89PNG\r\n\x1a\n" + b"".join(png_chunk(kind, body) for kind, body in chunks)
