"""
Image dimensions read only from a container that parses (GHSA-vch3).

ImageVerifier read width and height at fixed byte offsets once the first bytes
matched a signature, so 25 bytes of a PNG signature, zeros and two numbers
were "an 800x600 image", and an extended WebP was misread. Each function here
walks the format's structure and returns the dimensions only when it holds
together as one image of that size; otherwise None, and a size claim about
the data is not decided.

- PNG: an IHDR chunk first, of length 13 with valid fields; every chunk's
  length within the data and its CRC correct; no critical chunk other than
  IHDR, PLTE, IDAT and IEND; at most one palette, of whole entries, before
  the data, where the colour type allows one and required for a palette
  image; IDAT chunks in one run whose data inflates to exactly the bytes the
  header's size, colour type, bit depth and interlacing call for (at most
  136 MiB, enough for 4096 x 4096 RGBA at 16 bits, counted as it is
  inflated and not kept, each 64 KiB of it inflating to at least 48 KiB);
  then IEND.
- GIF: the logical screen and its colour table, then extension and image
  blocks whose sub-blocks fit; each image inside the screen, with an LZW
  code size of 2 to 8 and enough LZW data to hold its pixels; at least one
  image; then the trailer.
- JPEG: only the markers of a sequential, progressive or lossless image
  (no hierarchical or reserved ones, which decoders read differently);
  segments whose lengths fit; one frame header with a valid precision, 1 to
  4 distinct components and a consistent length; quantisation and Huffman
  tables that parse, and a restart interval of length 4; for a DCT frame,
  the quantisation tables each scanned component uses defined before the
  scan; each scan's components taken from the frame, its table selectors
  and spectral and approximation fields valid for the frame's process, and
  a Huffman table it uses defined (or one of the defaults decoders supply);
  the entropy-coded data after each scan walked to the next marker; then
  EOI.
- WebP: more than 30 bytes (as before), a RIFF size within the data; a VP8
  key frame that is shown, with its first partition inside the chunk; a VP8L
  header with data after it; for VP8X, a chunk of 10 bytes with no reserved
  flag set, a canvas under 2^32 pixels, no animation, at most one ALPH chunk
  and only directly before a VP8 image, and one VP8 or VP8L image of the
  canvas's size with nothing that is part of an image after it.

Bytes after the end of an image (after IEND, the GIF trailer, EOI, or the
RIFF size) are ignored, as decoders ignore them. Each walk stops, undecided,
past a number of chunks, blocks, segments or scans no real image of the size
the API accepts needs. Apart from PNG's inflate the pixel data is not
decoded: GIF's LZW data, JPEG's entropy-coded data and the VP8 and VP8L
bitstreams are walked or bounded, not decoded.
"""

import re
import struct
import zlib
from typing import Dict, Optional, Tuple

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_BIT_DEPTHS = {0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8}, 4: {8, 16}, 6: {8, 16}}
_PNG_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
_PNG_CRITICAL = frozenset({b"IHDR", b"PLTE", b"IDAT", b"IEND"})
_PNG_MAX_SIDE = 2**31 - 1
# The most image data a PNG may inflate to before its size is left undecided:
# a 4096 x 4096 RGBA image at 16 bits, interlaced, needs 134,225,408 bytes.
_PNG_MAX_RAW = 136 * 1024 * 1024
_INFLATE_STEP = 1 << 16
# Each _INFLATE_STEP of compressed data must inflate to at least 3/4 of its
# size. A real encoder's stream never inflates to less (stored blocks give as
# much as they take, and a Huffman-coded byte takes at most 9 bits of a fixed
# block), while a stream of empty deflate blocks makes the inflater work
# through megabytes for nothing.
_INFLATE_MIN_OUT, _INFLATE_MIN_IN = 3, 4
# Adam7 interlacing: first column, first row, column step and row step of
# each pass.
_ADAM7 = ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2))
# Frame headers of sequential, progressive and lossless JPEG (the
# differential ones, C5 to C7 and CD to CF, need a hierarchical DHP first).
_JPEG_FRAMES = frozenset({0xC0, 0xC1, 0xC2, 0xC3, 0xC9, 0xCA, 0xCB})
_JPEG_LOSSLESS = frozenset({0xC3, 0xCB})
_JPEG_PROGRESSIVE = frozenset({0xC2, 0xCA})
_JPEG_HUFFMAN = frozenset({0xC0, 0xC1, 0xC2, 0xC3})
# Decoders supply the standard Huffman tables 0 and 1 (DC and AC) when a file
# does not define them.
_JPEG_DEFAULT_HUFFMAN = frozenset({(0, 0), (0, 1), (1, 0), (1, 1)})
_JPEG_DHT, _JPEG_DQT, _JPEG_DRI, _JPEG_SOS = 0xC4, 0xDB, 0xDD, 0xDA
# Other segments such an image holds: DHT, DAC, DQT, DRI, APP0 to APP15, COM.
_JPEG_SEGMENTS = frozenset({0xC4, 0xCC, 0xDB, 0xDD, 0xFE, *range(0xE0, 0xF0)})
_JPEG_STANDALONE = frozenset({0x01, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7})
# The first marker after entropy-coded data: an FF that is not stuffing
# (FF 00), a restart marker or fill (FF FF).
_JPEG_NEXT_MARKER = re.compile(rb"\xff[^\x00\xd0-\xd7\xff]")
_NOT_FILL = re.compile(rb"[^\xff]")
_WEBP_ANIMATION_FLAG = 0x02
# ICC profile, alpha, EXIF, XMP and animation: any other VP8X flag is reserved.
_WEBP_FLAGS = 0x3E
_WEBP_MAX_CANVAS = 2**32
# Smaller than any real WebP (a 1x1 lossless one is 34 bytes); the size an
# image needed before (GHSA-vch3).
_WEBP_MIN_BYTES = 31
# Chunks that are part of an image, which must not follow the image.
_WEBP_IMAGE_CHUNKS = frozenset({b"VP8X", b"VP8 ", b"VP8L", b"ALPH", b"ANIM", b"ANMF", b"ICCP"})
# LZW codes after a clear code stop adding to GIF's table of 4096 entries.
_GIF_TABLE = 4096
# More than any real image of up to the API's 10 MB needs (libpng writes
# 8 KiB IDAT chunks, 1,280 for 10 MB; a progressive JPEG has tens of scans).
_MAX_PNG_CHUNKS = 16_384
_MAX_GIF_SUB_BLOCKS = 200_000
_MAX_JPEG_SEGMENTS = 65_536
_MAX_JPEG_SCANS = 1_000
_MAX_WEBP_CHUNKS = 64

Size = Tuple[int, int]


def _as_bytes(data) -> Optional[bytes]:
    """*data* as bytes, or None when it is not binary data."""
    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    return None


def png_size(data) -> Optional[Size]:
    """The (width, height) of a PNG whose chunks parse through IEND and whose
    image data inflates to what its header calls for."""
    data = _as_bytes(data)
    if data is None or not data.startswith(PNG_SIGNATURE):
        return None
    pos, header, inflation = len(PNG_SIGNATURE), None, None
    palette = image_data = image_data_closed = False
    for _ in range(_MAX_PNG_CHUNKS):
        if pos + 12 > len(data):
            return None
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        end = pos + 12 + length
        if end > len(data) or not kind.isalpha() or not kind.isascii():
            return None
        body = data[pos + 8:pos + 8 + length]
        if zlib.crc32(kind + body) & 0xFFFFFFFF != struct.unpack(">I", data[end - 4:end])[0]:
            return None
        if kind[:1].isupper() and kind not in _PNG_CRITICAL:
            return None
        if header is None:
            header = _png_header(kind, body)
            expected = _png_raw_size(*header) if header is not None else None
            if expected is None:
                return None
            inflation = _Inflation(expected)
        elif kind == b"IDAT":
            if image_data_closed or (header[3] == 3 and not palette):
                return None
            image_data = True
            if not inflation.feed(body):
                return None
        elif kind == b"IEND":
            complete = image_data and length == 0 and inflation.complete()
            return (header[0], header[1]) if complete else None
        elif kind == b"PLTE":
            if palette or image_data or not _png_palette(header, length):
                return None
            palette = True
        elif kind == b"IHDR":
            return None
        else:
            image_data_closed = image_data
        pos = end
    return None


def _png_header(kind: bytes, body: bytes) -> Optional[Tuple[int, int, int, int, int]]:
    """(width, height, bit depth, colour type, interlace) of an IHDR chunk
    whose fields are valid."""
    if kind != b"IHDR" or len(body) != 13:
        return None
    width, height, depth, colour, compression, filtering, interlace = struct.unpack(">IIBBBBB", body)
    if not (0 < width <= _PNG_MAX_SIDE and 0 < height <= _PNG_MAX_SIDE):
        return None
    if depth not in _PNG_BIT_DEPTHS.get(colour, ()) or compression or filtering or interlace > 1:
        return None
    return width, height, depth, colour, interlace


def _png_palette(header: Tuple[int, int, int, int, int], length: int) -> bool:
    """Whether a PLTE chunk of *length* fits the image: whole entries, 1 to
    256 of them (at most 2^depth for a palette image), and a colour type
    that has one."""
    depth, colour = header[2], header[3]
    if colour in (0, 4) or length == 0 or length % 3:
        return False
    entries = length // 3
    return entries <= (2**depth if colour == 3 else 256)


def _png_raw_size(width: int, height: int, depth: int, colour: int, interlace: int) -> Optional[int]:
    """How many bytes the image data inflates to: a filter byte and the
    pixels of each row (of each interlace pass); None above the bound."""
    bits = _PNG_CHANNELS[colour] * depth

    def rows(columns: int, count: int) -> int:
        return count * (1 + (columns * bits + 7) // 8) if columns > 0 and count > 0 else 0

    if interlace == 0:
        total = rows(width, height)
    else:
        total = sum(
            rows((width - x + dx - 1) // dx, (height - y + dy - 1) // dy) for x, y, dx, dy in _ADAM7
        )
    return total if total <= _PNG_MAX_RAW else None


class _Inflation:
    """A PNG's image data inflated a step at a time and counted, not kept,
    against the size its header calls for."""

    __slots__ = ("inflater", "expected", "count", "window_in", "window_out")

    def __init__(self, expected: int):
        self.inflater = zlib.decompressobj()
        self.expected = expected
        self.count = 0
        # Compressed bytes read and bytes they inflated to since the last check.
        self.window_in = self.window_out = 0

    def feed(self, chunk: bytes) -> bool:
        """Inflate *chunk*; False when the stream is corrupt, ends before
        *chunk* does, passes the expected size, or inflates to too little
        for what it takes (_INFLATE_MIN_OUT). The chunk is fed in slices,
        so what is left of a slice after a step is never more than one."""
        try:
            for start in range(0, len(chunk), _INFLATE_STEP):
                pending = chunk[start:start + _INFLATE_STEP]
                before = self.count
                while True:
                    if self.inflater.eof:
                        return not pending and self._ended_with(chunk, start)
                    produced = len(self.inflater.decompress(pending, _INFLATE_STEP))
                    self.count += produced
                    if self.count > self.expected:
                        return False
                    pending = self.inflater.unconsumed_tail
                    # A full step may leave output to come though all input was read.
                    if not pending and produced < _INFLATE_STEP:
                        break
                if not self._yields_enough(len(chunk[start:start + _INFLATE_STEP]), self.count - before):
                    return False
        except zlib.error:
            return False
        return not self.inflater.unused_data

    def _ended_with(self, chunk: bytes, start: int) -> bool:
        """Whether the stream ended with nothing of *chunk* left after the
        slice at *start* and no data after its end."""
        return not (self.inflater.unused_data or chunk[start + _INFLATE_STEP:])

    def _yields_enough(self, taken: int, given: int) -> bool:
        """Count *taken* compressed bytes that inflated to *given*; False when
        a window of _INFLATE_STEP or more inflated to less than its share."""
        self.window_in += taken
        self.window_out += given
        if self.window_in < _INFLATE_STEP:
            return True
        enough = self.window_out * _INFLATE_MIN_IN >= self.window_in * _INFLATE_MIN_OUT
        self.window_in = self.window_out = 0
        return enough

    def complete(self) -> bool:
        """Whether the stream ended after exactly the expected size."""
        return self.inflater.eof and self.count == self.expected


def gif_size(data) -> Optional[Size]:
    """The logical screen (width, height) of a GIF whose blocks parse through
    the trailer, with every image inside the screen."""
    data = _as_bytes(data)
    if data is None or data[:6] not in (b"GIF87a", b"GIF89a") or len(data) < 13:
        return None
    width, height, packed = struct.unpack("<HHB", data[6:11])
    if not (width and height):
        return None
    pos = 13 + (3 * (2 << (packed & 7)) if packed & 0x80 else 0)
    images, budget = 0, [_MAX_GIF_SUB_BLOCKS]
    while pos is not None and pos < len(data):
        block = data[pos]
        if block == 0x3B:
            return (width, height) if images else None
        if block == 0x21:
            pos = _gif_sub_blocks(data, pos + 2, budget)[0]
        elif block == 0x2C:
            if pos + 10 > len(data):
                return None
            left, top, frame_width, frame_height, local = struct.unpack("<HHHHB", data[pos + 1:pos + 10])
            if not (frame_width and frame_height) or left + frame_width > width or top + frame_height > height:
                return None
            pos += 10 + (3 * (2 << (local & 7)) if local & 0x80 else 0)
            if pos >= len(data) or not 2 <= data[pos] <= 8:
                return None
            code_size = data[pos]
            pos, held = _gif_sub_blocks(data, pos + 1, budget)
            if _gif_most_pixels(held, code_size) < frame_width * frame_height:
                return None
            images += 1
        else:
            return None
    return None


def _gif_sub_blocks(data: bytes, pos: int, budget: list) -> Tuple[Optional[int], int]:
    """The position after a run of GIF data sub-blocks and its terminator
    (None past the end of the data or the budget of sub-blocks left), and
    how many data bytes the sub-blocks hold."""
    held = 0
    while pos < len(data):
        budget[0] -= 1
        if budget[0] < 0:
            return None, held
        count = data[pos]
        pos += 1 + count
        held += count
        if count == 0:
            return pos, held
    return None, held


def _gif_most_pixels(held: int, code_size: int) -> int:
    """The most pixels *held* bytes of LZW data with minimum code size
    *code_size* can decode to. Each code takes at least code_size + 1 bits.
    After a clear code the n-th code gives at most n pixels (each table entry
    is one longer than one before it), until the table is full; after that
    no code gives more than the longest entry. The pixel data is not decoded:
    this only refuses data too short to hold the image."""
    codes = held * 8 // (code_size + 1)
    growing = _GIF_TABLE - (1 << code_size) - 1
    if codes <= growing:
        return codes * (codes + 1) // 2
    return growing * (growing + 1) // 2 + (codes - growing) * growing


def jpeg_size(data) -> Optional[Size]:
    """The (width, height) of a JPEG whose segments and scans parse through
    EOI, with one frame header."""
    data = _as_bytes(data)
    if data is None or not data.startswith(b"\xff\xd8"):
        return None
    pos, size, frame, scans = 2, None, None, 0
    tables, huffman = set(), set()
    for _ in range(_MAX_JPEG_SEGMENTS):
        if pos + 2 > len(data) or data[pos] != 0xFF:
            return None
        marker = data[pos + 1]
        if marker == 0xFF:
            found = _NOT_FILL.search(data, pos + 1)
            if found is None:
                return None
            pos = found.start() - 1
            continue
        if marker == 0xD9:
            return size if scans else None
        if marker in _JPEG_STANDALONE:
            pos += 2
            continue
        if not (marker in _JPEG_FRAMES or marker in _JPEG_SEGMENTS or marker == 0xDA) or pos + 4 > len(data):
            return None
        length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        end = pos + 2 + length
        if length < 2 or end > len(data):
            return None
        body = data[pos + 4:end]
        if marker in _JPEG_FRAMES:
            frame = _jpeg_frame(body, marker) if size is None else None
            if frame is None:
                return None
            size = frame.size
        elif marker == _JPEG_DQT:
            defined = _jpeg_tables(body)
            if defined is None:
                return None
            tables |= defined
        elif marker == _JPEG_DHT:
            defined = _jpeg_huffman_tables(body)
            if defined is None:
                return None
            huffman |= defined
        elif marker == _JPEG_DRI and length != 4:
            return None
        elif marker == _JPEG_SOS:
            if frame is None or scans >= _MAX_JPEG_SCANS or not _jpeg_scan(body, frame, tables, huffman):
                return None
            scans += 1
            found = _JPEG_NEXT_MARKER.search(data, end)
            if found is None:
                return None
            end = found.start()
        pos = end
    return None


class _JpegFrame:
    """What a frame header states: the size, the process (its marker), the
    precision and the quantisation table of each component."""

    __slots__ = ("size", "marker", "precision", "components")

    def __init__(self, size: Size, marker: int, precision: int, components: Dict[int, int]):
        self.size = size
        self.marker = marker
        self.precision = precision
        self.components = components


def _jpeg_frame(body: bytes, marker: int) -> Optional[_JpegFrame]:
    """The frame a header states, when its precision, length, component
    count, sampling factors and table numbers are valid."""
    if len(body) < 6:
        return None
    precision, height, width, count = struct.unpack(">BHHB", body[:6])
    if marker in _JPEG_LOSSLESS:
        precision_ok = 2 <= precision <= 16
    else:
        precision_ok = precision == 8 or (precision == 12 and marker != 0xC0)
    if not precision_ok or not (width and height) or not 1 <= count <= 4 or len(body) != 6 + 3 * count:
        return None
    ids, sampling, quantisation = body[6::3], body[7::3], body[8::3]
    if len(set(ids)) != count or any(not (1 <= s >> 4 <= 4 and 1 <= s & 15 <= 4) for s in sampling):
        return None
    if any(table > 3 for table in quantisation):
        return None
    return _JpegFrame((width, height), marker, precision, dict(zip(ids, quantisation)))


def _jpeg_huffman_tables(body: bytes) -> Optional[set]:
    """The (class, number) of each table a DHT segment defines, when it is a
    whole number of tables that decoders accept: class 0 or 1, number 0 to
    3, at most 256 codes, their symbols inside the segment, DC symbols of at
    most 16, and code counts that fit their lengths; else None."""
    pos, defined = 0, set()
    while pos < len(body):
        if pos + 17 > len(body):
            return None
        table_class, number = body[pos] >> 4, body[pos] & 15
        counts = body[pos + 1:pos + 17]
        total = sum(counts)
        if table_class > 1 or number > 3 or total > 256 or pos + 17 + total > len(body):
            return None
        symbols = body[pos + 17:pos + 17 + total]
        if table_class == 0 and any(symbol > 16 for symbol in symbols):
            return None
        code = 0
        for bits, count in enumerate(counts, 1):
            code += count
            # Canonical codes of each length must fit in that many bits, as
            # decoders check when they build the table.
            if count and code >= 1 << bits:
                return None
            code <<= 1
        defined.add((table_class, number))
        pos += 17 + total
    return defined or None


def _jpeg_tables(body: bytes) -> Optional[set]:
    """The table numbers a DQT segment defines, when it is a whole number of
    valid tables; else None."""
    pos, defined = 0, set()
    while pos < len(body):
        precision, number = body[pos] >> 4, body[pos] & 15
        if precision > 1 or number > 3:
            return None
        defined.add(number)
        pos += 1 + 64 * (precision + 1)
    return defined if pos == len(body) and defined else None


def _jpeg_scan(body: bytes, frame: _JpegFrame, tables: set, huffman: set) -> bool:
    """Whether a scan header's length fits its component count, each of its
    components is a different one of the frame's, its table selectors are 0
    to 3, its spectral and approximation fields are valid for the frame's
    process, (for a DCT frame) the quantisation table each component uses is
    defined, and (for a Huffman-coded frame) each Huffman table the scan
    uses is defined or one decoders supply."""
    if not body or not 1 <= body[0] <= 4 or len(body) != 1 + 2 * body[0] + 3:
        return False
    count = body[0]
    selectors, entropy = body[1:1 + 2 * count:2], body[2:2 + 2 * count:2]
    components = frame.components
    if len(set(selectors)) != len(selectors) or any(s not in components for s in selectors):
        return False
    if any(e >> 4 > 3 or e & 15 > 3 for e in entropy):
        return False
    start, end, high, low = body[-3], body[-2], body[-1] >> 4, body[-1] & 15
    lossless = frame.marker in _JPEG_LOSSLESS
    if lossless:
        # A predictor, no spectral band, and a point transform under the precision.
        if not (1 <= start <= 7 and end == 0 and high == 0 and low < frame.precision):
            return False
    elif not all(components[s] in tables for s in selectors):
        return False
    if frame.marker in _JPEG_PROGRESSIVE:
        band = end == 0 if start == 0 else (start <= end <= 63 and count == 1)
        if not band or (high and low != high - 1) or low > 13:
            return False
    if frame.marker not in _JPEG_HUFFMAN:
        return True
    return all(
        used in huffman or used in _JPEG_DEFAULT_HUFFMAN for used in _jpeg_huffman_used(frame, entropy, start, high)
    )


def _jpeg_huffman_used(frame: _JpegFrame, entropy: bytes, start: int, high: int) -> set:
    """The (class, number) of each Huffman table a scan decodes with: DC
    tables for a lossless scan, a sequential scan and a progressive DC first
    pass; AC tables for a sequential scan and a progressive AC scan."""
    progressive = frame.marker in _JPEG_PROGRESSIVE
    dc = frame.marker in _JPEG_LOSSLESS or not progressive or (start == 0 and high == 0)
    ac = frame.marker not in _JPEG_LOSSLESS and (not progressive or start > 0)
    used = set()
    for selector in entropy:
        if dc:
            used.add((0, selector >> 4))
        if ac:
            used.add((1, selector & 15))
    return used


def webp_size(data) -> Optional[Size]:
    """The (width, height) of a WebP whose RIFF container and image chunk
    are valid."""
    data = _as_bytes(data)
    if data is None or len(data) < 20 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return None
    riff_end = struct.unpack("<I", data[4:8])[0] + 8
    if not _WEBP_MIN_BYTES <= riff_end <= len(data):
        return None
    data = data[:riff_end]
    kind, length = struct.unpack("<4sI", data[12:20])
    end = 20 + length + (length & 1)
    if end > len(data):
        return None
    body = data[20:20 + length]
    if kind == b"VP8X":
        return _webp_extended(data, body, end) if length == 10 else None
    if end != len(data):
        return None
    if kind == b"VP8 ":
        return _webp_lossy(body)
    if kind == b"VP8L":
        return _webp_lossless(body)
    return None


def _webp_lossy(body: bytes) -> Optional[Size]:
    """The size a VP8 key frame header states, when the frame is shown and
    its first partition fits in the chunk."""
    if len(body) < 10 or body[3:6] != b"\x9d\x01\x2a":
        return None
    tag = int.from_bytes(body[:3], "little")
    key_frame, version, shown, first_partition = not tag & 1, (tag >> 1) & 7, (tag >> 4) & 1, tag >> 5
    if not key_frame or version > 3 or not shown or not 0 < first_partition <= len(body) - 10:
        return None
    width, height = (value & 0x3FFF for value in struct.unpack("<HH", body[6:10]))
    return (width, height) if width and height else None


def _webp_lossless(body: bytes) -> Optional[Size]:
    """The size a VP8L header states, when image data follows it."""
    if len(body) < 6 or body[0] != 0x2F:
        return None
    bits = struct.unpack("<I", body[1:5])[0]
    if bits >> 29:
        return None
    return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1


def _webp_extended(data: bytes, body: bytes, pos: int) -> Optional[Size]:
    """The canvas size of a VP8X file that is not animated and holds one VP8
    or VP8L image of that size, its chunks fitting the RIFF, as libwebp's
    demuxer reads it: a 10-byte VP8X chunk with no reserved flag, one VP8X,
    at most one ALPH and only directly before a VP8 image, and nothing that
    is part of an image (or an ICC profile) after the image."""
    if len(body) != 10 or body[0] & ~_WEBP_FLAGS or body[0] & _WEBP_ANIMATION_FLAG:
        return None
    width, height = 1 + int.from_bytes(body[4:7], "little"), 1 + int.from_bytes(body[7:10], "little")
    if width * height >= _WEBP_MAX_CANVAS:
        return None
    image, alpha = None, False
    for _ in range(_MAX_WEBP_CHUNKS):
        if pos >= len(data):
            return (width, height) if image == (width, height) else None
        if pos + 8 > len(data):
            return None
        kind, length = struct.unpack("<4sI", data[pos:pos + 8])
        chunk = data[pos + 8:pos + 8 + length]
        pos += 8 + length + (length & 1)
        if pos > len(data) or (image is not None and kind in _WEBP_IMAGE_CHUNKS):
            return None
        if kind in (b"VP8X", b"ANIM", b"ANMF") or (alpha and kind != b"VP8 "):
            return None
        if kind == b"ALPH":
            alpha = True
        elif kind in (b"VP8 ", b"VP8L"):
            image, alpha = (_webp_lossy(chunk) if kind == b"VP8 " else _webp_lossless(chunk)), False
            if image is None:
                return None
    return None
