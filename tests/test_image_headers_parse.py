"""ImageVerifier decides a size only from a container that parses (GHSA-vch3).

It read width and height at fixed byte offsets once the first bytes matched a
signature, so 25 bytes (a PNG signature, eight zeros, 800, 600 and one byte)
were admitted as "an 800x600 image", and an extended WebP was misread. The
dimensions now come from a walk of the format's structure, checked to be one
image of that size (PNG data inflated and counted, GIF frames inside the
screen, JPEG tables and scans, the WebP canvas matching its image); when it
does not hold together, a size claim is UNVERIFIABLE.

The images are built by hand here, so the tests need no imaging library.
"""

import struct
import time
import zlib

import pytest

from qwed_new.core.diagnostics import admission_decision
from qwed_new.core.image_verifier import ImageVerifier
from tests.image_fixtures import gif_lzw
from tests.image_fixtures import png_chunk as _chunk
from tests.test_issue_320_logic_route_admission import client  # noqa: F401  (fixture)


def _png(width=8, height=4, colour=2, depth=8, chunks=None, interlace=0, raw=None):
    header = struct.pack(">IIBBBBB", width, height, depth, colour, 0, 0, interlace)
    pixels = zlib.compress(raw if raw is not None else b"\x00" * (height * (1 + width * 3)))
    body = chunks if chunks is not None else [(b"IHDR", header), (b"IDAT", pixels), (b"IEND", b"")]
    return b"\x89PNG\r\n\x1a\n" + b"".join(_chunk(kind, data) for kind, data in body)


def _ihdr(width=8, height=4, colour=2, depth=8, interlace=0):
    return (b"IHDR", struct.pack(">IIBBBBB", width, height, depth, colour, 0, 0, interlace))


DQT = b"\xff\xdb" + struct.pack(">H", 67) + b"\x00" + bytes(range(1, 65))
ENTROPY = b"\x12\x34\xff\x00\x56\xff\xd0\x78"  # with stuffing and a restart marker


def _sof(width, height, marker=0xC0, components=(1,), precision=8, table=0):
    body = struct.pack(">BHHB", precision, height, width, len(components))
    body += b"".join(bytes([c, 0x11, table]) for c in components)
    return bytes([0xFF, marker]) + struct.pack(">H", 2 + len(body)) + body


def _segment(marker, body):
    return bytes([0xFF, marker]) + struct.pack(">H", 2 + len(body)) + body


def _sos(components=(1,), start=0, end=63, approx=0, entropy=0):
    body = bytes([len(components)]) + b"".join(bytes([c, entropy]) for c in components) + bytes([start, end, approx])
    return b"\xff\xda" + struct.pack(">H", 2 + len(body)) + body


def _band(marker, index):
    """The spectral band of scan *index* in a frame of *marker*: a predictor
    for lossless, a DC pass then AC passes for progressive, all of it for
    sequential."""
    if marker in (0xC3, 0xCB):
        return 1, 0
    if marker in (0xC2, 0xCA):
        return (0, 0) if index == 0 else (1, 63)
    return 0, 63


def _jpeg(width=8, height=4, frames=1, end=b"\xff\xd9", tables=True, marker=0xC0, scans=1, scan=(1,)):
    head = b"\xff\xd8" + (DQT if tables else b"") + _sof(width, height, marker) * frames
    return head + b"".join(_sos(scan, *_band(marker, index)) + ENTROPY for index in range(scans)) + end


def _gif(width=8, height=4, trailer=b"\x3b", left=0, frame=None, lzw=2, data=None):
    frame_width, frame_height = frame or (width, height)
    screen = b"GIF89a" + struct.pack("<HHBBB", width, height, 0, 0, 0)
    image = b"\x2c" + struct.pack("<HHHHB", left, 0, frame_width, frame_height, 0)
    return screen + image + (data if data is not None else gif_lzw(frame_width * frame_height, lzw)) + trailer


def _riff(*chunks):
    body = b"WEBP" + b"".join(
        kind + struct.pack("<I", len(data)) + data + (b"\x00" if len(data) & 1 else b"") for kind, data in chunks
    )
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _vp8l(width, height, data=b"\x00" * 10):
    bits = (width - 1) | ((height - 1) << 14)
    return b"\x2f" + struct.pack("<I", bits) + data


def _vp8(width, height, key=True, shown=True, partition=6, payload=None):
    tag = (partition << 5) | (int(shown) << 4) | (0 if key else 1)
    data = payload if payload is not None else b"\x00" * partition
    return tag.to_bytes(3, "little") + b"\x9d\x01\x2a" + struct.pack("<HH", width, height) + data


def _vp8x(width, height, flags=0):
    return bytes([flags]) + b"\x00\x00\x00" + (width - 1).to_bytes(3, "little") + (height - 1).to_bytes(3, "little")


def _interlaced_gray_8x8(raw_size):
    return _png(chunks=[_ihdr(8, 8, 0, 8, 1), (b"IDAT", zlib.compress(b"\x00" * raw_size)), (b"IEND", b"")])


VALID = {
    "png": (_png(800, 600), (800, 600)),
    "png_palette": (_png(chunks=[
        _ihdr(8, 4, 3), (b"PLTE", b"\x00\x00\x00"), (b"IDAT", zlib.compress(b"\x00" * 36)), (b"IEND", b""),
    ]), (8, 4)),
    "png_split_data": (_png(chunks=[
        _ihdr(), (b"IDAT", zlib.compress(b"\x00" * 100)[:5]), (b"IDAT", zlib.compress(b"\x00" * 100)[5:]),
        (b"IEND", b""),
    ]), (8, 4)),
    # Adam7: seven passes of 2, 2, 3, 6, 10, 20 and 36 bytes.
    "png_interlaced": (_interlaced_gray_8x8(79), (8, 8)),
    "png_trailing_bytes": (_png(800, 600) + b"junk after IEND", (800, 600)),
    "jpeg": (_jpeg(800, 600), (800, 600)),
    "jpeg_progressive": (_jpeg(800, 600, marker=0xC2, scans=3), (800, 600)),
    "jpeg_lossless_without_tables": (_jpeg(64, 48, tables=False, marker=0xC3), (64, 48)),
    "jpeg_trailing_bytes": (_jpeg(800, 600) + b"junk after EOI", (800, 600)),
    "gif": (_gif(320, 200), (320, 200)),
    "gif_frame_inside": (_gif(320, 200, left=20, frame=(300, 200)), (320, 200)),
    "gif_trailing_bytes": (_gif(320, 200) + b"junk", (320, 200)),
    "webp_lossless": (_riff((b"VP8L", _vp8l(1000, 1000))), (1000, 1000)),
    "webp_lossy": (_riff((b"VP8 ", _vp8(640, 480))), (640, 480)),
    "webp_extended": (_riff((b"VP8X", _vp8x(1000, 1000)), (b"VP8L", _vp8l(1000, 1000))), (1000, 1000)),
    "webp_extended_alpha": (
        _riff((b"VP8X", _vp8x(640, 480, 0x10)), (b"ALPH", b"\x00\x00"), (b"VP8 ", _vp8(640, 480))), (640, 480),
    ),
    "webp_trailing_bytes": (_riff((b"VP8L", _vp8l(1000, 1000))) + b"junk", (1000, 1000)),
}


def _reader(name):
    from qwed_new.core import image_headers

    return {"png": image_headers.png_size, "jpeg": image_headers.jpeg_size,
            "gif": image_headers.gif_size, "webp": image_headers.webp_size}[name.split("_")[0]]


@pytest.mark.parametrize("name", list(VALID))
def test_a_whole_image_states_its_size(name):
    data, size = VALID[name]
    assert _reader(name)(data) == size
    width, height = size
    result = ImageVerifier().verify_image(data, f"The image is {width}x{height} pixels")
    assert (result.status.value, admission_decision(result).value) == ("VERIFIED", "ADMIT")
    wrong = ImageVerifier().verify_image(data, f"The image is {width + 1}x{height} pixels")
    assert admission_decision(wrong).value == "BLOCKED"


@pytest.mark.parametrize("name", ["png", "jpeg", "gif", "webp_lossless"])
@pytest.mark.parametrize("wrap", [bytearray, memoryview])
def test_bytes_in_another_buffer_read_the_same(name, wrap):
    data, size = VALID[name]
    assert _reader(name)(wrap(data)) == size
    assert _reader(name)("not bytes") is None


def _with_bad_crc(data):
    return data[:29] + bytes([data[29] ^ 0xFF]) + data[30:]


ADVISORY = b"\x89PNG\r\n\x1a\n" + b"\x00" * 8 + struct.pack(">II", 800, 600) + b"\x00"

BROKEN = {
    "advisory_25_bytes": ADVISORY,
    "png_bad_crc": _with_bad_crc(_png(800, 600)),
    "png_no_iend": _png(800, 600)[:-12],
    "png_no_idat": _png(chunks=[_ihdr(800, 600), (b"IEND", b"")]),
    "png_ihdr_not_first": _png(chunks=[(b"tEXt", b"a\x00b"), _ihdr(800, 600), (b"IEND", b"")]),
    "png_zero_width": _png(0, 600),
    "png_bad_depth": _png(800, 600, colour=2, depth=4),
    "png_palette_without_plte": _png(chunks=[_ihdr(8, 4, 3), (b"IDAT", zlib.compress(b"\x00" * 36)), (b"IEND", b"")]),
    "png_palette_after_data": _png(chunks=[
        _ihdr(8, 4, 3), (b"IDAT", zlib.compress(b"\x00" * 36)), (b"PLTE", b"\x00\x00\x00"), (b"IEND", b""),
    ]),
    "png_truncated": _png(800, 600)[:40],
    # The data must inflate to exactly what 800x600 RGB calls for.
    "png_too_little_data": _png(800, 600, raw=b"\x00" * 10),
    "png_too_much_data": _png(800, 600, raw=b"\x00" * (600 * 2401 + 1)),
    "png_data_not_zlib": _png(chunks=[_ihdr(800, 600), (b"IDAT", b"not zlib at all"), (b"IEND", b"")]),
    "png_data_after_stream": _png(chunks=[
        _ihdr(), (b"IDAT", zlib.compress(b"\x00" * 100) + b"more"), (b"IEND", b""),
    ]),
    "png_data_split_by_a_chunk": _png(chunks=[
        _ihdr(), (b"IDAT", zlib.compress(b"\x00" * 100)[:5]), (b"tEXt", b"a\x00b"),
        (b"IDAT", zlib.compress(b"\x00" * 100)[5:]), (b"IEND", b""),
    ]),
    "png_interlaced_read_as_plain": _interlaced_gray_8x8(72),
    "png_over_the_bound": _png(chunks=[_ihdr(20000, 20000), (b"IDAT", zlib.compress(b"\x00")), (b"IEND", b"")]),
    "jpeg_no_eoi": _jpeg(800, 600, end=b""),
    "jpeg_two_frames": _jpeg(800, 600, frames=2),
    "jpeg_zero_height": _jpeg(800, 0),
    "jpeg_header_only": b"\xff\xd8\xff\xc0\x00\x11\x08\x02\x58\x03\x20",
    "jpeg_no_tables": _jpeg(800, 600, tables=False),
    "jpeg_scan_of_another_component": _jpeg(800, 600, scan=(2,)),
    "jpeg_no_scan": b"\xff\xd8" + DQT + _sof(800, 600) + b"\xff\xd9",
    "jpeg_five_components": b"\xff\xd8" + DQT + _sof(800, 600, components=(1, 2, 3, 4, 5)) + _sos() + ENTROPY + b"\xff\xd9",
    "jpeg_bad_tables": b"\xff\xd8\xff\xdb\x00\x04\x00\x01" + _sof(800, 600) + _sos() + ENTROPY + b"\xff\xd9",
    "gif_no_trailer": _gif(320, 200, trailer=b""),
    "gif_header_only": b"GIF89a" + struct.pack("<HH", 320, 200) + b"\x00\x00\x00\x00",
    "gif_frame_outside_screen": _gif(320, 200, left=1),
    "gif_frame_larger_than_screen": _gif(320, 200, frame=(800, 600)),
    "gif_lzw_size_1": _gif(320, 200, lzw=1),
    "gif_lzw_size_9": _gif(320, 200, lzw=9),
    "webp_riff_size_wrong": _riff((b"VP8L", _vp8l(1000, 1000)))[:-1],
    "webp_inter_frame": _riff((b"VP8 ", _vp8(640, 480, key=False))),
    "webp_frame_not_shown": _riff((b"VP8 ", _vp8(640, 480, shown=False))),
    "webp_partition_past_the_chunk": _riff((b"VP8 ", _vp8(640, 480, partition=100, payload=b"\x00" * 6))),
    "webp_lossless_header_only": _riff((b"VP8L", _vp8l(1000, 1000, data=b""))),
    "webp_lossless_bad_signature": _riff((b"VP8L", b"\x00" + _vp8l(10, 10)[1:])),
    "webp_extended_without_image": _riff((b"VP8X", _vp8x(1000, 1000))),
    "webp_extended_canvas_not_the_image": _riff((b"VP8X", _vp8x(1000, 1000)), (b"VP8L", _vp8l(800, 600))),
    "webp_extended_two_images": _riff(
        (b"VP8X", _vp8x(1000, 1000)), (b"VP8L", _vp8l(1000, 1000)), (b"VP8L", _vp8l(1000, 1000)),
    ),
    "webp_extended_animated": _riff(
        (b"VP8X", _vp8x(1000, 1000, 0x02)), (b"ANIM", b"\x00" * 6), (b"VP8L", _vp8l(1000, 1000)),
    ),
    "webp_extended_frames_without_flag": _riff(
        (b"VP8X", _vp8x(1000, 1000)), (b"ANMF", b"\x00" * 16 + _vp8l(1000, 1000)), (b"VP8L", _vp8l(1000, 1000)),
    ),
    # A whole 1x1 JPEG inside a segment decoders do not skip by its length,
    # before an 800x600 frame: decoders read the 1x1 one.
    "jpeg_hidden_in_ff00": b"\xff\xd8" + _segment(0x00, _jpeg(1, 1)) + _jpeg(800, 600)[2:],
    "jpeg_hidden_in_jpg": b"\xff\xd8" + _segment(0xC8, _jpeg(1, 1)) + _jpeg(800, 600)[2:],
    "jpeg_hidden_in_jpgn": b"\xff\xd8" + _segment(0xF0, _jpeg(1, 1)) + _jpeg(800, 600)[2:],
    "jpeg_hierarchical_dhp": (
        b"\xff\xd8" + DQT + _sof(800, 600) + _sof(1, 1, marker=0xDE) + _sos() + ENTROPY + b"\xff\xd9"
    ),
    "jpeg_differential_frame": _jpeg(800, 600, marker=0xC5),
    "jpeg_precision_0": b"\xff\xd8" + DQT + _sof(800, 600, precision=0) + _sos() + ENTROPY + b"\xff\xd9",
    "jpeg_baseline_precision_12": b"\xff\xd8" + DQT + _sof(800, 600, precision=12) + _sos() + ENTROPY + b"\xff\xd9",
    "jpeg_undefined_table": b"\xff\xd8" + DQT + _sof(800, 600, table=3) + _sos() + ENTROPY + b"\xff\xd9",
    "png_unknown_critical_chunk": _png(800, 600, chunks=[
        _ihdr(800, 600), (b"ABCD", b""), (b"IDAT", zlib.compress(b"\x00" * (600 * 2401))), (b"IEND", b""),
    ]),
    "png_empty_palette": _png(chunks=[_ihdr(8, 4, 3), (b"PLTE", b""), (b"IDAT", zlib.compress(b"\x00" * 36)), (b"IEND", b"")]),
    "png_palette_of_part_entries": _png(chunks=[
        _ihdr(8, 4, 3), (b"PLTE", b"\x00" * 4), (b"IDAT", zlib.compress(b"\x00" * 36)), (b"IEND", b""),
    ]),
    "png_two_palettes": _png(chunks=[
        _ihdr(8, 4, 3), (b"PLTE", b"\x00" * 3), (b"PLTE", b"\x00" * 3), (b"IDAT", zlib.compress(b"\x00" * 36)),
        (b"IEND", b""),
    ]),
    "png_palette_in_a_grey_image": _png(chunks=[
        _ihdr(8, 4, 0, 8), (b"PLTE", b"\x00" * 3), (b"IDAT", zlib.compress(b"\x00" * 36)), (b"IEND", b""),
    ]),
    "png_palette_larger_than_the_depth": _png(chunks=[
        _ihdr(8, 4, 3, 1), (b"PLTE", b"\x00" * 9), (b"IDAT", zlib.compress(b"\x00" * 8)), (b"IEND", b""),
    ]),
}


@pytest.mark.parametrize("name", list(BROKEN))
def test_a_size_claim_about_data_that_does_not_parse_is_unverifiable(name):
    data = BROKEN[name]
    for claim in ("The image is 800x600 pixels", "The image is 320x200 pixels", "The image is 1000x1000 pixels"):
        result = ImageVerifier().verify_image(data, claim)
        assert result.status.value == "UNVERIFIABLE", (name, claim)
        assert admission_decision(result).value == "BLOCKED"


def test_a_webp_canvas_of_2_to_the_32_pixels_or_more_is_not_read():
    from qwed_new.core.image_headers import webp_size

    assert webp_size(_riff((b"VP8X", _vp8x(65536, 65536)), (b"VP8L", _vp8l(16384, 16384)))) is None


@pytest.mark.timeout(60)
def test_inflating_is_counted_and_bounded():
    from qwed_new.core.image_headers import png_size

    # 4000 x 4000 grey: 16 MB of data, inflated in steps and not kept.
    big = _png(chunks=[_ihdr(4000, 4000, 0, 8), (b"IDAT", zlib.compress(b"\x00" * (4000 * 4001))), (b"IEND", b"")])
    started = time.perf_counter()
    assert png_size(big) == (4000, 4000)
    # A stream that inflates to far more than the header calls for stops at it.
    bomb = _png(chunks=[_ihdr(64, 64, 0, 8), (b"IDAT", zlib.compress(b"\x00" * 50_000_000)), (b"IEND", b"")])
    assert png_size(bomb) is None
    assert time.perf_counter() - started < 10


TEN_MB = 10_000_000


def _crafted(name):
    """Inputs of about 10 MB (the API's limit) built to make a walk slow."""
    if name == "png_long_tail_after_the_stream":
        # A stream that inflates to 16 MiB in few bytes, then 10 MB more in the
        # same chunk: each step must not copy the rest of the chunk.
        data = zlib.compress(b"\x00" * (4096 * 4097)) + b"\x00" * TEN_MB
        return _png(chunks=[_ihdr(4096, 4096, 0, 8), (b"IDAT", data), (b"IEND", b"")]), None
    if name == "png_many_empty_chunks":
        chunks = [_ihdr()] + [(b"abCd", b"")] * (TEN_MB // 12) + [(b"IDAT", zlib.compress(b"\x00" * 100)), (b"IEND", b"")]
        return _png(chunks=chunks), None
    if name == "gif_one_byte_sub_blocks":
        return _gif(320, 200)[:13] + b"\x21\xfe" + b"\x01x" * (TEN_MB // 2) + b"\x00" + _gif(320, 200)[13:], None
    if name == "jpeg_stuffing_in_the_scan":
        return _jpeg(800, 600)[:-2 - len(ENTROPY)] + b"\xff\x00" * (TEN_MB // 2) + b"\xff\xd9", (800, 600)
    if name == "jpeg_fill_bytes":
        return b"\xff\xd8" + b"\xff" * TEN_MB + _jpeg(800, 600)[2:], (800, 600)
    if name == "jpeg_many_scans":
        return _jpeg(800, 600, marker=0xC2, scans=TEN_MB // 20), None
    raise KeyError(name)


@pytest.mark.timeout(120)
@pytest.mark.parametrize("name", [
    "png_long_tail_after_the_stream", "png_many_empty_chunks", "gif_one_byte_sub_blocks",
    "jpeg_stuffing_in_the_scan", "jpeg_fill_bytes", "jpeg_many_scans",
])
def test_a_crafted_10_mb_input_is_read_quickly(name):
    data, size = _crafted(name)
    started = time.perf_counter()
    assert _reader(name)(data) == size
    assert time.perf_counter() - started < 5


def test_the_format_is_still_named():
    analysis = ImageVerifier().verify_image(ADVISORY, "The image is 800x600 pixels").developer_fields["analysis"]
    assert analysis["metadata"] == {"width": 0, "height": 0, "format": "PNG"}


# --- From the second review: tables, chunk order and pixel data that a
# decoder refuses, and the cost of a crafted image. ---------------------------

# The standard DC luminance table: 12 codes of lengths 2 to 9.
_DC_COUNTS = (0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0)


def _dht(table_class=0, number=0, counts=_DC_COUNTS, symbols=None):
    symbols = bytes(range(sum(counts))) if symbols is None else symbols
    return _segment(0xC4, bytes([table_class << 4 | number]) + bytes(counts) + symbols)


def _jpeg_with(*segments, marker=0xC0, components=(1,), scans=None):
    scans = scans if scans is not None else [_sos()]
    frame = _sof(800, 600, marker, components=components)
    return b"\xff\xd8" + DQT + b"".join(segments) + frame + b"".join(scan + ENTROPY for scan in scans) + b"\xff\xd9"


SECOND_REVIEW_VALID = {
    "jpeg_with_a_huffman_table": (_jpeg_with(_dht()), (800, 600)),
    "jpeg_with_a_restart_interval": (_jpeg_with(_segment(0xDD, b"\x00\x10")), (800, 600)),
    "jpeg_scan_with_huffman_tables_2": (
        _jpeg_with(_dht(0, 2), _dht(1, 2), scans=[_sos(entropy=0x22)]), (800, 600),
    ),
    "gif_code_size_8": (_gif(16, 16, lzw=8), (16, 16)),
    "webp_extended_alpha_then_exif": (
        _riff((b"VP8X", _vp8x(640, 480, 0x18)), (b"ALPH", b"\x00\x00"), (b"VP8 ", _vp8(640, 480)), (b"EXIF", b"II*\x00")),
        (640, 480),
    ),
    "webp_extended_icc_profile_first": (
        _riff((b"VP8X", _vp8x(1000, 1000, 0x20)), (b"ICCP", b"\x00" * 8), (b"VP8L", _vp8l(1000, 1000))), (1000, 1000),
    ),
}


@pytest.mark.parametrize("name", list(SECOND_REVIEW_VALID))
def test_a_whole_image_with_valid_tables_and_chunks_states_its_size(name):
    data, size = SECOND_REVIEW_VALID[name]
    assert _reader(name)(data) == size


def _vp8x_file(*chunks, flags=0, vp8x=None):
    return _riff((b"VP8X", vp8x if vp8x is not None else _vp8x(1000, 1000, flags)), *chunks)


_LOSSLESS = (b"VP8L", _vp8l(1000, 1000))
_LOSSY = (b"VP8 ", _vp8(1000, 1000))
_ALPHA = (b"ALPH", b"\x00\x00")

SECOND_REVIEW_BROKEN = {
    # No LZW data at all: decoders open it and cannot load it.
    "gif_26_bytes": _gif(800, 600, data=b"\x02\x00"),
    "gif_lzw_data_too_short": _gif(800, 600, data=b"\x02\x0a" + b"\x00" * 10 + b"\x00"),
    # 26 bytes: the size an image needed before, and smaller than any real one.
    "webp_lossless_26_bytes": _riff((b"VP8L", _vp8l(800, 600, data=b"\x00"))),
    "webp_extended_chunk_of_11": _vp8x_file(_LOSSLESS, vp8x=_vp8x(1000, 1000) + b"\x00"),
    "webp_extended_chunk_of_18": _vp8x_file(_LOSSLESS, vp8x=_vp8x(1000, 1000) + b"\x00" * 8),
    "webp_extended_reserved_flag_0": _vp8x_file(_LOSSLESS, flags=0x01),
    "webp_extended_reserved_flag_6": _vp8x_file(_LOSSLESS, flags=0x40),
    "webp_extended_reserved_flag_7": _vp8x_file(_LOSSLESS, flags=0x80),
    "webp_extended_alpha_before_lossless": _vp8x_file(_ALPHA, _LOSSLESS, flags=0x10),
    "webp_extended_alpha_after_the_image": _vp8x_file(_LOSSY, _ALPHA, flags=0x10),
    "webp_extended_alpha_not_next_to_the_image": _vp8x_file(_ALPHA, (b"EXIF", b"II*\x00"), _LOSSY, flags=0x18),
    "webp_extended_two_alpha_chunks": _vp8x_file(_ALPHA, _ALPHA, _LOSSY, flags=0x10),
    "webp_extended_two_vp8x_chunks": _vp8x_file((b"VP8X", _vp8x(1000, 1000)), _LOSSLESS),
    "webp_extended_icc_profile_after_the_image": _vp8x_file(_LOSSLESS, (b"ICCP", b"\x00" * 8), flags=0x20),
    "jpeg_huffman_table_number_4": _jpeg_with(_dht(0, 4)),
    "jpeg_huffman_table_class_2": _jpeg_with(_dht(2, 0)),
    "jpeg_huffman_symbols_past_the_segment": _jpeg_with(_dht(symbols=b"\x00" * 5)),
    "jpeg_huffman_codes_too_many_for_their_length": _jpeg_with(_dht(counts=(3,) + (0,) * 15, symbols=b"\x00\x01\x02")),
    "jpeg_huffman_dc_symbol_17": _jpeg_with(_dht(counts=(0, 1) + (0,) * 14, symbols=b"\x11")),
    "jpeg_restart_interval_of_length_5": _jpeg_with(_segment(0xDD, b"\x00\x10\x00")),
    "jpeg_scan_table_selector_4": _jpeg_with(scans=[_sos(entropy=0x40)]),
    "jpeg_scan_uses_an_undefined_huffman_table": _jpeg_with(scans=[_sos(entropy=0x22)]),
    "jpeg_progressive_band_past_63": _jpeg_with(marker=0xC2, scans=[_sos(start=0, end=0), _sos(start=64, end=70)]),
    "jpeg_progressive_dc_scan_with_ac": _jpeg_with(marker=0xC2, scans=[_sos(start=0, end=63)]),
    "jpeg_progressive_ac_scan_of_two_components": _jpeg_with(
        marker=0xC2, components=(1, 2), scans=[_sos((1, 2), 0, 0), _sos((1, 2), 1, 63)],
    ),
    "jpeg_progressive_refinement_not_one_bit": _jpeg_with(marker=0xC2, scans=[_sos(start=0, end=0, approx=0x31)]),
    "jpeg_lossless_predictor_0": _jpeg_with(marker=0xC3, scans=[_sos(start=0, end=0)]),
    "jpeg_lossless_predictor_8": _jpeg_with(marker=0xC3, scans=[_sos(start=8, end=0)]),
    "jpeg_more_scans_than_any_image": _jpeg(800, 600, marker=0xC2, scans=1_001),
    # Zero-length IDAT chunks past the number any real image has.
    "png_more_chunks_than_any_image": _png(chunks=[_ihdr(800, 600)] + [(b"IDAT", b"")] * 16_384 + [
        (b"IDAT", zlib.compress(b"\x00" * (600 * 2401))), (b"IEND", b""),
    ]),
}


@pytest.mark.parametrize("name", list(SECOND_REVIEW_BROKEN))
def test_data_a_decoder_refuses_is_unverifiable(name):
    data = SECOND_REVIEW_BROKEN[name]
    for claim in ("The image is 800x600 pixels", "The image is 1000x1000 pixels"):
        result = ImageVerifier().verify_image(data, claim)
        assert result.status.value == "UNVERIFIABLE", (name, claim)
        assert admission_decision(result).value == "BLOCKED"


def test_a_thousand_scans_and_a_thousand_idat_chunks_are_still_read():
    assert _reader("jpeg")(_jpeg(800, 600, marker=0xC2, scans=1_000)) == (800, 600)
    png = _png(chunks=[_ihdr(800, 600)] + [(b"IDAT", b"")] * 1_000 + [
        (b"IDAT", zlib.compress(b"\x00" * (600 * 2401))), (b"IEND", b""),
    ])
    assert _reader("png")(png) == (800, 600)


def _stored(payload):
    return b"\x01" + struct.pack("<HH", len(payload), len(payload) ^ 0xFFFF) + payload


def _empty_dynamic_blocks(count):
    """*count* dynamic Huffman deflate blocks that hold only an end-of-block
    code: each makes an inflater build two code tables for nothing."""
    acc = bits = 0
    out = bytearray()

    def put(value, width):
        nonlocal acc, bits
        acc |= value << bits
        bits += width
        while bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            bits -= 8

    order = (16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15)
    lengths = {18: 1, 0: 2, 1: 2}
    for _ in range(count):
        put(0, 1)  # not the last block
        put(2, 2)  # dynamic Huffman codes
        put(0, 5)  # 257 literal and length codes
        put(0, 5)  # 1 distance code
        put(14, 4)  # 18 code length codes
        for symbol in order[:18]:
            put(lengths.get(symbol, 0), 3)
        # 256 zero lengths (138 + 118), end-of-block length 1, distance 0:
        # code 18 is "0", code 0 is "01" and code 1 is "11", bits reversed.
        put(0, 1)
        put(138 - 11, 7)
        put(0, 1)
        put(118 - 11, 7)
        put(0b11, 2)
        put(0b01, 2)
        put(0, 1)  # the end-of-block symbol
    # An empty stored block, which aligns the stream to a byte.
    put(0, 1)
    put(0, 2)
    if bits:
        out.append(acc & 0xFF)
    return bytes(out) + b"\x00\x00\xff\xff"


@pytest.mark.parametrize("filler, count", [("stored", 30_000), ("dynamic", 20_000)])
def test_a_stream_that_inflates_to_far_less_than_it_takes_is_not_read(filler, count):
    raw = b"\x00" * 36  # 8 x 4 grey
    blocks = b"\x00\x00\x00\xff\xff" * count if filler == "stored" else _empty_dynamic_blocks(count)
    body = b"\x78\x01" + blocks + _stored(raw) + struct.pack(">I", zlib.adler32(raw))
    assert zlib.decompress(body) == raw
    data = _png(chunks=[_ihdr(8, 4, 0, 8), (b"IDAT", body), (b"IEND", b"")])
    assert _reader("png")(data) is None
    # The same pixels without the filler are read.
    plain = _png(chunks=[_ihdr(8, 4, 0, 8), (b"IDAT", zlib.compress(raw)), (b"IEND", b"")])
    assert _reader("png")(plain) == (8, 4)


def test_a_batch_walks_the_image_once(monkeypatch):
    calls = []
    real = ImageVerifier._extract_metadata

    def counting(self, image_bytes):
        calls.append(len(image_bytes))
        return real(self, image_bytes)

    monkeypatch.setattr(ImageVerifier, "_extract_metadata", counting)
    claims = [f"The image is {w}x600 pixels" for w in (800, 801, 802, 803, 804)]
    result = ImageVerifier().verify_batch(_png(800, 600), claims)
    assert len(calls) == 1
    assert result.developer_fields["summary"]["total"] == 5


def test_the_route_walks_the_image_off_the_event_loop(client, monkeypatch):  # noqa: F811
    import asyncio

    ran = []
    real = asyncio.to_thread

    async def recording(func, *args, **kwargs):
        ran.append(func.__name__)
        return await real(func, *args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", recording)
    files = {"image": ("i.png", _png(800, 600), "image/png")}
    response = client.post("/verify/image", files=files, data={"claim": "The image is 800x600 pixels"}).json()
    assert "verify_image" in ran
    assert response["status"] == "VERIFIED"


@pytest.mark.timeout(120)
@pytest.mark.parametrize("depth", [8, 16])
def test_a_4096_by_4096_rgba_image_is_read(depth):
    from qwed_new.core.image_headers import png_size

    row = b"\x00" * (1 + 4096 * 4 * depth // 8)
    packer = zlib.compressobj(1)
    stream = b"".join(packer.compress(row * 256) for _ in range(16)) + packer.flush()
    data = _png(chunks=[_ihdr(4096, 4096, 6, depth), (b"IDAT", stream), (b"IEND", b"")])
    started = time.perf_counter()
    assert png_size(data) == (4096, 4096)
    assert time.perf_counter() - started < 10
