from __future__ import annotations

import hashlib
import struct

import pytest

from firebreak import sparse

BLOCK = sparse.BLOCK
LIMIT = 0x100000


def image_of(seed: int, blocks: int, *, zero: int = 5) -> bytes:
    data = bytearray()
    number = 0
    while len(data) < blocks * BLOCK:
        source = hashlib.sha256(f"{seed}:{number}".encode()).digest()
        number += 1
        count = 1 + source[1] % 8
        if source[0] % 10 < zero:
            data += bytes(BLOCK * count)
        else:
            data += (source * BLOCK)[: BLOCK * count]
    return bytes(data[: blocks * BLOCK])


def test_a_large_image_is_cut_at_download_boundaries() -> None:
    image = image_of(7, 3000, zero=0)
    parts = sparse.pieces(image, LIMIT)
    assert len(parts) > 2
    starts = []
    for number, part in enumerate(parts):
        blk_sz, chunks = sparse.parse(part)
        assert blk_sz == BLOCK
        magic, major, _minor, file_hdr, chunk_hdr, _blk, total, count, _sum = (
            sparse.HEADER.unpack_from(part)
        )
        assert (magic, major, file_hdr, chunk_hdr) == (0xED26FF3A, 1, 28, 12)
        assert count == len(chunks)
        if number == 0:
            assert chunks[0][0] == sparse.RAW
            starts.append(0)
        else:
            assert chunks[0][0] == sparse.DONT_CARE
            starts.append(chunks[0][1])
        assert total == sum(count for _kind, count, _body in chunks)
    assert starts == sorted(starts)
    assert all(
        kind != sparse.DONT_CARE
        for part in parts
        for kind, _, _ in sparse.parse(part)[1][1:]
    )
    sparse.check(image, parts, LIMIT)


def test_check_refuses_a_piece_that_differs_or_is_missing_or_doubled() -> None:
    image = image_of(11, 900)
    parts = sparse.pieces(image, LIMIT)
    assert len(parts) > 1
    with pytest.raises(ValueError, match="do not put the image back"):
        sparse.check(image, parts[:-1], LIMIT)
    with pytest.raises(ValueError, match="missing or written twice"):
        sparse.check(image + bytes(BLOCK), parts, LIMIT)
    with pytest.raises(ValueError, match="do not put"):
        sparse.check(image[:-BLOCK], parts, LIMIT)
    with pytest.raises(ValueError, match="written twice"):
        sparse.check(image, [*parts, parts[0]], LIMIT)
    with pytest.raises(ValueError, match="download limit"):
        sparse.check(image, parts, max(map(len, parts)) - 1)


@pytest.mark.parametrize(
    "damage",
    [
        "magic",
        "major",
        "file-header",
        "chunk-header",
        "short-header",
        "short-chunk",
        "raw-size",
        "fill-size",
        "crc32",
        "count",
        "truncated",
    ],
)
def test_parse_is_strict_about_what_the_loader_reads(  # ruff: ignore[complex-structure, too-many-branches]
    damage: str,
) -> None:
    (part,) = sparse.pieces(image_of(3, 4, zero=0), LIMIT)
    header = list(sparse.HEADER.unpack_from(part))
    chunk = list(sparse.CHUNK.unpack_from(part, 28))
    if damage == "magic":
        header[0] = 0
    elif damage == "major":
        header[1] = 2
    elif damage == "file-header":
        header[3] = 30
    elif damage == "chunk-header":
        header[4] = 16
    elif damage == "crc32":
        chunk[0] = 0xCAC4
    elif damage == "raw-size":
        chunk[2] += 1
    elif damage == "fill-size":
        (fill,) = sparse.pieces(bytes(4 * BLOCK), LIMIT)
        part = fill
        chunk = list(sparse.CHUNK.unpack_from(part, 28))
        chunk[3] += 1
    elif damage == "count":
        header[7] += 1
    broken = bytearray(part)
    if damage == "short-header":
        broken = broken[:27]
    elif damage == "short-chunk":
        broken = broken[:-1]
    elif damage == "truncated":
        struct.pack_into("<I", broken, 36, len(broken) * 2)
    else:
        broken[:28] = sparse.HEADER.pack(*header)
        if damage != "count":
            broken[28:40] = sparse.CHUNK.pack(*chunk)
    with pytest.raises(ValueError, match=r"sparse|chunk|RAW|FILL"):
        sparse.parse(bytes(broken))


@pytest.mark.parametrize("seed", [1, 2, 3])
@pytest.mark.parametrize("blocks", [1, 2, 7, 300, 3000])
def test_pieces_put_an_image_back_within_the_download_limit(
    seed: int, blocks: int
) -> None:
    image = image_of(seed, blocks)
    parts = sparse.pieces(image, LIMIT)
    sparse.check(image, parts, LIMIT)
    assert all(0 < len(part) <= LIMIT for part in parts)
    assert sparse.replay(parts, len(image)) == image
    assert sparse.parse(parts[0])[1][0][0] != sparse.DONT_CARE


def test_pieces_refuse_what_cannot_be_written_in_blocks() -> None:
    for image in (b"", b"x" * (BLOCK - 1), b"x" * (BLOCK + 1)):
        with pytest.raises(ValueError, match="multiple of the block size"):
            sparse.pieces(image, LIMIT)


def test_replay_refuses_another_block_size() -> None:
    (part,) = sparse.pieces(bytes(3 * BLOCK), LIMIT)
    other = bytearray(part)
    struct.pack_into("<H", other, 12, 2048)
    with pytest.raises(ValueError, match="blk_sz"):
        sparse.replay([bytes(other)], 3 * BLOCK)


def test_zero_blocks_travel_as_fill_and_an_all_zero_image_is_one_run() -> None:
    image = bytes(3 * BLOCK) + b"x" * BLOCK + bytes(2 * BLOCK)
    (part,) = sparse.pieces(image, LIMIT)
    assert [kind for kind, _count, _body in sparse.parse(part)[1]] == [
        sparse.FILL,
        sparse.RAW,
        sparse.FILL,
    ]
    (part,) = sparse.pieces(bytes(9 * BLOCK), LIMIT)
    assert sparse.parse(part)[1] == [(sparse.FILL, 9, bytes(4))]
    assert sparse.replay([part], 9 * BLOCK) == bytes(9 * BLOCK)
