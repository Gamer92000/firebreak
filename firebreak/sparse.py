from __future__ import annotations

import re
import struct

BLOCK = 4096
CHUNK = struct.Struct("<HHII")
DONT_CARE, FILL, RAW = 0xCAC3, 0xCAC2, 0xCAC1
FILL_SIZE = 4
HEADER = struct.Struct("<IHHHHIIII")
KINDS = frozenset({RAW, FILL, DONT_CARE})
MAGIC = 0xED26FF3A


def _pack(chunks: list[tuple[int, int, bytes]], limit: int) -> list[bytes]:
    parts: list[bytes] = []
    current: list[tuple[int, int, bytes]] = []
    used = 0
    start: int | None = None
    offset = 0
    budget = limit - HEADER.size

    def emit() -> None:
        nonlocal current, used, start
        if current:
            lead = b"" if start == 0 else CHUNK.pack(DONT_CARE, 0, start, CHUNK.size)
            span = start + sum(count for _kind, count, _body in current)
            parts.append(
                HEADER.pack(
                    MAGIC,
                    1,
                    0,
                    HEADER.size,
                    CHUNK.size,
                    BLOCK,
                    span,
                    len(current) + bool(lead),
                    0,
                )
                + lead
                + b"".join(
                    CHUNK.pack(kind, 0, count, CHUNK.size + len(body)) + body
                    for kind, count, body in current
                )
            )
        current, used, start = [], 0, None

    for kind, count, payload in chunks:
        placed = 0
        while placed < count:
            if start is None:
                start = offset
            room = budget - used - (CHUNK.size if start else 0)
            if kind == FILL:
                fits, take = CHUNK.size + FILL_SIZE <= room, count - placed
            else:
                take = max(0, (room - CHUNK.size) // BLOCK)
                fits = take > 0
                take = min(take, count - placed)
            if not fits:
                emit()
                continue
            if kind == RAW:
                body = payload[placed * BLOCK : (placed + take) * BLOCK]
            else:
                body = payload
            current.append((kind, take, body))
            used += CHUNK.size + len(body)
            offset += take
            placed += take
            if placed < count:
                emit()
    emit()
    return parts


def _zero_runs(image: bytes) -> list[tuple[int, int]]:
    runs = []
    for match in re.finditer(b"\x00{%d,}" % BLOCK, image):
        first = -(-match.start() // BLOCK)
        end = match.end() // BLOCK
        if end > first:
            runs.append((first, end - first))
    return runs


def check(image: bytes, parts: list[bytes], limit: int) -> None:
    if replay(parts, len(image)) != image:
        msg = "the pieces do not put the image back"
        raise ValueError(msg)
    writes: set[int] = set()
    twice = False
    for part in parts:
        if len(part) > limit:
            msg = f"a piece is {len(part)} bytes, over the download limit"
            raise ValueError(msg)
        offset = 0
        for kind, count, _body in parse(part)[1]:
            if kind != DONT_CARE:
                blocks = set(range(offset, offset + count))
                twice |= not writes.isdisjoint(blocks)
                writes |= blocks
            offset += count
    if twice or len(writes) != len(image) // BLOCK:
        msg = "blocks are missing or written twice"
        raise ValueError(msg)


def parse(  # ruff: ignore[too-many-locals]
    part: bytes,
) -> tuple[int, list[tuple[int, int, bytes]]]:
    try:
        magic, major, _minor, file_hdr, chunk_hdr, blk_sz, _total, count, _sum = (
            HEADER.unpack_from(part)
        )
    except struct.error as error:
        msg = "sparse file is shorter than its header"
        raise ValueError(msg) from error
    if (
        magic != MAGIC
        or major != 1
        or file_hdr != HEADER.size
        or chunk_hdr != CHUNK.size
    ):
        msg = "not a sparse file the loader takes"
        raise ValueError(msg)
    at, chunks = file_hdr, []
    while at < len(part):
        try:
            kind, _reserved, size, total = CHUNK.unpack_from(part, at)
        except struct.error as error:
            msg = "truncated chunk header"
            raise ValueError(msg) from error
        body = part[at + CHUNK.size : at + total]
        if len(body) != total - CHUNK.size:
            msg = "truncated chunk"
            raise ValueError(msg)
        if kind == RAW and len(body) != size * blk_sz:
            msg = "RAW chunk size mismatch"
            raise ValueError(msg)
        if kind == FILL and len(body) != FILL_SIZE:
            msg = "FILL chunk size mismatch"
            raise ValueError(msg)
        if kind not in KINDS:
            msg = "chunk type the loader does not take"
            raise ValueError(msg)
        chunks.append((kind, size, body))
        at += total
    if len(chunks) != count:
        msg = "chunk count mismatch"
        raise ValueError(msg)
    return blk_sz, chunks


def pieces(image: bytes, limit: int) -> list[bytes]:
    if not image or len(image) % BLOCK:
        msg = "image size must be a multiple of the block size"
        raise ValueError(msg)
    blocks = len(image) // BLOCK
    chunks: list[tuple[int, int, bytes]] = []
    at = 0
    for first, count in _zero_runs(image):
        if first > at:
            chunks.append((RAW, first - at, image[at * BLOCK : first * BLOCK]))
        chunks.append((FILL, count, bytes(FILL_SIZE)))
        at = first + count
    if at < blocks:
        chunks.append((RAW, blocks - at, image[at * BLOCK :]))
    if not chunks:
        chunks.append((FILL, blocks, bytes(FILL_SIZE)))
    return _pack(chunks, limit)


def replay(parts: list[bytes], size: int) -> bytes:
    image = bytearray(size)
    for part in parts:
        blk_sz, chunks = parse(part)
        if blk_sz != BLOCK:
            msg = "blk_sz differs"
            raise ValueError(msg)
        offset = 0
        for kind, count, body in chunks:
            if kind == DONT_CARE:
                offset += count
            elif kind == FILL:
                span = slice(offset * BLOCK, (offset + count) * BLOCK)
                image[span] = body * (count * BLOCK // FILL_SIZE)
                offset += count
            else:
                image[offset * BLOCK : (offset + count) * BLOCK] = body
                offset += count
    return bytes(image)
