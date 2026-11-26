from __future__ import annotations

import hashlib
import struct
from typing import TYPE_CHECKING

BEGIN_NODE, END_NODE, PROP, NOP, END = 1, 2, 3, 4, 9
FIT_MAGIC = 0xD00DFEED
IMAGE = "/images/kernel-1"
PSS_TRAILER = 0xBC
SELECTED = 2
SIGNATURE = "/configurations/conf-1/signature-1"

if TYPE_CHECKING:
    from collections.abc import Callable

    Trace = Callable[[str], None]


class Fit:
    def __init__(self, data: bytes) -> None:
        self.data = data
        try:
            header = struct.unpack_from(">10I", data)
        except struct.error as error:
            msg = "FIT is shorter than its header"
            raise ValueError(msg) from error
        if header[0] != FIT_MAGIC or header[1] > len(data):
            msg = "invalid FIT header"
            raise ValueError(msg)
        self.total, self.so, self.st, self.ss, self.sz = (
            header[1],
            header[2],
            header[3],
            header[8],
            header[9],
        )
        self.block = data[self.so : self.so + self.sz]
        self.strings = data[self.st : self.st + self.ss]
        self.events: list[tuple[int, int, int, str, str | None]] = []
        self.props: dict[tuple[str, str], tuple[int, int, int, int]] = {}
        self._parse()

    def _parse(self) -> None:  # ruff: ignore[complex-structure]
        at, stack, names = 0, [], []
        block = self.block
        while at < len(block):
            start = at
            tag = be32(block, at)
            at += 4
            if tag == BEGIN_NODE:
                end = block.find(b"\0", at)
                if end < 0:
                    msg = "unterminated node name"
                    raise ValueError(msg)
                name = block[at:end].decode()
                at = (end + 4) & ~3
                names.append(name)
                path = "/" + "/".join(names[1:])
                stack.append(path)
                self.events.append((tag, start, at, path, None))
            elif tag == END_NODE:
                if not stack:
                    msg = "malformed FIT structure"
                    raise ValueError(msg)
                path = stack.pop()
                names.pop()
                self.events.append((tag, start, at, path, None))
            elif tag == PROP:
                if not stack:
                    msg = "property outside a node"
                    raise ValueError(msg)
                size, nameoff = struct.unpack_from(">II", block, at)
                at += 8
                end = self.strings.find(b"\0", nameoff)
                if end < 0:
                    msg = "unterminated property name"
                    raise ValueError(msg)
                name = self.strings[nameoff:end].decode()
                value_start = at
                at = (at + size + 3) & ~3
                self.props[stack[-1], name] = (start, at, value_start, size)
                self.events.append((tag, start, at, stack[-1], name))
            elif tag in {NOP, END}:
                self.events.append((tag, start, at, stack[-1] if stack else "", None))
                if tag == END:
                    break
            else:
                msg = f"invalid FDT token {tag} at 0x{start:x}"
                raise ValueError(msg)
        if stack or at != len(block):
            msg = "malformed FIT structure"
            raise ValueError(msg)

    def prop(self, path: str, name: str) -> bytes:
        _, _, start, size = self.props[path, name]
        return self.block[start : start + size]

    def signed_stream(  # ruff: ignore[complex-structure, too-many-branches]
        self, sig_path: str
    ) -> bytes:
        included = [
            x.decode() for x in self.prop(sig_path, "hashed-nodes").split(b"\0") if x
        ]
        if not included:
            msg = "empty hashed-nodes"
            raise ValueError(msg)
        start, length = struct.unpack(">II", self.prop(sig_path, "hashed-strings"))
        if start + length > len(self.strings):
            msg = "invalid hashed-strings range"
            raise ValueError(msg)
        pieces, wants = [], []
        want = 0
        region_start = None
        for tag, start_off, end_off, path, name in self.events:
            stop_at = end_off
            if tag == BEGIN_NODE:
                wants.append(want)
                if want == 1:
                    stop_at = start_off
                if path in included:
                    want = SELECTED
                elif want:
                    want -= 1
                else:
                    stop_at = start_off
                take = want > 0
            elif tag == END_NODE:
                take = want > 0
                want = wants.pop()
            elif tag == PROP:
                take = want >= SELECTED and name != "data"
                stop_at = start_off
            elif tag == NOP:
                take = want >= SELECTED
                stop_at = start_off
            else:
                take = True
            if take and region_start is None:
                region_start = start_off
            if not take and region_start is not None:
                pieces.append(self.block[region_start:stop_at])
                region_start = None
        if region_start is not None:
            pieces.append(self.block[region_start : self.events[-1][2]])
        pieces.append(self.strings[start : start + length])
        return b"".join(pieces)


def be32(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def mgf1(seed: bytes, length: int) -> bytes:
    made = b"".join(
        hashlib.sha256(seed + i.to_bytes(4, "big")).digest()
        for i in range((length + 31) // 32)
    )
    return made[:length]


def verifies(fit: Fit, key: tuple[int, int]) -> bool:
    signature = fit.prop(SIGNATURE, "value")
    modulus, exponent = key
    length = (modulus.bit_length() + 7) // 8
    encoded = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(
        length, "big"
    )
    if encoded[-1] != PSS_TRAILER:
        return False
    hashed = encoded[-33:-1]
    masked = encoded[:-33]
    db = bytearray(a ^ b for a, b in zip(masked, mgf1(hashed, len(masked))))
    db[0] &= 0x7F
    try:
        delimiter = db.index(1)
    except ValueError:
        return False
    if any(db[:delimiter]):
        return False
    digest = hashlib.sha256(fit.signed_stream(SIGNATURE)).digest()
    return hashlib.sha256(b"\0" * 8 + digest + db[delimiter + 1 :]).digest() == hashed
