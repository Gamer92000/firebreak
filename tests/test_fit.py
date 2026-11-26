from __future__ import annotations

import hashlib
import struct

import pytest
from conftest import FIT_KEY, FitTree, fit_image, fit_stream

from firebreak.mediatek import fit

DIRTY = 1255
LENGTH = FIT_KEY[0].bit_length() // 8
NO_DELIMITER = 1412
PAYLOAD = b"the patched loader" * 30
SIGNATURE = fit.SIGNATURE
STOCK = b"the stock loader" * 40


def crafted(number: int) -> bytes:
    return number.to_bytes(LENGTH, "big")


def raw(block: bytes, strings: bytes = b"\0") -> bytes:
    return (
        struct.pack(
            ">10I",
            fit.FIT_MAGIC,
            56 + len(block) + len(strings),
            56,
            56 + len(block),
            40,
            17,
            16,
            0,
            len(strings),
            len(block),
        )
        + bytes(16)
        + block
        + strings
    )


def replaced(image: bytes, was: bytes, now: bytes, *, nth: int = 0) -> bytes:
    assert len(was) == len(now)
    at = -1
    for _ in range(nth + 1):
        at = image.index(was, at + 1)
    return image[:at] + now + image[at + len(was) :]


def signed_tree(hashed: bytes, strings: tuple[int, int]) -> FitTree:
    tree = FitTree()
    tree.begin("")
    tree.begin("images")
    tree.begin("kernel-1")
    tree.nop()
    tree.prop("description", b"first\0")
    tree.prop("data", b"the payload")
    tree.begin("hash-1")
    tree.prop("algo", b"sha256\0")
    tree.prop("value", b"its hash")
    tree.end()
    tree.prop("type", b"after the sub-node\0")
    tree.nop()
    tree.end()
    tree.begin("other")
    tree.prop("description", b"not listed\0")
    tree.end()
    tree.nop()
    tree.end()
    tree.begin("configurations")
    tree.begin("conf-1")
    tree.begin("signature-1")
    tree.prop("hashed-nodes", hashed)
    tree.prop("hashed-strings", struct.pack(">II", *strings))
    tree.prop("value", bytes(LENGTH))
    tree.end()
    tree.end()
    tree.end()
    tree.end()
    return tree


def test_a_listed_sub_node_is_signed_too() -> None:
    tree = signed_tree(
        b"/images/kernel-1\0/images/kernel-1/hash-1\0", (0, tree_strings())
    )
    stream = fit.Fit(tree.image()).signed_stream(SIGNATURE)
    for present in (b"first\0", b"sha256\0", b"its hash", b"after the sub-node\0"):
        assert present in stream
    assert b"not listed\0" not in stream
    assert b"the payload" not in stream


def test_a_sealed_fit_verifies_and_exposes_its_parts() -> None:
    image = fit_image(PAYLOAD, stock=STOCK)
    parsed = fit.Fit(image)
    assert parsed.prop(fit.IMAGE, "data") == PAYLOAD
    assert (
        parsed.prop(fit.IMAGE + "/hash-1", "value") == hashlib.sha256(PAYLOAD).digest()
    )
    assert parsed.prop(fit.IMAGE + "/hash-1", "algo") == b"sha256\0"
    assert parsed.prop(SIGNATURE, "hashed-nodes") == b"/images/archive/kernel-1\0"
    assert parsed.prop("/images/archive/kernel-1", "data") == STOCK
    assert len(parsed.prop(SIGNATURE, "value")) == LENGTH
    assert fit.verifies(parsed, FIT_KEY)


def test_an_edit_of_the_environment_breaks_the_signature() -> None:
    image = fit_image(PAYLOAD, stock=STOCK)
    edited = replaced(image, b"u-boot\0", b"U-Boot\0", nth=1)
    assert fit_stream(edited) != fit_stream(image)
    assert not fit.verifies(fit.Fit(edited), FIT_KEY)
    assert fit_stream(fit_image(b"another payload" * 25, stock=STOCK)) == fit_stream(
        image
    )


def test_another_key_is_refused() -> None:
    parsed = fit.Fit(fit_image(PAYLOAD, stock=STOCK))
    assert not fit.verifies(parsed, (FIT_KEY[0], 3))
    assert not fit.verifies(parsed, (FIT_KEY[0] ^ 0xFF, FIT_KEY[1]))
    assert not fit.verifies(parsed, (FIT_KEY[0] * 3, FIT_KEY[1]))


@pytest.mark.parametrize(
    "signature",
    [
        crafted(DIRTY),
        crafted(NO_DELIMITER),
        crafted(2),
        crafted(2**1024 - FIT_KEY[0] - 1),
        bytes(LENGTH),
    ],
)
def test_crafted_signatures_are_refused(signature: bytes) -> None:
    image = fit_image(PAYLOAD, stock=STOCK)
    assert not fit.verifies(fit.Fit(with_signature(image, signature)), FIT_KEY)


@pytest.mark.parametrize(
    "damage",
    [
        "magic",
        "short",
        "size",
        "token",
        "unterminated-name",
        "unterminated-property",
        "unclosed",
        "unopened",
        "trailing",
    ],
)
def test_malformed_images_are_refused(damage: str) -> None:
    image = fit_image(PAYLOAD, stock=STOCK)
    begin = struct.pack(">I", fit.BEGIN_NODE)
    end = struct.pack(">I", fit.END_NODE)
    broken = {
        "magic": b"\0\0\0\0" + image[4:],
        "short": image[:30],
        "size": image[:4] + struct.pack(">I", 10**7) + image[8:],
        "token": image[:56] + struct.pack(">I", 7) + image[60:],
        "trailing": image[:36]
        + struct.pack(">I", struct.unpack_from(">I", image, 36)[0] + 4)
        + image[40:],
        "unclosed": raw(begin + bytes(4) + struct.pack(">I", fit.END)),
        "unopened": raw(end + struct.pack(">I", fit.END)),
        "unterminated-name": raw(begin + b"name"),
        "unterminated-property": raw(
            begin
            + bytes(4)
            + struct.pack(">III", fit.PROP, 0, 9999)
            + end
            + struct.pack(">I", fit.END)
        ),
    }[damage]
    with pytest.raises(ValueError, match=r"FIT|FDT|node|property|structure"):
        fit.Fit(broken)


def test_missing_parts_and_bad_ranges_are_refused() -> None:
    image = fit_image(PAYLOAD, stock=STOCK)
    parsed = fit.Fit(image)
    with pytest.raises(KeyError):
        parsed.prop("/images/kernel-2", "data")
    with pytest.raises(KeyError):
        parsed.prop(fit.IMAGE, "type")
    for name, value in (
        ("hashed-nodes", bytes(26)),
        ("hashed-strings", struct.pack(">II", 0, 10**6)),
        ("hashed-strings", struct.pack(">II", 10**6, 0)),
    ):
        broken = fit.Fit(with_property(image, name, value))
        with pytest.raises(ValueError, match="hashed"):
            broken.signed_stream(SIGNATURE)


def test_signed_stream_takes_what_the_signature_names() -> None:
    tree = signed_tree(b"/images/kernel-1\0", (4, 10))
    image = tree.image()
    stream = fit.Fit(image).signed_stream(SIGNATURE)
    strings = image[struct.unpack_from(">I", image, 12)[0] :]
    assert stream.endswith(strings[4:14])
    assert b"first\0" in stream
    assert b"after the sub-node\0" in stream
    for absent in (b"the payload", b"its hash", b"not listed\0", b"sha256\0"):
        assert absent not in stream


def test_the_signature_covers_neither_the_payload_nor_its_hash() -> None:
    image = fit_image(PAYLOAD, stock=STOCK)
    digest = hashlib.sha256(PAYLOAD).digest()
    edited = replaced(image, PAYLOAD, b"edited after sealing" * 27)
    stale = replaced(edited, digest, bytes(32))
    parsed = fit.Fit(stale)
    assert parsed.prop(fit.IMAGE, "data") == b"edited after sealing" * 27
    assert fit.verifies(parsed, FIT_KEY)
    assert fit_stream(stale) == fit_stream(image)
    payload = parsed.prop(fit.IMAGE, "data")
    assert hashlib.sha256(payload).digest() != parsed.prop(
        fit.IMAGE + "/hash-1", "value"
    )


def tree_strings() -> int:
    return len(signed_tree(b"/images/kernel-1\0", (0, 0)).strings)


def with_property(image: bytes, name: str, value: bytes) -> bytes:
    parsed = fit.Fit(image)
    at = parsed.so + parsed.props[SIGNATURE, name][2]
    old = parsed.prop(SIGNATURE, name)
    return (
        image[:at] + value.ljust(len(old), b"\0")[: len(old)] + image[at + len(old) :]
    )


def with_signature(image: bytes, signature: bytes) -> bytes:
    parsed = fit.Fit(image)
    at = parsed.so + parsed.props[SIGNATURE, "value"][2]
    return image[:at] + signature.ljust(LENGTH, b"\0")[:LENGTH] + image[at + LENGTH :]
