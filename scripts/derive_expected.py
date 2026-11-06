"""Independent expectations for fixtures/cases.json and the length sweep.

Lays the C structs out with `struct` (LP64, little-endian), then follows the
comparator source by hand: which field each line reads, and whether that
field lies inside the object it is read from. It does not import or call
the Rust code. Usage: derive_expected.py > fixtures/expected.json
"""
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STRING_SIZE, OBJECT_SIZE = 24, 40


def pre(a, b):
    """GENERAL_NAME_cmp -> ASN1_TYPE_cmp over objects that are ASN1_STRINGs."""
    # ASN1_TYPE.type (offset 0) is ASN1_STRING.length; value (offset 8) is .data
    ta, tb = len(a), len(b)
    if ta != tb:
        return "Different"
    t = ta
    if t == 5:                       # V_ASN1_NULL: result 0, nothing else read
        return "Equal" if a == b else "WrongResult"
    if t == 6:                       # V_ASN1_OBJECT: OBJ_cmp on the TLV bytes
        if len(a) < 24:              # ASN1_OBJECT.length is at offset 20..24
            return "OutOfAllocationRead"
        return obj_like(a, b)
    if t == 1:
        raise ValueError("a TLV is at least 2 bytes")
    return string_like(a, b)         # default: ASN1_STRING_cmp on the TLV bytes


def string_like(a, b):
    """ASN1_STRING_cmp where each 'struct' is the TLV byte array itself."""
    if len(a) < 4:
        return "OutOfAllocationRead"           # a->length needs bytes 0..4
    la, lb = struct.unpack_from("<i", a)[0], struct.unpack_from("<i", b)[0]
    if la != lb:
        return "Different" if a != b else "WrongResult"
    if la != 0:
        if len(a) < 16:
            return "OutOfAllocationRead"       # a->data needs bytes 8..16
        ptr = struct.unpack_from("<Q", a, 8)[0]
        if ptr < 0x10000 or ptr >= 0x10000 * 64:  # outside every model region
            return "WildPointerRead"
        raise ValueError("fixture bytes must not look like model addresses")
    return "Equal" if a == b else "WrongResult"


def obj_like(a, b):
    raise ValueError("no fixture reaches OBJ_cmp with >= 24 bytes")


def fix(a, b):
    """ASN1_STRING_cmp over real ASN1_STRINGs: length, memcmp, type."""
    if len(a) != len(b):
        return "Different"
    return "Equal" if a == b else "Different"


def main():
    cases = json.loads((ROOT / "fixtures/cases.json").read_text())["cases"]
    exp = {}
    for c in cases:
        a, b = bytes.fromhex(c["a"]), bytes.fromhex(c["b"])
        exp[c["name"]] = {"Pre": {"Decoded": pre(a, b), "Declared": fix(a, b)},
                          "Fix": {"Decoded": fix(a, b), "Declared": "not-applicable"}}
    sweep = {}
    for n in range(2, 65):
        a = bytes([0xA3, n - 2]) + b"\x5a" * (n - 2)
        b2 = a[:-1] + b"\x31" if n > 2 else a
        sweep[str(n)] = {"identical": pre(a, a), "last_byte_differs": pre(a, b2)}
    json.dump({"cases": exp, "sweep_pre": sweep}, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
