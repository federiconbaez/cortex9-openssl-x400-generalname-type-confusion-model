# cortex9-openssl-x400-generalname-type-confusion-model

Labelled-heap model of **CVE-2023-0286**, the X.400 address type confusion
in OpenSSL's `GENERAL_NAME_cmp` (fixed in 3.0.8, 1.1.1t, 1.0.2zg).
Educational, offline, deterministic. The comparators run over **model
bytes** at model addresses. A read outside an allocation is reported, not
performed. No certificate or CRL is built; fixtures are inert byte patterns.

*Versión en español: [README.es.md](README.es.md).*

## The bug, from the source

- **Declaration.** The public `GENERAL_NAME` declared `d.x400Address` as
  `ASN1_TYPE *` (`include/openssl/x509v3.h.in`, parent of 7880536, line 160).
- **Decoding.** The template decodes it as an `ASN1_STRING`:
  - `ASN1_IMP(GENERAL_NAME, d.x400Address, ASN1_SEQUENCE, GEN_X400)`
    (`v3_genn.c:37`);
  - a SEQUENCE is kept in encoded form, header included
    (`tasn_dec.c:757-782`);
  - so the string holds the whole TLV, with `type = 16`.
- **Comparison.** `GENERAL_NAME_cmp` called `ASN1_TYPE_cmp` on it
  (`v3_genn.c:100-101`).
- **Fix** 7880536 ("Fix GENERAL_NAME_cmp for x400Address"): declares the
  field `ASN1_STRING *` and calls `ASN1_STRING_cmp`.

With LP64 layouts:

| `ASN1_TYPE` field read | is really | consequence |
|---|---|---|
| `type` @0 | `ASN1_STRING.length` | the TLV length picks the `switch` branch in `a_type.c:70` |
| `value.ptr` @8 | `ASN1_STRING.data` | the TLV bytes are then read as a struct |

The `switch` branches (`a_type.c`, lines 67-101):

- **Length 5** (`V_ASN1_NULL`): the result is 0. Two different addresses
  compare equal without reading anything (line 78).
- **Length 6** (`V_ASN1_OBJECT`): `OBJ_cmp` reads a 40-byte
  `ASN1_OBJECT` from the TLV bytes.
- **Anything else**: `ASN1_STRING_cmp` reads a 24-byte `ASN1_STRING` from
  the TLV bytes:
  - fewer than 16 bytes: the read runs past the allocation;
  - 16 bytes or more: content bytes 8..16 become the `memcmp` pointer
    (line 395). This is the advisory's "arbitrary pointers to a memcmp
    call".

## Results (`results/`, regenerated in CI)

Fixture cases (`results/cases.csv`). Each row lists the source line where
the comparison stops.

| case | pre-fix | fix | control (declared `ASN1_TYPE`, pre comparator) |
|---|---|---|---|
| upstream regression `a3 00` | read past a 2-byte allocation at `asn1_lib.c:392` | Equal | Equal |
| length 5, different bytes | **WrongResult** (0) | Different | Different |
| length 6 | read past the allocation at `obj_lib.c:60` | Equal | Equal |
| length 16/24 | `memcmp` through pointer `0x5a5a…`/`0x4141…`/`0x0` | Equal / Different | Equal / Different |

Length sweep (`results/sweep_len.csv`, TLV lengths 2..64, identical pair
and pair differing in the last byte), pre-fix:

- 98 wild-pointer reads, 25 reads past an allocation, 1 wrong result,
  1 correct `Different` and 1 correct `Equal`;
- the fix gives the correct answer in all 126 comparisons, with every read
  inside an allocation.

`scripts/derive_expected.py` derives every expected label independently,
using Python `struct` layouts.

## Usage

```sh
cargo test
cargo run --release --bin x400-cmp-model -- cmp pre decoded a300 a300
cargo run --release --bin x400-cmp-model -- results fixtures/cases.json /tmp/r
```

See [LIMITATIONS.md](LIMITATIONS.md), [SOURCES.md](SOURCES.md) and
[PRACTICE.md](PRACTICE.md) (Spanish). License: Apache-2.0.
