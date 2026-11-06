# Sources

Local copies under `security-research-45/sources/next3/` (not in this repo),
fetched read-only on 2026-11-06. "Parent" is
`adf77d6657e836fc87391fad53d857927a764297`, the parent of 7880536.

| Source | Used for | SHA-256 of copy |
|---|---|---|
| OpenSSL Security Advisory 2023-02-07 (`secadv/20230207.txt`) | description, affected/fixed versions, CRL-check precondition | 22c21bb4f051ceea234372770930996bfaaf7ccbc93187ff603098e50d99d243 |
| openssl commit 7880536fe17c2b5450e279155bedd51771d28c9f patch ("Fix GENERAL_NAME_cmp for x400Address (master)") | the causal diff, regression vector `a3 00` | 388e5f93f388d738fd45cef78b71b8cc82b0d2776690f2c9751f6a8a19ea0c1f |
| `crypto/x509/v3_genn.c` parent / 7880536 | template line 37; `GENERAL_NAME_cmp` 93-131 | c7e7a63136f274fbe208ca8a6054baeef4ed46bab0bd58f3398150030af2f686 / ac465b11789ba482bfae6620e966e49da1ce87c804c28d423126562d34fee373 |
| `include/openssl/x509v3.h.in` parent / 7880536 | `GENERAL_NAME` layout, line 160 | b36ff16ea7729af23241a8793e180b7d0185f51b85d130d7d208261e2628a8fc / c586a5b70ba8b498898cc93aaf02f64b2e8eabb61688a4a536907aecc79b97e9 |
| `crypto/asn1/a_type.c` parent | `ASN1_TYPE_cmp` 63-107 | a9031ef25facd580c71a2949bb954e67ff825876c72543ef4b2b719cb1921b48 |
| `crypto/asn1/asn1_lib.c` parent | `ASN1_STRING_cmp` 388-403 | d64f32af2cf64173be68012256252d3bd8acdb1b7513cab9881bb96b84083443 |
| `crypto/objects/obj_lib.c` parent | `OBJ_cmp` 56-64 | bd48f1269e9211ae4942bd7f77e8c57f536c85262b6ecc166487089e70e44b80 |
| `include/openssl/asn1.h.in` parent | `asn1_string_st` 163-173, `asn1_type_st` 476-, `V_ASN1_*` | 7836479e3223955cb81f61bc765a0d70868b149478195b70df316120d72d2e8e |
| `include/crypto/asn1.h` parent | `asn1_object_st` 114-120 | f76c1bf6e5b7e59fcf3c57cfb8ade934aab1dd0f5968c537bbc1cfc1cf09b099 |
| `crypto/asn1/tasn_dec.c` parent | SEQUENCE kept encoded with header, 757-782 | ec4b22e403c3aa4e707be08ef3d39aeaa941991639cfb8acb7e80b1f299c8a18 |
