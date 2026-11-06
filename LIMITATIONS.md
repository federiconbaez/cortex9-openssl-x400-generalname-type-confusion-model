# Limitations

- **LP64, little-endian layouts only.** On 32-bit targets the offsets
  differ: `value.ptr` would overlap `ASN1_STRING.type`, not `.data`. That is
  not modelled.
- **The model stops at the first read it cannot answer.** Real code would
  read whatever lies there and continue. The model never invents those
  bytes, so later steps are not reported.
- **Addresses are model addresses** (64 KiB regions from 0x10000). A read
  past an allocation but within its region is "out of allocation";
  anything else, NULL included, is a "wild pointer". Real heap adjacency
  is not modelled.
- **Only the x400Address branch** of `GENERAL_NAME_cmp` is modelled. The
  CRL path that reaches it (`X509_V_FLAG_CRL_CHECK`, distribution-point
  matching) is described by the advisory but not modelled.
- **The `memcmp` result is the byte-order sign**, not the C return value.
- **Fix + declared `ASN1_TYPE`** is not a real combination and is not
  reported.
- **Sources** are the master commit 7880536 and its parent. The 3.0 and
  1.1.1 branch commits were not read.
- This is not a finding and nothing is attributed beyond the advisory and
  the commit.
