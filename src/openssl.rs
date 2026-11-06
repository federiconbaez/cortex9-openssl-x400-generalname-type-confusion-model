//! LP64 layouts and the comparators, line by line.
//!
//! Layouts (x86-64 / aarch64 LP64, little-endian):
//! - `struct asn1_string_st` (include/openssl/asn1.h.in:163-173):
//!   length i32 @0, type i32 @4, data ptr @8, flags i64 @16; size 24.
//! - `struct asn1_type_st` (asn1.h.in:476-): type i32 @0, value union @8; size 16.
//! - `struct asn1_object_st` (include/crypto/asn1.h:114-120): sn @0, ln @8,
//!   nid i32 @16, length i32 @20, data ptr @24, flags i32 @32; size 40.
//! - `GENERAL_NAME` (include/openssl/x509v3.h.in:144-): type i32 @0, d @8.
use crate::heap::{Heap, Read, Stop};

pub const V_ASN1_BOOLEAN: i32 = 1;
pub const V_ASN1_NULL: i32 = 5;
pub const V_ASN1_OBJECT: i32 = 6;
pub const V_ASN1_SEQUENCE: i32 = 16;
pub const GEN_X400: i32 = 3;

pub struct Ctx<'a> {
    pub heap: &'a Heap,
    pub trace: Vec<Read>,
}

fn sign(x: i64) -> i32 {
    x.signum() as i32
}

impl Ctx<'_> {
    fn i32_at(&mut self, at: &str, addr: u64) -> Result<i32, Stop> {
        self.heap.read_i32(at, addr, &mut self.trace)
    }
    fn ptr_at(&mut self, at: &str, addr: u64) -> Result<u64, Stop> {
        self.heap.read_ptr(at, addr, &mut self.trace)
    }

    /// `memcmp` reads both ranges; the sign is what matters.
    fn memcmp(&mut self, at: &str, a: u64, b: u64, n: u64) -> Result<i32, Stop> {
        let x = self.heap.read(at, a, n, &mut self.trace)?;
        let y = self.heap.read(at, b, n, &mut self.trace)?;
        Ok(match x.cmp(&y) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        })
    }

    /// `ASN1_STRING_cmp` (crypto/asn1/asn1_lib.c:388-403).
    pub fn asn1_string_cmp(&mut self, a: u64, b: u64) -> Result<i32, Stop> {
        let al = self.i32_at("asn1_lib.c:392 a->length", a)?;
        let bl = self.i32_at("asn1_lib.c:392 b->length", b)?;
        let i = sign(al as i64 - bl as i64);
        if i != 0 {
            return Ok(i);
        }
        let mut i = 0;
        if al != 0 {
            let ad = self.ptr_at("asn1_lib.c:395 a->data", a + 8)?;
            let bd = self.ptr_at("asn1_lib.c:395 b->data", b + 8)?;
            // memcmp's size_t argument: a negative int converts to a huge size
            i = self.memcmp("asn1_lib.c:395 memcmp", ad, bd, al as i64 as u64)?;
        }
        if i != 0 {
            return Ok(i);
        }
        let at = self.i32_at("asn1_lib.c:397 a->type", a + 4)?;
        let bt = self.i32_at("asn1_lib.c:397 b->type", b + 4)?;
        Ok(sign(at as i64 - bt as i64))
    }

    /// `OBJ_cmp` (crypto/objects/obj_lib.c:56-64).
    pub fn obj_cmp(&mut self, a: u64, b: u64) -> Result<i32, Stop> {
        let al = self.i32_at("obj_lib.c:60 a->length", a + 20)?;
        let bl = self.i32_at("obj_lib.c:60 b->length", b + 20)?;
        if al != bl {
            return Ok(sign(al as i64 - bl as i64));
        }
        let ad = self.ptr_at("obj_lib.c:63 a->data", a + 24)?;
        let bd = self.ptr_at("obj_lib.c:63 b->data", b + 24)?;
        self.memcmp("obj_lib.c:63 memcmp", ad, bd, al as i64 as u64)
    }

    /// `ASN1_TYPE_cmp` (crypto/asn1/a_type.c:63-107).
    pub fn asn1_type_cmp(&mut self, a: u64, b: u64) -> Result<i32, Stop> {
        let at = self.i32_at("a_type.c:67 a->type", a)?;
        let bt = self.i32_at("a_type.c:67 b->type", b)?;
        if at != bt {
            return Ok(-1);
        }
        match at {
            V_ASN1_OBJECT => {
                let ao = self.ptr_at("a_type.c:72 a->value.object", a + 8)?;
                let bo = self.ptr_at("a_type.c:72 b->value.object", b + 8)?;
                self.obj_cmp(ao, bo)
            }
            V_ASN1_BOOLEAN => {
                let x = self.i32_at("a_type.c:75 a->value.boolean", a + 8)?;
                let y = self.i32_at("a_type.c:75 b->value.boolean", b + 8)?;
                Ok(sign(x as i64 - y as i64))
            }
            V_ASN1_NULL => Ok(0), // a_type.c:78
            _ => {
                let ap = self.ptr_at("a_type.c:101 a->value.ptr", a + 8)?;
                let bp = self.ptr_at("a_type.c:101 b->value.ptr", b + 8)?;
                self.asn1_string_cmp(ap, bp)
            }
        }
    }

    /// `GENERAL_NAME_cmp`, x400Address branch: pre (v3_genn.c:100-101 at
    /// parent of 7880536) calls ASN1_TYPE_cmp, fix calls ASN1_STRING_cmp.
    pub fn general_name_cmp(&mut self, v: Version, a: u64, b: u64) -> Result<i32, Stop> {
        let at = self.i32_at("v3_genn.c:97 a->type", a)?;
        let bt = self.i32_at("v3_genn.c:97 b->type", b)?;
        if at != bt {
            return Ok(-1);
        }
        if at != GEN_X400 {
            unimplemented!("only the x400Address branch is modelled")
        }
        let ad = self.ptr_at("v3_genn.c:101 a->d.x400Address", a + 8)?;
        let bd = self.ptr_at("v3_genn.c:101 b->d.x400Address", b + 8)?;
        match v {
            Version::Pre => self.asn1_type_cmp(ad, bd),
            Version::Fix => self.asn1_string_cmp(ad, bd),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Version {
    Pre,
    Fix,
}

fn le32(x: i32) -> Vec<u8> {
    x.to_le_bytes().to_vec()
}

/// What `d2i_GENERAL_NAME` builds for `[3] x400Address`: the template is
/// `ASN1_IMP(GENERAL_NAME, d.x400Address, ASN1_SEQUENCE, GEN_X400)`
/// (v3_genn.c:37). A SEQUENCE is kept in encoded form with its header
/// (tasn_dec.c:757-782), so the ASN1_STRING holds the whole TLV, type 16.
pub fn decoded_x400(heap: &mut Heap, name: &str, tlv: &[u8]) -> u64 {
    let data = heap.alloc(
        &format!("{name}: x400 TLV bytes ({} B)", tlv.len()),
        tlv.to_vec(),
    );
    let mut s = le32(tlv.len() as i32);
    s.extend(le32(V_ASN1_SEQUENCE));
    s.extend(data.to_le_bytes());
    s.extend(0i64.to_le_bytes());
    let st = heap.alloc(&format!("{name}: ASN1_STRING (24 B)"), s);
    let mut g = le32(GEN_X400);
    g.extend([0u8; 4]);
    g.extend(st.to_le_bytes());
    heap.alloc(&format!("{name}: GENERAL_NAME (16 B)"), g)
}

/// Counterfactual control: the object the *declared* type describes, an
/// ASN1_TYPE (type SEQUENCE) pointing at the ASN1_STRING.
pub fn declared_x400(heap: &mut Heap, name: &str, tlv: &[u8]) -> u64 {
    let g = decoded_x400(heap, name, tlv);
    let st = heap.allocs[heap.allocs.len() - 2].base; // the ASN1_STRING
    let mut t = le32(V_ASN1_SEQUENCE);
    t.extend([0u8; 4]);
    t.extend(st.to_le_bytes());
    let ty = heap.alloc(&format!("{name}: ASN1_TYPE (16 B)"), t);
    let gn = heap.allocs.len() - 2; // the GENERAL_NAME
    heap.allocs[gn].bytes[8..16].copy_from_slice(&ty.to_le_bytes());
    g
}
