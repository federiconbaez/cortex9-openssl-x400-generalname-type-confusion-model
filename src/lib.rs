//! Labelled-heap model of CVE-2023-0286: the x400Address of a GENERAL_NAME
//! is decoded as an ASN1_STRING but was declared, and compared, as an
//! ASN1_TYPE. Comparators run over model bytes only.
pub mod heap;
pub mod openssl;

pub use heap::*;
pub use openssl::*;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Build {
    /// What the decoder really builds (ASN1_STRING behind d.x400Address).
    Decoded,
    /// Control: what the declared type describes (ASN1_TYPE -> ASN1_STRING).
    Declared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Label {
    Equal,
    Different,
    /// Returned a value, but it disagrees with byte equality of the two TLVs.
    WrongResult,
    /// Stopped: a read would run past an allocation (abstract, not performed).
    OutOfAllocationRead,
    /// Stopped: a read through a pointer that is not in any allocation.
    WildPointerRead,
    /// Refused before building the heap: an input is outside the model
    /// domain (empty or longer than `MODEL_MAX_TLV`).
    InvalidInput,
}

/// Largest TLV the model accepts: well inside one 64 KiB heap region and
/// in `i32` range for `ASN1_STRING.length`.
pub const MODEL_MAX_TLV: usize = 4096;

#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub result: Option<i32>,
    pub stop: Option<Stop>,
    pub label: Label,
    pub reads: Vec<Read>,
    /// The reading `ASN1_TYPE.type` takes from `ASN1_STRING.length`.
    pub reinterpreted_type: i32,
}

pub fn run(v: Version, build: Build, a: &[u8], b: &[u8]) -> Outcome {
    if a.is_empty() || b.is_empty() || a.len() > MODEL_MAX_TLV || b.len() > MODEL_MAX_TLV {
        return Outcome {
            result: None,
            stop: None,
            label: Label::InvalidInput,
            reads: vec![],
            reinterpreted_type: 0,
        };
    }
    let mut heap = Heap::default();
    let mk = match build {
        Build::Decoded => decoded_x400,
        Build::Declared => declared_x400,
    };
    let ga = mk(&mut heap, "a", a);
    let gb = mk(&mut heap, "b", b);
    let mut ctx = Ctx {
        heap: &heap,
        trace: vec![],
    };
    let r = ctx.general_name_cmp(v, ga, gb);
    let same = a == b;
    let (result, stop, label) = match r {
        Ok(x) => {
            let l = if (x == 0) != same {
                Label::WrongResult
            } else if x == 0 {
                Label::Equal
            } else {
                Label::Different
            };
            (Some(x), None, l)
        }
        Err(s) => {
            let l = match s {
                Stop::OutOfAllocation { .. } => Label::OutOfAllocationRead,
                Stop::WildPointer { .. } => Label::WildPointerRead,
            };
            (None, Some(s), l)
        }
    };
    Outcome {
        result,
        stop,
        label,
        reads: ctx.trace,
        reinterpreted_type: i32::try_from(a.len()).expect("bounded by MODEL_MAX_TLV"),
    }
}

/// A TLV `[3] { ... }` of total length `len` (2..=129), content filled with
/// `fill`, last content byte replaced by `last` when given.
pub fn x400_tlv(len: usize, fill: u8, last: Option<u8>) -> Vec<u8> {
    assert!((2..=129).contains(&len));
    let mut v = vec![0xa3, (len - 2) as u8];
    v.extend(std::iter::repeat_n(fill, len - 2));
    if let (Some(l), true) = (last, len > 2) {
        *v.last_mut().unwrap() = l;
    }
    v
}
