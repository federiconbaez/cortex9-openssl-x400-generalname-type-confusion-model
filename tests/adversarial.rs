//! Adversarial inputs: hostile lengths and pointers inside model objects,
//! out-of-domain TLVs, address arithmetic at the edges. Each must end in a
//! labelled stop or a refusal, never a panic or an unlabelled read.
use cortex9_openssl_x400_generalname_type_confusion_model::*;

fn string_obj(heap: &mut Heap, len: i32, data: u64) -> u64 {
    let mut s = len.to_le_bytes().to_vec();
    s.extend(V_ASN1_SEQUENCE.to_le_bytes());
    s.extend(data.to_le_bytes());
    s.extend(0i64.to_le_bytes());
    heap.alloc("hostile ASN1_STRING", s)
}

#[test]
fn heap_read_edges_do_not_overflow() {
    let mut h = Heap::default();
    let a = h.alloc("x", vec![1, 2, 3, 4]);
    let mut t = vec![];
    assert!(
        matches!(h.read("t", a, u64::MAX, &mut t), Err(Stop::OutOfAllocation { bytes_past_end, .. }) if bytes_past_end == u64::MAX - 4)
    );
    assert!(matches!(
        h.read("t", u64::MAX, 1, &mut t),
        Err(Stop::WildPointer { .. })
    ));
    assert!(matches!(
        h.read("t", u64::MAX, u64::MAX, &mut t),
        Err(Stop::WildPointer { .. })
    ));
    assert!(matches!(
        h.read("t", a + 4, 1, &mut t),
        Err(Stop::OutOfAllocation {
            bytes_past_end: 1,
            ..
        })
    ));
    assert!(matches!(
        h.read("t", a + 100, 2, &mut t),
        Err(Stop::OutOfAllocation {
            bytes_past_end: 2,
            ..
        })
    ));
    assert_eq!(h.read("t", a + 4, 0, &mut t), Ok(vec![]));
    assert_eq!(h.read("t", 0, 0, &mut t), Ok(vec![]));
    assert!(matches!(
        h.read("t", 0, 1, &mut t),
        Err(Stop::WildPointer { .. })
    ));
    assert_eq!(t.len(), 8, "every attempted read is traced");
    // only the zero-length read inside an allocation is ok; the NULL one
    // returns no bytes but is not inside any allocation
    assert_eq!(t.iter().filter(|r| r.ok).count(), 1);
}

#[test]
fn negative_and_huge_string_lengths_stop_cleanly() {
    for len in [-1, i32::MIN, i32::MAX, 9, 1 << 20] {
        let mut h = Heap::default();
        let d1 = h.alloc("d1", vec![0x41; 8]);
        let d2 = h.alloc("d2", vec![0x41; 8]);
        let a = string_obj(&mut h, len, d1);
        let b = string_obj(&mut h, len, d2);
        let mut c = Ctx {
            heap: &h,
            trace: vec![],
        };
        let r = c.asn1_string_cmp(a, b);
        assert!(
            matches!(r, Err(Stop::OutOfAllocation { .. })),
            "{len}: {r:?}"
        );
    }
}

#[test]
fn hostile_data_pointers_are_wild_not_dereferenced() {
    for p in [
        0,
        1,
        u64::MAX,
        u64::MAX - 7,
        HEAP_BASE - 1,
        0x4141_4141_4141_4141,
    ] {
        let mut h = Heap::default();
        let a = string_obj(&mut h, 4, p);
        let b = string_obj(&mut h, 4, p);
        let mut c = Ctx {
            heap: &h,
            trace: vec![],
        };
        let r = c.asn1_string_cmp(a, b);
        assert!(matches!(r, Err(Stop::WildPointer { .. })), "{p:#x}: {r:?}");
        let mut c = Ctx {
            heap: &h,
            trace: vec![],
        };
        assert!(c.obj_cmp(a, b).is_err(), "{p:#x}");
    }
}

#[test]
fn run_refuses_out_of_domain_tlvs() {
    let ok = x400_tlv(10, 0x41, None);
    let big = vec![0xa3; MODEL_MAX_TLV + 1];
    for (a, b) in [
        (&[][..], &ok[..]),
        (&ok[..], &[][..]),
        (&big[..], &ok[..]),
        (&ok[..], &big[..]),
    ] {
        for v in [Version::Pre, Version::Fix] {
            for bd in [Build::Decoded, Build::Declared] {
                let o = run(v, bd, a, b);
                assert_eq!(o.label, Label::InvalidInput);
                assert!(o.reads.is_empty());
            }
        }
    }
    let edge = vec![0xa3; MODEL_MAX_TLV];
    assert_ne!(
        run(Version::Fix, Build::Decoded, &edge, &edge).label,
        Label::InvalidInput
    );
}

#[test]
fn malformed_tlvs_never_panic_and_fix_is_byte_exact() {
    // inconsistent length bytes, wrong tags, single bytes: the fix compares
    // the stored bytes, so it must agree with byte equality for any input
    let samples: Vec<Vec<u8>> = vec![
        vec![0xa3],
        vec![0xa3, 0x7f],
        vec![0xa3, 0xff, 0x00],
        vec![0x30, 0x00],
        vec![0x00; 5],
        vec![0xff; 6],
        vec![0xa3, 0x04, 1, 2, 3, 4],
        vec![0xa3, 0x04, 1, 2, 3, 5],
        (0..=255u8).collect(),
    ];
    for a in &samples {
        for b in &samples {
            let f = run(Version::Fix, Build::Decoded, a, b);
            let want = if a == b {
                Label::Equal
            } else {
                Label::Different
            };
            assert_eq!(f.label, want, "{a:?} {b:?}");
            for bd in [Build::Decoded, Build::Declared] {
                let p = run(Version::Pre, bd, a, b);
                assert!(p.stop.is_some() || p.result.is_some());
            }
            // control: with the declared object, the pre code is byte-exact too
            let c = run(Version::Pre, Build::Declared, a, b);
            assert_eq!(c.label, want, "control {a:?} {b:?}");
        }
    }
}
