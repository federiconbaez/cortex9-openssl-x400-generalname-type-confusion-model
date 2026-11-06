//! Checks every answer in PRACTICE.md so the guide cannot drift from the code.
use cortex9_openssl_x400_generalname_type_confusion_model::*;

fn pre(a: &[u8], b: &[u8]) -> Outcome {
    run(Version::Pre, Build::Decoded, a, b)
}

#[test]
fn practice_level_1_decoder_keeps_the_whole_tlv() {
    let mut h = Heap::default();
    let g = decoded_x400(&mut h, "a", &[0xa3, 0x00]);
    let mut t = vec![];
    let s = h.read_ptr("test", g + 8, &mut t).unwrap();
    assert_eq!(h.read_i32("test", s, &mut t).unwrap(), 2); // length = whole TLV
    assert_eq!(h.read_i32("test", s + 4, &mut t).unwrap(), V_ASN1_SEQUENCE);
}

#[test]
fn practice_level_2_type_comes_from_length() {
    assert_eq!(pre(&[0xa3, 0x00], &[0xa3, 0x00]).reinterpreted_type, 2);
}

#[test]
fn practice_level_3_upstream_regression_reads_past_two_bytes() {
    match pre(&[0xa3, 0x00], &[0xa3, 0x00]).stop {
        Some(Stop::OutOfAllocation {
            at,
            alloc_size,
            bytes_past_end,
            ..
        }) => {
            assert_eq!(at, "asn1_lib.c:392 a->length");
            assert_eq!((alloc_size, bytes_past_end), (2, 2));
        }
        s => panic!("{s:?}"),
    }
}

#[test]
fn practice_level_4_length_five_compares_equal_without_reading() {
    let o = pre(&[0xa3, 3, 2, 1, 1], &[0xa3, 3, 2, 1, 2]);
    assert_eq!((o.label, o.result), (Label::WrongResult, Some(0)));
}

#[test]
fn practice_level_5_length_six_takes_the_object_branch() {
    let a = [0xa3, 4, 2, 2, 1, 0];
    match pre(&a, &a).stop {
        Some(Stop::OutOfAllocation { at, .. }) => assert_eq!(at, "obj_lib.c:60 a->length"),
        s => panic!("{s:?}"),
    }
}

#[test]
fn practice_level_6_content_bytes_become_the_memcmp_pointer() {
    let mut a = x400_tlv(24, 0x5a, None);
    a[8..16].copy_from_slice(&[0x41; 8]);
    match pre(&a, &a).stop {
        Some(Stop::WildPointer { at, addr, .. }) => {
            assert_eq!(at, "asn1_lib.c:395 memcmp");
            assert_eq!(addr, 0x4141_4141_4141_4141);
        }
        s => panic!("{s:?}"),
    }
}

#[test]
fn practice_level_7_fix_compares_bytes() {
    let a = x400_tlv(24, 0x5a, None);
    let b = x400_tlv(24, 0x5a, Some(0x31));
    assert_eq!(
        run(Version::Fix, Build::Decoded, &a, &b).label,
        Label::Different
    );
    assert_eq!(
        run(Version::Fix, Build::Decoded, &a, &a).label,
        Label::Equal
    );
}

#[test]
fn practice_level_8_declared_type_control() {
    let a = x400_tlv(24, 0x5a, None);
    assert_eq!(
        run(Version::Pre, Build::Declared, &a, &a).label,
        Label::Equal
    );
}
