//! Model vs expectations derived independently by scripts/derive_expected.py.
use cortex9_openssl_x400_generalname_type_confusion_model::*;
use serde_json::Value;
use std::fs;

fn read(p: &str) -> Value {
    serde_json::from_str(
        &fs::read_to_string(format!("{}/{p}", env!("CARGO_MANIFEST_DIR"))).unwrap(),
    )
    .unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn every_case_matches_independent_derivation() {
    let exp = read("fixtures/expected.json");
    let cases = read("fixtures/cases.json");
    let cases = cases["cases"].as_array().unwrap();
    assert_eq!(cases.len(), exp["cases"].as_object().unwrap().len());
    for c in cases {
        let n = c["name"].as_str().unwrap();
        let (a, b) = (
            unhex(c["a"].as_str().unwrap()),
            unhex(c["b"].as_str().unwrap()),
        );
        for (v, bl, key) in [
            (Version::Pre, Build::Decoded, ["Pre", "Decoded"]),
            (Version::Fix, Build::Decoded, ["Fix", "Decoded"]),
            (Version::Pre, Build::Declared, ["Pre", "Declared"]),
        ] {
            let o = run(v, bl, &a, &b);
            assert_eq!(
                format!("{:?}", o.label),
                exp["cases"][n][key[0]][key[1]].as_str().unwrap(),
                "{n} {key:?}"
            );
        }
    }
}

#[test]
fn length_sweep_matches_independent_derivation() {
    let exp = read("fixtures/expected.json");
    for len in 2..=64usize {
        let a = x400_tlv(len, 0x5a, None);
        let b = x400_tlv(len, 0x5a, Some(0x31));
        let e = &exp["sweep_pre"][len.to_string()];
        assert_eq!(
            format!("{:?}", run(Version::Pre, Build::Decoded, &a, &a).label),
            e["identical"].as_str().unwrap(),
            "len {len}"
        );
        assert_eq!(
            format!("{:?}", run(Version::Pre, Build::Decoded, &a, &b).label),
            e["last_byte_differs"].as_str().unwrap(),
            "len {len}"
        );
    }
}

#[test]
fn invariant_fix_is_correct_and_stays_inside_allocations() {
    for len in 2..=129usize {
        let a = x400_tlv(len, 0x5a, None);
        for b in [
            a.clone(),
            x400_tlv(len, 0x5a, Some(0x31)),
            x400_tlv(len.max(3) - 1, 0x5a, None),
        ] {
            let o = run(Version::Fix, Build::Decoded, &a, &b);
            assert!(o.stop.is_none(), "len {len}");
            assert!(o.reads.iter().all(|r| r.ok));
            assert_eq!(o.result == Some(0), a == b, "len {len}");
        }
    }
}

#[test]
fn counterfactual_declared_type_makes_pre_comparator_correct() {
    for len in 2..=129usize {
        let a = x400_tlv(len, 0x5a, None);
        let b = x400_tlv(len, 0x5a, Some(0x31));
        for (x, y) in [(&a, &a), (&a, &b)] {
            let o = run(Version::Pre, Build::Declared, x, y);
            assert!(
                o.stop.is_none() && o.reads.iter().all(|r| r.ok),
                "len {len}"
            );
            assert_eq!(o.result == Some(0), x == y);
        }
    }
}

#[test]
fn reinterpreted_type_is_the_string_length() {
    let o = run(Version::Pre, Build::Decoded, &[0xa3, 0x00], &[0xa3, 0x00]);
    assert_eq!(o.reinterpreted_type, 2);
    let r = &o.reads[4];
    assert_eq!(r.at, "a_type.c:67 a->type");
    assert!(r.alloc.as_deref().unwrap().contains("ASN1_STRING"));
}

#[test]
fn every_stop_names_a_source_line() {
    for len in 2..=64usize {
        let a = x400_tlv(len, 0x5a, None);
        if let Some(s) = run(Version::Pre, Build::Decoded, &a, &a).stop {
            let at = match s {
                Stop::OutOfAllocation { at, .. } | Stop::WildPointer { at, .. } => at,
            };
            assert!(at.contains(".c:"), "{at}");
        }
    }
}
