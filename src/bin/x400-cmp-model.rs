//! CLI. Subcommands:
//!   cmp <pre|fix> <decoded|declared> <hex a> <hex b>
//!   cases <fixtures/cases.json>
//!   results <fixtures/cases.json> <out_dir>
use cortex9_openssl_x400_generalname_type_confusion_model::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path, process::exit};

fn hex(s: &str) -> Vec<u8> {
    if !s.is_ascii() || !s.len().is_multiple_of(2) || s.len() < 4 || s.len() > 258 {
        usage()
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|_| usage()))
        .collect()
}

fn usage() -> ! {
    eprintln!(
        "usage: x400-cmp-model cmp <pre|fix> <decoded|declared> <hex a> <hex b>\n       x400-cmp-model cases <cases.json> | results <cases.json> <out_dir>"
    );
    exit(2)
}

fn version(s: &str) -> Version {
    match s {
        "pre" => Version::Pre,
        "fix" => Version::Fix,
        _ => usage(),
    }
}

fn build(s: &str) -> Build {
    match s {
        "decoded" => Build::Decoded,
        "declared" => Build::Declared,
        _ => usage(),
    }
}

fn fail(msg: String) -> ! {
    eprintln!("error: {msg}");
    exit(2)
}

/// Loads fixtures; malformed files exit with status 2 and a message.
fn load(p: &Path) -> Vec<Value> {
    let text = fs::read_to_string(p).unwrap_or_else(|e| fail(format!("{}: {e}", p.display())));
    let v: Value = serde_json::from_str(&text).unwrap_or_else(|e| fail(format!("json: {e}")));
    let Some(cases) = v["cases"].as_array() else {
        fail("missing \"cases\" array".into())
    };
    for c in cases {
        for k in ["name", "a", "b"] {
            if !c[k].is_string() {
                fail(format!("case without string field \"{k}\": {c}"))
            }
        }
    }
    cases.clone()
}

fn summary(o: &Outcome) -> String {
    let stop = match &o.stop {
        Some(Stop::OutOfAllocation {
            at,
            len,
            alloc,
            bytes_past_end,
            ..
        }) => {
            format!("{at}: {len} B from '{alloc}', {bytes_past_end} B past end")
        }
        Some(Stop::WildPointer { at, addr, len }) => format!("{at}: {len} B at {addr:#x}"),
        None => String::new(),
    };
    format!(
        "{:?},{},{},{},\"{}\"",
        o.label,
        o.result.map(|r| r.to_string()).unwrap_or_default(),
        o.reinterpreted_type,
        o.reads.len(),
        stop
    )
}

fn sweep_rows() -> String {
    let mut s = String::from("len,pair,version,label,result,reinterpreted_type,reads,stop\n");
    for len in 2..=64 {
        for (pair, last) in [("identical", None), ("last_byte_differs", Some(0x31))] {
            let a = x400_tlv(len, 0x5a, None);
            let b = x400_tlv(len, 0x5a, last.filter(|_| len > 2));
            for v in [Version::Pre, Version::Fix] {
                let o = run(v, Build::Decoded, &a, &b);
                s += &format!("{len},{pair},{v:?},{}\n", summary(&o));
            }
        }
    }
    s
}

fn results(cases: &Path, out: &Path) {
    fs::create_dir_all(out).unwrap();
    let mut s = String::from("case,version,build,label,result,reinterpreted_type,reads,stop\n");
    for c in load(cases) {
        let (a, b) = (hex(c["a"].as_str().unwrap()), hex(c["b"].as_str().unwrap()));
        // Fix + Declared is not a real combination: after the fix the field
        // is declared as the ASN1_STRING the decoder builds.
        for (v, bl) in [
            (Version::Pre, Build::Decoded),
            (Version::Fix, Build::Decoded),
            (Version::Pre, Build::Declared),
        ] {
            let o = run(v, bl, &a, &b);
            s += &format!(
                "{},{v:?},{bl:?},{}\n",
                c["name"].as_str().unwrap(),
                summary(&o)
            );
        }
    }
    fs::write(out.join("cases.csv"), s).unwrap();
    fs::write(out.join("sweep_len.csv"), sweep_rows()).unwrap();
    let mut sums = String::new();
    for f in ["cases.csv", "sweep_len.csv"] {
        let d = Sha256::digest(fs::read(out.join(f)).unwrap());
        let h: String = d.iter().map(|x| format!("{x:02x}")).collect();
        sums += &format!("{h}  {f}\n");
    }
    fs::write(out.join("SHA256SUMS"), sums).unwrap();
}

fn main() {
    let a: Vec<String> = env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("cmp") if a.len() == 6 => {
            let o = run(version(&a[2]), build(&a[3]), &hex(&a[4]), &hex(&a[5]));
            println!("{}", serde_json::to_string_pretty(&o).unwrap());
        }
        Some("cases") if a.len() == 3 => {
            for c in load(Path::new(&a[2])) {
                let (x, y) = (hex(c["a"].as_str().unwrap()), hex(c["b"].as_str().unwrap()));
                let pre = run(Version::Pre, Build::Decoded, &x, &y);
                let fix = run(Version::Fix, Build::Decoded, &x, &y);
                println!(
                    "{}: {}",
                    c["name"].as_str().unwrap(),
                    json!({"pre": summary(&pre), "fix": summary(&fix)})
                );
            }
        }
        Some("results") if a.len() == 4 => results(Path::new(&a[2]), Path::new(&a[3])),
        _ => usage(),
    }
}
