//! A labelled abstract heap. Every object the comparators touch lives here
//! as bytes at a model address. A read is answered only if it lies entirely
//! inside one allocation; otherwise the model stops and records why. No
//! real memory is read, and nothing outside the model is ever dereferenced.
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct Alloc {
    pub base: u64,
    pub bytes: Vec<u8>,
    pub label: String,
}

#[derive(Debug, Clone, Default)]
pub struct Heap {
    pub allocs: Vec<Alloc>,
}

/// Why a comparison stopped before returning a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Stop {
    /// The read starts inside an allocation but runs past its end.
    OutOfAllocation {
        at: String,
        addr: u64,
        len: u64,
        alloc: String,
        alloc_size: u64,
        bytes_past_end: u64,
    },
    /// The address is not inside any allocation (NULL included).
    WildPointer { at: String, addr: u64, len: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Read {
    pub at: String,
    pub addr: u64,
    pub len: u64,
    pub alloc: Option<String>,
    pub ok: bool,
}

/// Allocations start here and are 64 KiB apart, so no content byte pattern
/// used in the fixtures (0x30..0x5a repeated) is ever a model address.
pub const HEAP_BASE: u64 = 0x0001_0000;
pub const HEAP_STRIDE: u64 = 0x0001_0000;

impl Heap {
    pub fn alloc(&mut self, label: &str, bytes: Vec<u8>) -> u64 {
        let base = HEAP_BASE + HEAP_STRIDE * self.allocs.len() as u64;
        self.allocs.push(Alloc {
            base,
            bytes,
            label: label.to_string(),
        });
        base
    }

    /// The allocation whose 64 KiB region holds `addr`. An address past the
    /// end of an allocation but inside its region is reported against that
    /// allocation (a read beyond it), not as a wild pointer.
    fn find(&self, addr: u64) -> Option<&Alloc> {
        self.allocs
            .iter()
            .find(|a| addr >= a.base && addr < a.base + HEAP_STRIDE)
    }

    pub fn read(
        &self,
        at: &str,
        addr: u64,
        len: u64,
        trace: &mut Vec<Read>,
    ) -> Result<Vec<u8>, Stop> {
        let a = self.find(addr);
        let ok = a.is_some_and(|a| addr + len <= a.base + a.bytes.len() as u64);
        trace.push(Read {
            at: at.to_string(),
            addr,
            len,
            alloc: a.map(|a| a.label.clone()),
            ok,
        });
        match a {
            None if len == 0 => Ok(vec![]),
            None => Err(Stop::WildPointer {
                at: at.to_string(),
                addr,
                len,
            }),
            Some(a) if !ok => Err(Stop::OutOfAllocation {
                at: at.to_string(),
                addr,
                len,
                alloc: a.label.clone(),
                alloc_size: a.bytes.len() as u64,
                bytes_past_end: (addr + len - (a.base + a.bytes.len() as u64)).min(len),
            }),
            Some(a) => {
                let o = (addr - a.base) as usize;
                Ok(a.bytes[o..o + len as usize].to_vec())
            }
        }
    }

    pub fn read_i32(&self, at: &str, addr: u64, t: &mut Vec<Read>) -> Result<i32, Stop> {
        let b = self.read(at, addr, 4, t)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_ptr(&self, at: &str, addr: u64, t: &mut Vec<Read>) -> Result<u64, Stop> {
        let b = self.read(at, addr, 8, t)?;
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    }
}
