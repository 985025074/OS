extern crate alloc;

use alloc::vec::Vec;
use core::any::Any;
use spin::Mutex;

use crate::mm::UserBuffer;

use super::File;

pub enum PseudoKind {
    Static(Vec<u8>),
    Urandom(u64),
    Null,
    Zero,
}

pub struct PseudoFile {
    readable: bool,
    writable: bool,
    inner: Mutex<PseudoInner>,
}

struct PseudoInner {
    offset: usize,
    kind: PseudoKind,
}

impl PseudoFile {
    pub fn new_static(content: &str) -> Self {
        Self {
            readable: true,
            writable: false,
            inner: Mutex::new(PseudoInner {
                offset: 0,
                kind: PseudoKind::Static(content.as_bytes().to_vec()),
            }),
        }
    }

    pub fn new_urandom(seed: u64) -> Self {
        Self {
            readable: true,
            writable: false,
            inner: Mutex::new(PseudoInner {
                offset: 0,
                kind: PseudoKind::Urandom(seed),
            }),
        }
    }

    pub fn new_null() -> Self {
        Self {
            readable: true,
            writable: true,
            inner: Mutex::new(PseudoInner {
                offset: 0,
                kind: PseudoKind::Null,
            }),
        }
    }

    pub fn new_zero() -> Self {
        Self {
            readable: true,
            writable: false,
            inner: Mutex::new(PseudoInner {
                offset: 0,
                kind: PseudoKind::Zero,
            }),
        }
    }
}

impl File for PseudoFile {
    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        self.writable
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        let mut inner = self.inner.lock();
        let PseudoInner { offset, kind } = &mut *inner;
        match kind {
            PseudoKind::Static(data) => {
                if *offset >= data.len() {
                    return 0;
                }
                let mut total = 0usize;
                for slice in buf.buffers.iter_mut() {
                    if *offset >= data.len() {
                        break;
                    }
                    let n = core::cmp::min(slice.len(), data.len() - *offset);
                    slice[..n].copy_from_slice(&data[*offset..*offset + n]);
                    *offset += n;
                    total += n;
                    if n < slice.len() {
                        break;
                    }
                }
                total
            }
            PseudoKind::Urandom(seed) => {
                // xorshift64*
                let mut total = 0usize;
                for slice in buf.buffers.iter_mut() {
                    for b in slice.iter_mut() {
                        let mut x = *seed;
                        x ^= x >> 12;
                        x ^= x << 25;
                        x ^= x >> 27;
                        x = x.wrapping_mul(0x2545F4914F6CDD1D);
                        *seed = x;
                        *b = (x & 0xff) as u8;
                        total += 1;
                    }
                }
                total
            }
            PseudoKind::Null => 0,
            PseudoKind::Zero => {
                let mut total = 0usize;
                for slice in buf.buffers.iter_mut() {
                    slice.fill(0);
                    total += slice.len();
                }
                total
            }
        }
    }

    fn write(&self, buf: UserBuffer) -> usize {
        match self.inner.lock().kind {
            PseudoKind::Null => buf.len(),
            _ => 0,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
